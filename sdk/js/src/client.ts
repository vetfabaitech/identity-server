import { type IdentityClaims, IdentityError, readClaims, type ErrorCode } from "./claims.js";
import { type IdentityClientOptions, type ResolvedConfig, resolveConfig } from "./config.js";
import { newState, sameState, savePending, takePending } from "./pending.js";
import { safeReturnPath } from "./redirects.js";

export type AuthStatus = "loading" | "authenticated" | "unauthenticated" | "error";

export interface AuthSnapshot {
  status: AuthStatus;
  /** Claims of the current access token (UI use only: see `readClaims`). Null unless authenticated. */
  claims: IdentityClaims | null;
  /** Why `status` is `error`, or why the last sign-in attempt failed. */
  error: IdentityError | null;
  /**
   * How this page is authenticated: `token` (an access token in memory, sent as a bearer) or `session` (this app's own
   * HttpOnly cookie, started by an SSO hand-off, sent by the browser). Null unless authenticated.
   */
  mode: "token" | "session" | null;
}

export interface LoginOptions {
  /** Same-origin path to return to after sign-in. Default: the current page. */
  returnTo?: string;
}

const LOOP_KEY = "vetfab.identity.attempts";
const LOOP_WINDOW_MS = 30_000;
const LOOP_LIMIT = 3;
const MAX_BUSY_RETRIES = 2;
const MAX_RETRY_WAIT_MS = 5_000;
const MIN_RENEW_DELAY_MS = 5_000;

type Listener = () => void;

/**
 * The browser side of the Vetfab sign-in contract (CONTRACT.md, "Browser flows"):
 *
 * 1. `login()` sends the browser to the identity service with a random one-time `state`.
 * 2. The service returns to `<app>/handoff#token=…&state=…`; `handleCallback()` checks `state`, checks the token is
 *    meant for this app, and removes the fragment from the address bar.
 * 3. The access token lives in memory only (never storage, URLs or logs) and is renewed in the background from the
 *    identity service's refresh cookie. Authenticated requests go through `fetch()`.
 * 4. `logout()` posts to the service, which ends the session for every Vetfab product.
 *
 * Whether the person may do anything is decided by the backend, which verifies every token itself.
 */
export class IdentityClient {
  readonly config: ResolvedConfig;
  private snapshot: AuthSnapshot = { status: "loading", claims: null, error: null, mode: null };
  private mode: "token" | "session" | null = null;
  private sessionTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<Listener>();
  private token: string | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private renewing: Promise<boolean> | null = null;
  private initialising: Promise<void> | null = null;
  private callback: { hash: string; promise: Promise<{ returnTo: string }> } | null = null;

  constructor(options: IdentityClientOptions) {
    this.config = resolveConfig(options);
  }

  // ----------------------------------------------------------------- state

  getSnapshot = (): AuthSnapshot => this.snapshot;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private set(status: AuthStatus, claims: IdentityClaims | null, error: IdentityError | null): void {
    this.snapshot = { status, claims, error, mode: status === "authenticated" ? this.mode : null };
    for (const listener of [...this.listeners]) listener();
  }

  private fail(code: ErrorCode, message: string): IdentityError {
    const error = new IdentityError(code, message);
    this.set("error", null, error);
    return error;
  }

  private clear(): void {
    this.token = null;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.sessionTimer) clearTimeout(this.sessionTimer);
    this.sessionTimer = null;
  }

  /** Whether this page is the hand-off landing page carrying a token, which `handleCallback()` must process. */
  isCallback(): boolean {
    const { platform, callbackPath } = this.config;
    const path = platform.currentPath().split("?")[0];
    return path === callbackPath && platform.hash().includes("token=");
  }

  // ----------------------------------------------------------------- start up

  /**
   * Resolves the initial state: on the hand-off page nothing happens (the callback component handles it); anywhere else
   * the refresh cookie is tried silently, which is what makes a second Vetfab product open already signed in.
   * Safe to call more than once.
   */
  init(): Promise<void> {
    this.initialising ??= (async () => {
      // Child effects run before the provider's, so the callback component may already have taken the fragment.
      if (this.callback || this.isCallback()) return;
      if (await this.probeSession()) return;
      await this.renew();
    })();
    return this.initialising;
  }

  // ----------------------------------------------------------------- this app's own session (SSO hand-off)

  /**
   * Asks this app's backend whether the browser holds its cookie session (started by an SSO hand-off). The answer comes
   * from the backend; nothing here decides it. Resolves true when there is one.
   */
  private async probeSession(): Promise<boolean> {
    const { platform, appUrl, sessionUrl } = this.config;
    if (!sessionUrl) return false;
    try {
      const response = await platform.fetch(`${appUrl}${sessionUrl}`, { credentials: "same-origin" });
      if (!response.ok) return false;
      const body = (await response.json()) as { user_id?: unknown; expires_at?: unknown };
      if (typeof body.user_id !== "string" || typeof body.expires_at !== "number") return false;
      this.adoptSession(body.user_id, body.expires_at);
      return true;
    } catch {
      return false;
    }
  }

  private adoptSession(userId: string, expiresAt: number): void {
    const { platform, appUrl } = this.config;
    this.clear();
    this.mode = "session";
    const claims: IdentityClaims = { sub: userId, iss: "session", aud: appUrl, iat: Math.floor(platform.now() / 1000), exp: expiresAt };
    this.set("authenticated", claims, null);
    const delay = Math.max(MIN_RENEW_DELAY_MS, expiresAt * 1000 - platform.now());
    this.sessionTimer = setTimeout(() => void this.refreshSession(), delay);
  }

  /** The cookie session ended or is about to: look again, then fall back to the central session (silent sign-in). */
  private async refreshSession(): Promise<void> {
    if (await this.probeSession()) return;
    await this.renew();
  }

  // ----------------------------------------------------------------- sign in

  /** Redirects the browser to the identity service. Throws `login_loop` rather than redirecting forever. */
  login(options: LoginOptions = {}): void {
    const { platform, appUrl, authUrl } = this.config;
    const store = platform.storage();
    if (!store) throw this.fail("storage_unavailable", "This browser blocks the storage sign-in needs.");
    this.guardAgainstLoops();
    const returnTo = safeReturnPath(options.returnTo ?? platform.currentPath(), "/", [this.config.callbackPath]);
    const state = newState(platform);
    if (!savePending(platform, { state, returnTo, startedAt: platform.now() })) {
      throw this.fail("storage_unavailable", "This browser blocks the storage sign-in needs.");
    }
    const query = new URLSearchParams({ redirect: `${appUrl}${returnTo}`, state });
    platform.navigate(`${authUrl}/auth/login?${query.toString()}`);
  }

  private guardAgainstLoops(): void {
    const { platform } = this.config;
    const store = platform.storage();
    if (!store) return;
    let attempts: number[] = [];
    try {
      const parsed: unknown = JSON.parse(store.getItem(LOOP_KEY) ?? "[]");
      if (Array.isArray(parsed)) attempts = parsed.filter((t): t is number => typeof t === "number");
    } catch {
      attempts = [];
    }
    const now = platform.now();
    attempts = attempts.filter((t) => now - t < LOOP_WINDOW_MS);
    if (attempts.length >= LOOP_LIMIT) {
      throw this.fail(
        "login_loop",
        "Sign-in keeps returning without completing. Check that this app's origin is registered with the identity service.",
      );
    }
    try {
      store.setItem(LOOP_KEY, JSON.stringify([...attempts, now]));
    } catch {
      // Storage already proved writable in login(); a failure here only disables the loop guard.
    }
  }

  /**
   * Completes a sign-in on the hand-off page. Calling it again for the same fragment (React StrictMode, a re-render)
   * returns the same result instead of processing the one-time `state` twice.
   */
  handleCallback(hash: string = this.config.platform.hash()): Promise<{ returnTo: string }> {
    // The first call empties the address bar's fragment, so a repeat call (StrictMode) sees "": still the same hand-off.
    if (this.callback && (hash === this.callback.hash || hash === "")) return this.callback.promise;
    const promise = this.processCallback(hash);
    this.callback = { hash, promise };
    return promise;
  }

  private async processCallback(hash: string): Promise<{ returnTo: string }> {
    const { platform } = this.config;
    // Take the token out of the address bar first, so it cannot be copied, bookmarked or leaked by what runs next.
    platform.replaceUrl(platform.currentPath().split("?")[0] ?? "/");
    const params = new URLSearchParams(hash.replace(/^#/, ""));
    const token = params.get("token");
    const state = params.get("state");
    if (!token || !state) throw this.fail("callback_missing", "The sign-in response did not include a token.");
    const pending = takePending(platform);
    if (!pending || !sameState(pending.state, state)) {
      throw this.fail("callback_state", "This sign-in was not started from this tab, or has expired. Try again.");
    }
    let claims: IdentityClaims;
    try {
      claims = readClaims(token, this.config);
    } catch (error) {
      throw this.fail("callback_token", error instanceof Error ? error.message : "The access token was refused.");
    }
    try {
      platform.storage()?.removeItem(LOOP_KEY);
    } catch {
      // nothing to clean up
    }
    this.accept(token, claims);
    return { returnTo: pending.returnTo };
  }

  // ----------------------------------------------------------------- token

  private accept(token: string, claims: IdentityClaims): void {
    this.clear();
    this.token = token;
    this.mode = "token";
    this.set("authenticated", claims, null);
    const { platform, renewSkewSeconds } = this.config;
    const untilExpiry = claims.exp * 1000 - platform.now();
    const delay = Math.max(MIN_RENEW_DELAY_MS, untilExpiry - renewSkewSeconds * 1000);
    this.timer = setTimeout(() => void this.renew(), delay);
  }

  /** The current access token, renewed first when it is about to expire. Null when not signed in. */
  async getAccessToken(): Promise<string | null> {
    if (this.mode === "session") return null; // the cookie is the credential; there is no token to hand out
    const claims = this.snapshot.claims;
    if (this.token && claims && claims.exp * 1000 - this.config.platform.now() > MIN_RENEW_DELAY_MS) return this.token;
    if (this.token || this.snapshot.status === "loading") await this.renew();
    return this.token;
  }

  /**
   * Asks the identity service for a fresh token using the refresh cookie. Resolves true when a valid token is held.
   * Concurrent calls share one request: the refresh token rotates on every use.
   */
  renew(): Promise<boolean> {
    this.renewing ??= this.doRenew().finally(() => {
      this.renewing = null;
    });
    return this.renewing;
  }

  private async doRenew(): Promise<boolean> {
    const { platform, authUrl } = this.config;
    for (let attempt = 0; ; attempt += 1) {
      let response: Response;
      try {
        response = await platform.fetch(`${authUrl}/auth/session/token`, {
          method: "POST",
          credentials: "include",
          headers: { accept: "application/json" },
        });
      } catch {
        // The identity service is unreachable. A token that is still valid keeps working until it expires.
        if (!this.token) this.fail("network", "The sign-in service could not be reached.");
        return this.token !== null;
      }
      if (response.status === 503 && attempt < MAX_BUSY_RETRIES) {
        const wait = Number(response.headers.get("retry-after")) * 1000 || 2_000;
        await platform.sleep(Math.min(wait, MAX_RETRY_WAIT_MS));
        continue;
      }
      return this.finishRenewal(response);
    }
  }

  private async finishRenewal(response: Response): Promise<boolean> {
    if (response.status === 401) {
      const hadSession = this.token !== null || this.mode === "session";
      this.clear();
      this.mode = null;
      this.set("unauthenticated", null, null);
      if (hadSession) this.config.onSessionExpired?.();
      return false;
    }
    if (response.status === 403) {
      this.clear();
      this.fail("origin_not_allowed", "The sign-in service refused this app's origin (see IDENTITY_APP_ORIGINS).");
      return false;
    }
    if (response.status === 503) {
      if (!this.token) this.fail("service_busy", "The sign-in service is busy. Try again in a moment.");
      return this.token !== null;
    }
    try {
      if (!response.ok) throw new Error("unexpected status");
      const body: unknown = await response.json();
      const token = (body as { access_token?: unknown }).access_token;
      if (typeof token !== "string") throw new Error("no token");
      this.accept(token, readClaims(token, this.config));
      return true;
    } catch {
      this.clear();
      this.fail("renew_failed", "The sign-in service gave an unexpected answer.");
      return false;
    }
  }

  // ----------------------------------------------------------------- authenticated requests

  /**
   * `fetch` with the access token attached, for this app's own API only: the token is never sent to an origin that was
   * not configured (`appUrl`, `apiOrigins`). On a 401 the token is renewed and the request retried once.
   */
  async fetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const { platform, appUrl, apiOrigins } = this.config;
    const url = new URL(String(input), appUrl);
    if (this.mode === "session") return this.sessionFetch(url, init);
    if (!apiOrigins.includes(url.origin)) {
      throw new IdentityError("token_destination", `Refusing to send the access token to ${url.origin}.`);
    }
    const send = async (token: string) => {
      const headers = new Headers(init.headers);
      headers.set("authorization", `Bearer ${token}`);
      return platform.fetch(url, { ...init, headers });
    };
    const token = await this.getAccessToken();
    if (!token) throw new IdentityError("not_authenticated", "Not signed in.");
    const response = await send(token);
    if (response.status !== 401) return response;
    if (!(await this.renew()) || !this.token) return response;
    return send(this.token);
  }

  /** In session mode the browser sends this app's cookie itself, to this app's origin only. */
  private async sessionFetch(url: URL, init: RequestInit): Promise<Response> {
    const { platform, appUrl } = this.config;
    if (url.origin !== appUrl) {
      throw new IdentityError("token_destination", `The session cookie only works for ${appUrl}, not ${url.origin}.`);
    }
    const send = () => platform.fetch(url, { ...init, credentials: "same-origin" });
    const response = await send();
    if (response.status !== 401) return response;
    await this.refreshSession();
    if (this.mode === "session") return send();
    if (this.mode === "token") return this.fetch(url, init);
    return response;
  }

  // ----------------------------------------------------------------- sign out

  /** Forgets the token and ends the shared session: a POST to the identity service, which returns to `returnTo`. */
  async logout(options: LoginOptions = {}): Promise<void> {
    const { platform, appUrl, authUrl, sessionLogoutUrl } = this.config;
    const hadCookieSession = this.mode === "session";
    this.clear();
    this.mode = null;
    this.set("unauthenticated", null, null);
    if (hadCookieSession && sessionLogoutUrl) {
      // Ends this app's own cookie session first (it is not reachable from the identity service).
      try {
        await platform.fetch(`${appUrl}${sessionLogoutUrl}`, { method: "POST", credentials: "same-origin" });
      } catch {
        // the central sign-out below still proceeds; the cookie expires on its own
      }
    }
    const returnTo = safeReturnPath(options.returnTo, "/");
    const query = new URLSearchParams({ redirect: `${appUrl}${returnTo}` });
    platform.postForm(`${authUrl}/auth/logout?${query.toString()}`);
  }
}

export function createIdentityClient(options: IdentityClientOptions): IdentityClient {
  return new IdentityClient(options);
}
