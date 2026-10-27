/**
 * Starting an SSO hand-off from this app to another Vetfab service. Separate from sign-in on purpose: signing in is
 * `IdentityClient`'s job; moving a signed-in person to another service is this file's.
 *
 * The browser never validates a hand-off by itself. It asks the identity service for a one-time ticket, then posts the
 * ticket (in a form body, never a URL) to the destination, whose *backend* redeems it with the identity service and
 * starts the destination's own session. What this code checks is only what it must to avoid sending a person or a
 * ticket somewhere the registry did not name: the destination must be in the list the identity service published, and
 * the address it was told to post to must be that service's own origin.
 */

import { type ErrorCode, IdentityError } from "./claims.js";
import type { IdentityClient } from "./client.js";
import { safeReturnPath } from "./redirects.js";

export interface ServiceInfo {
  id: string;
  displayName: string;
  /** Origin of the service, from the identity service's registry. */
  baseUrl: string;
  environment: "local" | "staging" | "production";
}

export type HandoffStatus = "idle" | "loading" | "ready" | "starting" | "redirecting" | "error";

export interface HandoffSnapshot {
  status: HandoffStatus;
  /** Services this person may open, excluding the one this app is. Empty until loaded. */
  services: ServiceInfo[];
  /** Id of the service this app is, as the identity service knows it. */
  current: string | null;
  /** The destination of the hand-off in progress. */
  target: string | null;
  error: IdentityError | null;
}

export interface HandoffOptions {
  /** A path on the destination to open. Anything else (another origin, `//host`, the redemption route) becomes `/`. */
  returnTo?: string;
}

const SERVICE_ID = /^[a-z][a-z0-9-]{1,31}$/;
const TICKET = /^[A-Za-z0-9_-]{40,64}$/;
const ENVIRONMENTS = new Set(["local", "staging", "production"]);
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function validOrigin(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) return null;
    if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return url.origin;
  } catch {
    // fall through
  }
  return null;
}

function parseService(entry: unknown): ServiceInfo | null {
  if (typeof entry !== "object" || entry === null) return null;
  const { id, display_name: name, base_url: base, environment } = entry as Record<string, unknown>;
  const baseUrl = validOrigin(base);
  if (typeof id !== "string" || !SERVICE_ID.test(id) || typeof name !== "string" || !name || !baseUrl) return null;
  if (typeof environment !== "string" || !ENVIRONMENTS.has(environment)) return null;
  return { id, displayName: name.slice(0, 60), baseUrl, environment: environment as ServiceInfo["environment"] };
}

type Listener = () => void;

export class HandoffClient {
  private snapshot: HandoffSnapshot = { status: "idle", services: [], current: null, target: null, error: null };
  private listeners = new Set<Listener>();
  private loading: Promise<ServiceInfo[]> | null = null;
  private all: ServiceInfo[] = [];
  private starting: Promise<void> | null = null;

  constructor(private readonly client: IdentityClient) {}

  getSnapshot = (): HandoffSnapshot => this.snapshot;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private set(patch: Partial<HandoffSnapshot>): void {
    this.snapshot = { ...this.snapshot, ...patch };
    for (const listener of [...this.listeners]) listener();
  }

  private fail(code: ErrorCode, message: string): IdentityError {
    const error = new IdentityError(code, message);
    this.set({ status: "error", error, target: null });
    return error;
  }

  /**
   * The services this person may open, from the identity service's registry (never from configuration in the page).
   * A visibility convenience for the interface: the destination and the identity service enforce access themselves.
   * Concurrent calls share one request.
   */
  listAvailableServices(): Promise<ServiceInfo[]> {
    this.loading ??= this.load().finally(() => {
      this.loading = null;
    });
    return this.loading;
  }

  private async load(): Promise<ServiceInfo[]> {
    const { platform, authUrl } = this.client.config;
    if (this.snapshot.status !== "starting" && this.snapshot.status !== "redirecting") this.set({ status: "loading", error: null });
    let response: Response;
    try {
      response = await platform.fetch(`${authUrl}/auth/services`, { credentials: "include", headers: { accept: "application/json" } });
    } catch {
      throw this.fail("network", "The sign-in service could not be reached.");
    }
    if (response.status === 401) throw this.fail("session_expired", "Your session has ended. Sign in again.");
    if (response.status === 403) throw this.fail("source_not_registered", "This app is not registered for service switching.");
    if (!response.ok) throw this.fail("invalid_response", "The sign-in service gave an unexpected answer.");
    let body: { current?: unknown; services?: unknown };
    try {
      body = (await response.json()) as typeof body;
    } catch {
      throw this.fail("invalid_response", "The sign-in service gave an unexpected answer.");
    }
    if (!Array.isArray(body.services)) throw this.fail("invalid_response", "The sign-in service gave an unexpected answer.");
    const parsed = body.services.map(parseService).filter((s): s is ServiceInfo => s !== null);
    const current = typeof body.current === "string" && SERVICE_ID.test(body.current) ? body.current : null;
    this.all = parsed;
    this.set({ status: "ready", services: parsed.filter((s) => s.id !== current), current, error: null });
    return this.snapshot.services;
  }

  /** The address of a listed service, for a plain link. It does NOT sign anyone in: use `createHandoff` for that. */
  getServiceUrl(serviceId: string, returnTo?: string): string {
    const service = this.all.find((s) => s.id === serviceId);
    if (!service) throw new IdentityError("unknown_service", `Unknown service ${JSON.stringify(serviceId)}.`);
    return `${service.baseUrl}${safeReturnPath(returnTo, "/")}`;
  }

  /**
   * Moves the signed-in person to another service without a second sign-in: gets a one-time ticket bound to that
   * destination, then posts it to the destination's redemption route (a full-page navigation). Resolves once the
   * browser is on its way. A second call while one is in progress returns the first call's promise (double clicks).
   */
  createHandoff(serviceId: string, options: HandoffOptions = {}): Promise<void> {
    if (this.starting) return this.starting;
    const attempt: Promise<void> = this.run(serviceId, options).finally(() => {
      // After a success the status stays "redirecting" and `starting` stays set, so the page cannot start a second
      // hand-off in the moments before it navigates away. After any failure the person can try again.
      if (this.snapshot.status !== "redirecting") this.starting = null;
    });
    this.starting = attempt;
    return attempt;
  }

  private async run(serviceId: string, options: HandoffOptions): Promise<void> {
    const { platform, authUrl } = this.client.config;
    this.set({ status: "starting", target: serviceId, error: null });
    if (this.all.length === 0) await this.listAvailableServices();
    const service = this.all.find((s) => s.id === serviceId);
    if (!service || service.id === this.snapshot.current) {
      throw this.fail("unknown_service", `Unknown service ${JSON.stringify(serviceId)}.`);
    }
    this.set({ status: "starting", target: service.id, error: null });
    let response: Response;
    try {
      response = await platform.fetch(`${authUrl}/auth/handoff`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ target: service.id, return_to: safeReturnPath(options.returnTo, "/") }),
      });
    } catch {
      throw this.fail("network", "The sign-in service could not be reached.");
    }
    const refusal = this.refusal(response.status);
    if (refusal) throw this.fail(refusal[0], refusal[1]);
    let ticket: unknown;
    let redeemUrl: unknown;
    try {
      ({ ticket, redeem_url: redeemUrl } = (await response.json()) as Record<string, unknown>);
    } catch {
      // handled below
    }
    // The ticket may only go to the service the registry named: same origin as that service's base URL.
    const destination = typeof redeemUrl === "string" ? safeUrl(redeemUrl) : null;
    if (typeof ticket !== "string" || !TICKET.test(ticket) || !destination || destination.origin !== service.baseUrl) {
      throw this.fail("invalid_response", "The sign-in service gave an unexpected answer.");
    }
    this.set({ status: "redirecting" });
    platform.postForm(destination.href, { ticket });
  }

  private refusal(status: number): [ErrorCode, string] | null {
    if (status === 200) return null;
    if (status === 401) return ["session_expired", "Your session has ended. Sign in again."];
    if (status === 403) return ["service_unavailable", "That service is not available to you."];
    if (status === 429) return ["too_many_tickets", "Too many requests. Wait a minute and try again."];
    return ["invalid_response", "The sign-in service gave an unexpected answer."];
  }

  /** Clears an error so the switcher can be used again. */
  reset(): void {
    if (this.snapshot.status === "redirecting") return;
    this.starting = null;
    this.set({ status: this.all.length > 0 ? "ready" : "idle", target: null, error: null });
  }
}

function safeUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

export function createHandoffClient(client: IdentityClient): HandoffClient {
  return new HandoffClient(client);
}
