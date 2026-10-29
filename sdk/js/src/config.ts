/**
 * Client configuration. Nothing environment-specific is hardcoded: `authUrl` comes from the host application's own
 * configuration (`http://localhost:8200` in development), validated here with every problem reported at once.
 */

import { browserPlatform, type Platform } from "./platform.js";

export interface IdentityClientOptions {
  /** Origin of the identity service, e.g. `http://localhost:8200`. Required. */
  authUrl: string;
  /** Origin of this application. Must be listed in the identity service's `IDENTITY_APP_ORIGINS`. Defaults to the page's origin. */
  appUrl?: string;
  /** Where the identity service returns the browser with the token. Fixed by the service's contract. Default `/handoff`. */
  callbackPath?: string;
  /** Expected token issuer. Default `<authUrl>/auth`. */
  issuer?: string;
  /** Expected token audience. Default `vetfab`. */
  audience?: string;
  /** Extra origins (besides `appUrl`) that `client.fetch` may attach the access token to, e.g. a separate API host. */
  apiOrigins?: string[];
  /** Renew this many seconds before the token expires. Default 60. */
  renewSkewSeconds?: number;
  /**
   * Same-origin path of this app's backend route that reports its own cookie session (`handoffRouter` serves
   * `/handoff/session`). Set it when people can arrive by SSO hand-off: the page then recognises the session the
   * hand-off started instead of asking the identity service again.
   */
  sessionUrl?: string;
  /** Same-origin path that ends this app's own cookie session (`/handoff/logout`). */
  sessionLogoutUrl?: string;
  /** Called when a renewal is refused because the session ended (signed out elsewhere, revoked, expired). */
  onSessionExpired?: () => void;
  /** Browser operations; replace in tests or non-browser hosts. */
  platform?: Platform;
}

export interface ResolvedConfig {
  authUrl: string;
  appUrl: string;
  callbackPath: string;
  issuer: string;
  audience: string;
  apiOrigins: string[];
  renewSkewSeconds: number;
  sessionUrl: string | null;
  sessionLogoutUrl: string | null;
  onSessionExpired: (() => void) | undefined;
  platform: Platform;
}

export class IdentityConfigError extends Error {
  constructor(problems: string[]) {
    super(`Invalid Vetfab identity configuration:\n- ${problems.join("\n- ")}`);
    this.name = "IdentityConfigError";
  }
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function originOf(value: string): URL | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

function checkOrigin(name: string, value: string | undefined, problems: string[]): string {
  const url = value ? originOf(value) : null;
  if (!url) {
    problems.push(`${name} must be an origin such as http://localhost:8200 (got ${JSON.stringify(value ?? "")}).`);
    return "";
  }
  // Plain http is for local development only: tokens and cookies must never travel in clear text elsewhere.
  if (url.protocol === "http:" && !LOOPBACK.has(url.hostname)) {
    problems.push(`${name} must use https unless it is localhost (got ${value}).`);
  }
  return url.origin;
}

export function resolveConfig(options: IdentityClientOptions): ResolvedConfig {
  const problems: string[] = [];
  const platform = options.platform ?? browserPlatform();
  const authUrl = checkOrigin("authUrl", options.authUrl?.replace(/\/+$/, ""), problems);
  const appUrl = checkOrigin("appUrl", options.appUrl ?? platform.origin(), problems);
  const apiOrigins = (options.apiOrigins ?? []).map((origin) => checkOrigin("apiOrigins entry", origin, problems));
  const callbackPath = options.callbackPath ?? "/handoff";
  if (!callbackPath.startsWith("/") || callbackPath.startsWith("//")) {
    problems.push("callbackPath must be a path starting with a single '/'.");
  }
  for (const [name, value] of [["sessionUrl", options.sessionUrl], ["sessionLogoutUrl", options.sessionLogoutUrl]] as const) {
    if (value !== undefined && (!value.startsWith("/") || value.startsWith("//"))) {
      problems.push(`${name} must be a path on this app starting with a single '/'.`);
    }
  }
  if (problems.length > 0) throw new IdentityConfigError(problems);
  return {
    authUrl,
    appUrl,
    callbackPath,
    issuer: options.issuer ?? `${authUrl}/auth`,
    audience: options.audience ?? "vetfab",
    apiOrigins: [appUrl, ...apiOrigins],
    renewSkewSeconds: options.renewSkewSeconds ?? 60,
    sessionUrl: options.sessionUrl ?? null,
    sessionLogoutUrl: options.sessionLogoutUrl ?? null,
    onSessionExpired: options.onSessionExpired,
    platform,
  };
}
