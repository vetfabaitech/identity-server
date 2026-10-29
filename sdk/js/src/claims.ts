import type { ResolvedConfig } from "./config.js";

/** What the identity service puts in an access token (CONTRACT.md): the user's id, never profile data or roles. */
export interface IdentityClaims {
  /** The user's id (a UUID): the key to the product's own record of this person. */
  sub: string;
  iss: string;
  aud: string | string[];
  iat: number;
  exp: number;
}

export type ErrorCode =
  | "callback_missing" // the hand-off carried no token or state
  | "callback_state" // state absent, wrong, replayed or expired: not a sign-in this tab started
  | "callback_token" // the token is malformed, expired, or names another issuer or audience
  | "storage_unavailable" // sessionStorage is blocked, so a sign-in cannot be verified
  | "login_loop" // repeated sign-in redirects without ever completing
  | "origin_not_allowed" // the identity service refused this app's origin (IDENTITY_APP_ORIGINS)
  | "service_busy" // the identity service answered 503 after retries
  | "network" // the identity service could not be reached
  | "renew_failed" // an unexpected answer from the identity service
  | "not_authenticated"
  | "token_destination" // refusal to send the access token to an origin that is not configured
  | "unknown_service" // a hand-off target that is not in the registry the identity service published
  | "service_unavailable" // the target is disabled, restricted, or not open to this person
  | "session_expired" // the central session ended, so no hand-off can start
  | "source_not_registered" // this app's origin is not a registered service
  | "too_many_tickets" // too many hand-offs started without being completed
  | "invalid_response" // the identity service answered with something a hand-off cannot use
  | "handoff_in_progress"; // a hand-off is already under way

export class IdentityError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "IdentityError";
  }
}

function decodeSegment(segment: string): unknown {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(segment.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

/**
 * Reads the claims of an access token for the interface (who is signed in, when to renew) after checking the claims
 * that tell this app a token is meant for it. This does NOT verify the signature: the browser holds no reason to
 * trust its own check over the backend's, and every backend endpoint verifies the token itself (CONTRACT.md).
 * Nothing here is an authorisation decision.
 */
export function readClaims(token: string, config: ResolvedConfig): IdentityClaims {
  const bad = (why: string) => new IdentityError("callback_token", `The access token was refused: ${why}.`);
  const parts = token.split(".");
  if (parts.length !== 3 || token.length > 8192) throw bad("malformed");
  let payload: unknown;
  try {
    payload = decodeSegment(parts[1] ?? "");
  } catch {
    throw bad("malformed");
  }
  if (typeof payload !== "object" || payload === null) throw bad("malformed");
  const { sub, iss, aud, iat, exp } = payload as Record<string, unknown>;
  if (typeof sub !== "string" || sub === "") throw bad("no subject");
  if (typeof iat !== "number" || typeof exp !== "number") throw bad("no timestamps");
  if (iss !== config.issuer) throw bad("unexpected issuer");
  const audiences = Array.isArray(aud) ? aud : [aud];
  if (!audiences.includes(config.audience)) throw bad("unexpected audience");
  if (exp * 1000 <= config.platform.now()) throw bad("already expired");
  return { sub, iss, aud: aud as string | string[], iat, exp };
}
