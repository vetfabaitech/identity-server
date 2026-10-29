/**
 * Where the browser may return to after sign-in or sign-out: a same-origin path, never a URL.
 *
 * Mirrors the identity service's own screening (`identity/redirects.py`): control characters, whitespace, backslashes
 * and scheme-relative forms are refused, and dot segments are resolved before the checks, the way a browser would, so
 * `/a/../../evil` or `/%2e%2e//evil.example` cannot escape. The sign-in flow's own paths are never destinations
 * (they would loop).
 */

const MAX_LENGTH = 2048;
// Control characters, space, DEL and C1 controls, no-break space, line/paragraph separators, backslash (0x5c).
const FORBIDDEN = /[\x00-\x20\x7f-\x9f\xa0\x5c]|\u2028|\u2029/; // eslint-disable-line no-control-regex

export function safeReturnPath(value: string | null | undefined, fallback = "/", flowPaths: string[] = []): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_LENGTH) return fallback;
  if (FORBIDDEN.test(value) || !value.startsWith("/") || value.startsWith("//")) return fallback;
  let resolved: URL;
  try {
    resolved = new URL(value, "http://placeholder.invalid");
  } catch {
    return fallback;
  }
  if (resolved.origin !== "http://placeholder.invalid") return fallback;
  const path = resolved.pathname;
  if (path.startsWith("//")) return fallback;
  for (const flow of ["/handoff", "/signin", "/signout", ...flowPaths]) {
    if (path === flow || path.startsWith(`${flow}/`)) return fallback;
  }
  return path + resolved.search + resolved.hash;
}
