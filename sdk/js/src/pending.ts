/**
 * The sign-in this tab started: a random `state` and where to return to. Kept in sessionStorage (per tab, gone when
 * the tab closes) and consumed exactly once, so a hand-off the tab did not ask for, a replayed one, or one from
 * another tab is refused. The access token itself is never stored here.
 */

import type { Platform } from "./platform.js";

const KEY = "vetfab.identity.pending";
export const PENDING_MAX_AGE_MS = 10 * 60 * 1000;

export interface Pending {
  state: string;
  returnTo: string;
  startedAt: number;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 32 random bytes as base64url: 43 characters of `[A-Za-z0-9_-]`, within what the service echoes back untouched. */
export function newState(platform: Platform): string {
  return base64url(platform.randomBytes(32));
}

export function savePending(platform: Platform, pending: Pending): boolean {
  try {
    platform.storage()?.setItem(KEY, JSON.stringify(pending));
    return platform.storage() !== null;
  } catch {
    return false;
  }
}

/** Reads and deletes the pending sign-in. Null when there is none, it is malformed, or it is too old. */
export function takePending(platform: Platform): Pending | null {
  const store = platform.storage();
  if (!store) return null;
  let raw: string | null;
  try {
    raw = store.getItem(KEY);
    store.removeItem(KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const { state, returnTo, startedAt } = parsed as Record<string, unknown>;
    if (typeof state !== "string" || typeof returnTo !== "string" || typeof startedAt !== "number") return null;
    if (platform.now() - startedAt > PENDING_MAX_AGE_MS || startedAt > platform.now() + 60_000) return null;
    return { state, returnTo, startedAt };
  } catch {
    return null;
  }
}

/** Comparison whose time does not depend on where the strings first differ. */
export function sameState(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
