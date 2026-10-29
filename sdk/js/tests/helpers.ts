import { vi } from "vitest";

import { createIdentityClient, type IdentityClient, type IdentityClientOptions, type Platform } from "../src";

export const AUTH = "http://localhost:8200";
export const APP = "http://localhost:3000";
export const ISSUER = `${AUTH}/auth`;

export class MemoryStore {
  data = new Map<string, string>();
  getItem = (key: string) => this.data.get(key) ?? null;
  setItem = (key: string, value: string) => void this.data.set(key, value);
  removeItem = (key: string) => void this.data.delete(key);
}

export interface FakeBrowser extends Platform {
  clock: { now: number };
  store: MemoryStore;
  path: string;
  fragment: string;
  navigated: string[];
  replaced: string[];
  posted: string[];
  postedFields: Record<string, string>[];
  fetchMock: ReturnType<typeof vi.fn>;
  storageBlocked: boolean;
}

export function fakeBrowser(): FakeBrowser {
  const browser: FakeBrowser = {
    clock: { now: Date.UTC(2026, 9, 27, 12, 0, 0) },
    store: new MemoryStore(),
    path: "/dashboard?tab=1",
    fragment: "",
    navigated: [],
    replaced: [],
    posted: [],
    postedFields: [],
    storageBlocked: false,
    fetchMock: vi.fn(),
    origin: () => APP,
    currentPath: () => browser.path,
    hash: () => browser.fragment,
    navigate: (url) => void browser.navigated.push(url),
    replaceUrl: (path) => {
      browser.replaced.push(path);
      browser.fragment = "";
    },
    postForm: (url, fields = {}) => {
      browser.posted.push(url);
      browser.postedFields.push(fields);
    },
    storage: () => (browser.storageBlocked ? null : browser.store),
    fetch: (...args) => browser.fetchMock(...args),
    now: () => browser.clock.now,
    sleep: async () => {},
    randomBytes: (length) => Uint8Array.from({ length }, (_, i) => (i * 7 + 3) % 256),
  };
  return browser;
}

function segment(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A token shaped like the service's (unsigned: the browser never verifies signatures). */
export function makeToken(browser: FakeBrowser, overrides: Record<string, unknown> = {}, lifetime = 900): string {
  const iat = Math.floor(browser.clock.now / 1000);
  const claims = { sub: "00000000-0000-4000-8000-000000000001", iss: ISSUER, aud: "vetfab", iat, exp: iat + lifetime, ...overrides };
  return `${segment({ alg: "RS256", typ: "at+jwt", kid: "k" })}.${segment(claims)}.signature`;
}

export function setup(options: Partial<IdentityClientOptions> = {}): { browser: FakeBrowser; client: IdentityClient } {
  const browser = fakeBrowser();
  const client = createIdentityClient({ authUrl: AUTH, platform: browser, ...options });
  return { browser, client };
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

/** Runs a full sign-in round trip: login(), then the hand-off the service would send back. */
export function startLogin(browser: FakeBrowser, client: IdentityClient, returnTo = "/dashboard?tab=1"): string {
  client.login({ returnTo });
  const url = new URL(browser.navigated.at(-1) ?? "");
  return url.searchParams.get("state") ?? "";
}
