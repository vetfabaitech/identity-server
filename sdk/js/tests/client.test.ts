import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { IdentityConfigError, createIdentityClient } from "../src";
import { APP, AUTH, ISSUER, json, makeToken, setup, startLogin } from "./helpers";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("configuration", () => {
  it("reports every problem at once", () => {
    expect(() => createIdentityClient({ authUrl: "", appUrl: "http://example.com/app", callbackPath: "handoff" })).toThrow(
      IdentityConfigError,
    );
    try {
      createIdentityClient({ authUrl: "", appUrl: "http://example.com/app", callbackPath: "handoff" });
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain("authUrl");
      expect(message).toContain("appUrl");
      expect(message).toContain("callbackPath");
    }
  });

  it("allows plain http for localhost only", () => {
    expect(() => setup({ authUrl: "http://127.0.0.1:8200" })).not.toThrow();
    expect(() => setup({ authUrl: "http://auth.example.com" })).toThrow(/https/);
    expect(() => setup({ authUrl: "https://auth.example.com", appUrl: "http://app.example.com" })).toThrow(/appUrl/);
  });

  it("derives issuer and audience from authUrl", () => {
    const { client } = setup({ authUrl: `${AUTH}/` });
    expect(client.config.issuer).toBe(ISSUER);
    expect(client.config.audience).toBe("vetfab");
  });
});

describe("login", () => {
  it("redirects to the service with an absolute return URL and a fresh state", () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client, "/lab/3?x=1");
    const url = new URL(browser.navigated[0] ?? "");
    expect(url.origin + url.pathname).toBe(`${AUTH}/auth/login`);
    expect(url.searchParams.get("redirect")).toBe(`${APP}/lab/3?x=1`);
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(browser.store.getItem("vetfab.identity.pending")).toContain(state);
  });

  it.each(["//evil.example", "https://evil.example/x", "/\\evil", "/handoff", "javascript:alert(1)"])(
    "never returns to %s",
    (returnTo) => {
      const { browser, client } = setup();
      client.login({ returnTo });
      const redirect = new URL(browser.navigated[0] ?? "").searchParams.get("redirect");
      expect(redirect).toBe(`${APP}/`);
    },
  );

  it("resolves dot segments so the return path stays on this origin", () => {
    const { browser, client } = setup();
    client.login({ returnTo: "/a/../../../evil" });
    expect(new URL(browser.navigated[0] ?? "").searchParams.get("redirect")).toBe(`${APP}/evil`);
  });

  it("fails closed when storage is blocked", () => {
    const { browser, client } = setup();
    browser.storageBlocked = true;
    expect(() => client.login()).toThrow(/storage/);
    expect(browser.navigated).toEqual([]);
    expect(client.getSnapshot().error?.code).toBe("storage_unavailable");
  });

  it("stops a redirect loop instead of looping forever", () => {
    const { browser, client } = setup();
    for (let i = 0; i < 3; i += 1) client.login();
    expect(() => client.login()).toThrow(/keeps returning/);
    expect(browser.navigated).toHaveLength(3);
    expect(client.getSnapshot().error?.code).toBe("login_loop");
  });
});

describe("callback", () => {
  it("signs in, drops the token from the address bar and returns where the person was", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client, "/lab/3");
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&redirect=%2Flab%2F3&state=${state}`;
    expect(client.isCallback()).toBe(true);
    const result = await client.handleCallback();
    expect(result).toEqual({ returnTo: "/lab/3" });
    expect(browser.replaced).toEqual(["/handoff"]);
    const snapshot = client.getSnapshot();
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.claims?.sub).toBe("00000000-0000-4000-8000-000000000001");
  });

  it("ignores the redirect in the fragment and uses the one this tab chose", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client, "/lab/3");
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&redirect=%2F%2Fevil.example&state=${state}`;
    expect((await client.handleCallback()).returnTo).toBe("/lab/3");
  });

  it("refuses a hand-off with the wrong state", async () => {
    const { browser, client } = setup();
    startLogin(browser, client);
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&state=${"A".repeat(43)}`;
    await expect(client.handleCallback()).rejects.toMatchObject({ code: "callback_state" });
    expect(client.getSnapshot().status).toBe("error");
  });

  it("refuses a hand-off this tab never asked for", async () => {
    const { browser, client } = setup();
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&state=${"A".repeat(43)}`;
    await expect(client.handleCallback()).rejects.toMatchObject({ code: "callback_state" });
  });

  it("refuses a hand-off with no token or no state", async () => {
    const { browser, client } = setup();
    startLogin(browser, client);
    await expect(client.handleCallback("#state=abc")).rejects.toMatchObject({ code: "callback_missing" });
    await expect(client.handleCallback("")).rejects.toMatchObject({ code: "callback_missing" });
    expect(browser.navigated).toHaveLength(1);
  });

  it("uses each state once: a replay is refused", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    const hash = `#token=${makeToken(browser)}&state=${state}`;
    await client.handleCallback(hash);
    const replay = setup();
    replay.browser.store = browser.store;
    await expect(replay.client.handleCallback(hash)).rejects.toMatchObject({ code: "callback_state" });
  });

  it("processes the same fragment once when called twice (StrictMode)", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    const hash = `#token=${makeToken(browser)}&state=${state}`;
    const [first, second] = await Promise.all([client.handleCallback(hash), client.handleCallback(hash)]);
    expect(first).toBe(second);
    expect(client.getSnapshot().status).toBe("authenticated");
  });

  it("refuses a sign-in that took more than ten minutes", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    browser.clock.now += 11 * 60 * 1000;
    await expect(client.handleCallback(`#token=${makeToken(browser)}&state=${state}`)).rejects.toMatchObject({
      code: "callback_state",
    });
  });

  it.each([
    ["another issuer", { iss: "https://evil.example/auth" }],
    ["another audience", { aud: "someone-else" }],
    ["an expired token", { exp: 1 }],
    ["no subject", { sub: "" }],
  ])("refuses a token with %s", async (_label, overrides) => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    await expect(
      client.handleCallback(`#token=${makeToken(browser, overrides)}&state=${state}`),
    ).rejects.toMatchObject({ code: "callback_token" });
    expect(client.getSnapshot().status).toBe("error");
  });

  it("refuses a malformed token", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    await expect(client.handleCallback(`#token=not-a-jwt&state=${state}`)).rejects.toMatchObject({
      code: "callback_token",
    });
  });

  it("keeps the access token out of storage and the address bar", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client);
    const token = makeToken(browser);
    await client.handleCallback(`#token=${token}&state=${state}`);
    expect([...browser.store.data.values()].join("")).not.toContain(token);
    expect(browser.replaced.join("")).not.toContain(token);
    expect(await client.getAccessToken()).toBe(token);
  });
});

describe("renewal", () => {
  it("renews from the refresh cookie when the page opens, signing a returning person in silently", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.init();
    expect(browser.fetchMock).toHaveBeenCalledWith(
      `${AUTH}/auth/session/token`,
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
    expect(client.getSnapshot().status).toBe("authenticated");
  });

  it("is signed out when there is no session", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ error: "no_session" }, 401));
    await client.init();
    expect(client.getSnapshot()).toMatchObject({ status: "unauthenticated", error: null });
  });

  it("does not renew on the hand-off page: the callback handles it", async () => {
    const { browser, client } = setup();
    browser.path = "/handoff";
    browser.fragment = "#token=x&state=y";
    await client.init();
    expect(browser.fetchMock).not.toHaveBeenCalled();
    expect(client.getSnapshot().status).toBe("loading");
  });

  it("renews in the background before the token expires", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockImplementation(async () => json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.init();
    expect(browser.fetchMock).toHaveBeenCalledTimes(1);
    browser.clock.now += 850_000;
    await vi.advanceTimersByTimeAsync(850_000);
    expect(browser.fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shares one request between concurrent renewals", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockImplementation(async () => json({ access_token: makeToken(browser), expires_in: 900 }));
    await Promise.all([client.renew(), client.renew(), client.renew()]);
    expect(browser.fetchMock).toHaveBeenCalledTimes(1);
  });

  it("treats a refused renewal as the end of the session and says so", async () => {
    const onSessionExpired = vi.fn();
    const { browser, client } = setup({ onSessionExpired });
    browser.fetchMock.mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.renew();
    browser.fetchMock.mockResolvedValueOnce(json({ error: "revoked" }, 401));
    expect(await client.renew()).toBe(false);
    expect(client.getSnapshot().status).toBe("unauthenticated");
    expect(onSessionExpired).toHaveBeenCalledOnce();
    expect(await client.getAccessToken()).toBeNull();
  });

  it("explains a refused origin", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ error: "origin" }, 403));
    await client.init();
    expect(client.getSnapshot().error?.code).toBe("origin_not_allowed");
  });

  it("retries a busy service and then succeeds", async () => {
    const { browser, client } = setup();
    browser.fetchMock
      .mockResolvedValueOnce(json({ error: "busy" }, 503, { "retry-after": "2" }))
      .mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.init();
    expect(browser.fetchMock).toHaveBeenCalledTimes(2);
    expect(client.getSnapshot().status).toBe("authenticated");
  });

  it("gives up on a service that stays busy without signing the person out", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ error: "busy" }, 503));
    await client.init();
    expect(browser.fetchMock).toHaveBeenCalledTimes(3);
    expect(client.getSnapshot().error?.code).toBe("service_busy");
  });

  it("keeps a valid token through an outage of the identity service", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.renew();
    browser.fetchMock.mockRejectedValue(new TypeError("offline"));
    expect(await client.renew()).toBe(true);
    expect(client.getSnapshot().status).toBe("authenticated");
  });

  it("reports an unreachable service when there is no token", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockRejectedValue(new TypeError("offline"));
    await client.init();
    expect(client.getSnapshot().error?.code).toBe("network");
  });

  it("rejects a renewal answer whose token is for somebody else", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ access_token: makeToken(browser, { aud: "other" }), expires_in: 900 }));
    await client.init();
    expect(client.getSnapshot()).toMatchObject({ status: "error" });
    expect(await client.getAccessToken()).toBeNull();
  });
});

describe("authenticated requests", () => {
  async function signedIn() {
    const ctx = setup({ apiOrigins: ["http://localhost:8000"] });
    ctx.browser.fetchMock.mockResolvedValueOnce(json({ access_token: makeToken(ctx.browser), expires_in: 900 }));
    await ctx.client.renew();
    ctx.browser.fetchMock.mockReset();
    return ctx;
  }

  it("attaches the bearer token for the app and its configured API origins", async () => {
    const { browser, client } = await signedIn();
    browser.fetchMock.mockResolvedValue(json({ ok: true }));
    await client.fetch("/api/me");
    await client.fetch("http://localhost:8000/api/me");
    const calls = browser.fetchMock.mock.calls as [URL, RequestInit][];
    expect(calls.map(([url]) => url.href)).toEqual([`${APP}/api/me`, "http://localhost:8000/api/me"]);
    for (const [, init] of calls) expect(new Headers(init.headers).get("authorization")).toMatch(/^Bearer ey/);
  });

  it("never sends the token to another origin", async () => {
    const { browser, client } = await signedIn();
    await expect(client.fetch("https://evil.example/steal")).rejects.toMatchObject({ code: "token_destination" });
    await expect(client.fetch("//evil.example/steal")).rejects.toMatchObject({ code: "token_destination" });
    expect(browser.fetchMock).not.toHaveBeenCalled();
  });

  it("renews once and retries after a 401, then gives the 401 back", async () => {
    const { browser, client } = await signedIn();
    browser.fetchMock
      .mockResolvedValueOnce(json({ detail: "expired" }, 401))
      .mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }))
      .mockResolvedValueOnce(json({ ok: true }));
    expect((await client.fetch("/api/me")).status).toBe(200);
    expect(browser.fetchMock).toHaveBeenCalledTimes(3);

    browser.fetchMock.mockReset();
    browser.fetchMock
      .mockResolvedValueOnce(json({}, 401))
      .mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }))
      .mockResolvedValueOnce(json({}, 401));
    expect((await client.fetch("/api/me")).status).toBe(401);
    expect(browser.fetchMock).toHaveBeenCalledTimes(3);
  });

  it("refuses to call the API when signed out", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({}, 401));
    await client.init();
    browser.fetchMock.mockReset();
    await expect(client.fetch("/api/me")).rejects.toMatchObject({ code: "not_authenticated" });
    expect(browser.fetchMock).not.toHaveBeenCalled();
  });
});

describe("logout", () => {
  it("forgets the token and posts to the service, returning to a safe path", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValueOnce(json({ access_token: makeToken(browser), expires_in: 900 }));
    await client.renew();
    client.logout({ returnTo: "/goodbye" });
    expect(client.getSnapshot().status).toBe("unauthenticated");
    expect(await client.getAccessToken()).toBeNull();
    const url = new URL(browser.posted[0] ?? "");
    expect(url.origin + url.pathname).toBe(`${AUTH}/auth/logout`);
    expect(url.searchParams.get("redirect")).toBe(`${APP}/goodbye`);
  });

  it("does not return anywhere but this app", () => {
    const { browser, client } = setup();
    client.logout({ returnTo: "https://evil.example" });
    expect(new URL(browser.posted[0] ?? "").searchParams.get("redirect")).toBe(`${APP}/`);
  });
});
