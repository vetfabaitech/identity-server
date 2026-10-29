import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { APP, AUTH, json, makeToken, setup } from "./helpers";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

const OPTIONS = { sessionUrl: "/handoff/session", sessionLogoutUrl: "/handoff/logout" };

function sessionBody(browser: { clock: { now: number } }, userId = "00000000-0000-4000-8000-000000000009", seconds = 900) {
  return { user_id: userId, expires_at: Math.floor(browser.clock.now / 1000) + seconds };
}

describe("a service reached by SSO hand-off (its own cookie session)", () => {
  it("recognises the session its backend started, without asking the identity service", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockResolvedValue(json(sessionBody(browser)));
    await client.init();
    expect(browser.fetchMock).toHaveBeenCalledOnce();
    expect(browser.fetchMock).toHaveBeenCalledWith(`${APP}/handoff/session`, { credentials: "same-origin" });
    expect(client.getSnapshot()).toMatchObject({ status: "authenticated", mode: "session" });
    expect(client.getSnapshot().claims?.sub).toBe("00000000-0000-4000-8000-000000000009");
  });

  it("falls back to silent sign-in when there is no cookie session", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockImplementation(async (input: unknown) =>
      String(input).endsWith("/handoff/session")
        ? json({ error: "no_session" }, 401)
        : json({ access_token: makeToken(browser), expires_in: 900 }),
    );
    await client.init();
    expect(client.getSnapshot()).toMatchObject({ status: "authenticated", mode: "token" });
  });

  it("has no access token to hand out in session mode, and sends the cookie only to its own origin", async () => {
    const { browser, client } = setup({ ...OPTIONS, apiOrigins: ["http://localhost:8000"] });
    browser.fetchMock.mockResolvedValue(json(sessionBody(browser)));
    await client.init();
    expect(await client.getAccessToken()).toBeNull();
    browser.fetchMock.mockReset();
    browser.fetchMock.mockResolvedValue(json({ ok: true }));
    await client.fetch("/api/me");
    const [, init] = browser.fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).has("authorization")).toBe(false);
    await expect(client.fetch("http://localhost:8000/api/me")).rejects.toMatchObject({ code: "token_destination" });
    await expect(client.fetch("https://evil.example/x")).rejects.toMatchObject({ code: "token_destination" });
  });

  it("looks again when the cookie session expires, and signs out if the person is gone", async () => {
    const onSessionExpired = vi.fn();
    const { browser, client } = setup({ ...OPTIONS, onSessionExpired });
    browser.fetchMock.mockResolvedValueOnce(json(sessionBody(browser, undefined, 100)));
    await client.init();
    browser.fetchMock.mockResolvedValue(json({ error: "gone" }, 401));
    browser.clock.now += 101_000;
    await vi.advanceTimersByTimeAsync(101_000);
    expect(client.getSnapshot().status).toBe("unauthenticated");
    expect(onSessionExpired).toHaveBeenCalledOnce();
  });

  it("re-checks after a 401 from the API and carries on if the session is still good", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockResolvedValueOnce(json(sessionBody(browser)));
    await client.init();
    browser.fetchMock.mockReset();
    browser.fetchMock
      .mockResolvedValueOnce(json({}, 401)) // the API call
      .mockResolvedValueOnce(json(sessionBody(browser))) // the re-check
      .mockResolvedValueOnce(json({ ok: true })); // the retried API call
    expect((await client.fetch("/api/me")).status).toBe(200);
  });

  it("ends its own session, then the central one, on sign-out", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockResolvedValueOnce(json(sessionBody(browser)));
    await client.init();
    browser.fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await client.logout({ returnTo: "/bye" });
    expect(browser.fetchMock).toHaveBeenCalledWith(`${APP}/handoff/logout`, { method: "POST", credentials: "same-origin" });
    expect(new URL(browser.posted[0] ?? "").origin).toBe(AUTH);
    expect(client.getSnapshot().status).toBe("unauthenticated");
  });

  it("still signs out centrally if ending the local session fails", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockResolvedValueOnce(json(sessionBody(browser)));
    await client.init();
    browser.fetchMock.mockRejectedValue(new TypeError("offline"));
    await client.logout();
    expect(browser.posted).toHaveLength(1);
  });

  it("is not session mode at all unless configured", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ error: "no_session" }, 401));
    await client.init();
    expect(browser.fetchMock.mock.calls.map(([url]) => String(url))).toEqual([`${AUTH}/auth/session/token`]);
  });

  it("refuses malformed session answers", async () => {
    const { browser, client } = setup(OPTIONS);
    browser.fetchMock.mockImplementation(async (input: unknown) =>
      String(input).endsWith("/handoff/session") ? json({ user_id: 5 }) : json({}, 401),
    );
    await client.init();
    expect(client.getSnapshot().status).toBe("unauthenticated");
  });

  it("only accepts same-app paths for its session routes", () => {
    expect(() => setup({ sessionUrl: "https://evil.example/s" })).toThrow(/sessionUrl/);
    expect(() => setup({ sessionLogoutUrl: "//evil.example" })).toThrow(/sessionLogoutUrl/);
  });
});
