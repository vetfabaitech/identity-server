import { describe, expect, it, vi } from "vitest";

import { createHandoffClient } from "../src";
import { APP, AUTH, json, setup } from "./helpers";

const IDE = "https://ide.vetfab.ai";
const TICKET = "T".repeat(43);

const LISTING = {
  current: "lms",
  services: [
    { id: "lms", display_name: "Vetfab LMS", base_url: APP, environment: "local" },
    { id: "ide", display_name: "Vetfab IDE", base_url: IDE, environment: "production" },
    { id: "staging", display_name: "Vetfab Staging", base_url: "https://stg.vetfab.ai", environment: "staging" },
  ],
};

function world(routes: Partial<Record<"services" | "handoff", () => Response | Promise<Response>>> = {}) {
  const ctx = setup();
  const handoff = createHandoffClient(ctx.client);
  ctx.browser.fetchMock.mockImplementation(async (input: unknown) => {
    const url = String(input);
    if (url.endsWith("/auth/services")) return (routes.services ?? (() => json(LISTING)))();
    if (url.endsWith("/auth/handoff")) {
      return (routes.handoff ?? (() => json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem`, target: "ide", expires_in: 60 })))();
    }
    throw new Error(`unexpected request ${url}`);
  });
  return { ...ctx, handoff };
}

describe("listing services", () => {
  it("asks the identity service, with the session cookie, and drops the current service", async () => {
    const { browser, handoff } = world();
    const services = await handoff.listAvailableServices();
    expect(browser.fetchMock).toHaveBeenCalledWith(`${AUTH}/auth/services`, expect.objectContaining({ credentials: "include" }));
    expect(services.map((s) => s.id)).toEqual(["ide", "staging"]);
    expect(services[0]).toEqual({ id: "ide", displayName: "Vetfab IDE", baseUrl: IDE, environment: "production" });
    expect(handoff.getSnapshot()).toMatchObject({ status: "ready", current: "lms" });
  });

  it("shares one request between concurrent callers", async () => {
    const { browser, handoff } = world();
    await Promise.all([handoff.listAvailableServices(), handoff.listAvailableServices()]);
    expect(browser.fetchMock).toHaveBeenCalledTimes(1);
  });

  it("ignores entries the page could not safely use", async () => {
    const hostile = {
      current: "lms",
      services: [
        { id: "ide", display_name: "IDE", base_url: IDE, environment: "production" },
        { id: "ev il", display_name: "x", base_url: IDE, environment: "production" },
        { id: "evil", display_name: "x", base_url: "javascript:alert(1)", environment: "production" },
        { id: "evil2", display_name: "x", base_url: "http://evil.example", environment: "production" },
        { id: "evil3", display_name: "x", base_url: "https://evil.example/app", environment: "production" },
        { id: "evil4", display_name: "x", base_url: "https://u:p@evil.example", environment: "production" },
        { id: "evil5", display_name: "x", base_url: IDE, environment: "other" },
        { id: "evil6", display_name: "", base_url: IDE, environment: "production" },
        "string",
        null,
      ],
    };
    const { handoff } = world({ services: () => json(hostile) });
    expect((await handoff.listAvailableServices()).map((s) => s.id)).toEqual(["ide"]);
  });

  it.each([
    [401, "session_expired"],
    [403, "source_not_registered"],
    [500, "invalid_response"],
  ])("explains a %s", async (status, code) => {
    const { handoff } = world({ services: () => json({}, status) });
    await expect(handoff.listAvailableServices()).rejects.toMatchObject({ code });
    expect(handoff.getSnapshot()).toMatchObject({ status: "error", error: { code } });
  });

  it("explains an unreachable service and a malformed answer", async () => {
    const down = world({ services: () => Promise.reject(new TypeError("offline")) });
    await expect(down.handoff.listAvailableServices()).rejects.toMatchObject({ code: "network" });
    const bad = world({ services: () => json({ nothing: true }) });
    await expect(bad.handoff.listAvailableServices()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("looks up a destination's address from the registry, never from the caller", async () => {
    const { handoff } = world();
    await handoff.listAvailableServices();
    expect(handoff.getServiceUrl("ide", "/workspace/3")).toBe(`${IDE}/workspace/3`);
    expect(handoff.getServiceUrl("ide", "//evil.example")).toBe(`${IDE}/`);
    expect(() => handoff.getServiceUrl("https://evil.example")).toThrow(/Unknown service/);
  });
});

describe("starting a hand-off", () => {
  it("gets a ticket and posts it to the registered destination in a form body", async () => {
    const { browser, handoff } = world();
    await handoff.createHandoff("ide", { returnTo: "/workspace/7?tab=2" });
    const call = browser.fetchMock.mock.calls.find(([url]) => String(url).endsWith("/auth/handoff")) as [string, RequestInit];
    expect(call[1]).toMatchObject({ method: "POST", credentials: "include" });
    expect(JSON.parse(String(call[1].body))).toEqual({ target: "ide", return_to: "/workspace/7?tab=2" });
    expect(browser.posted).toEqual([`${IDE}/handoff/redeem`]);
    expect(browser.postedFields).toEqual([{ ticket: TICKET }]);
    expect(browser.posted.join()).not.toContain(TICKET); // never in a URL
    expect(handoff.getSnapshot().status).toBe("redirecting");
  });

  it("goes through every state on the way", async () => {
    const { handoff } = world();
    const seen: string[] = [handoff.getSnapshot().status];
    handoff.subscribe(() => seen.push(handoff.getSnapshot().status));
    await handoff.createHandoff("ide");
    // Loading the list as part of starting a hand-off is reported as "starting": the person pressed a button, not "list".
    expect(seen).toEqual(["idle", "starting", "ready", "starting", "redirecting"]);
  });

  it("refuses a destination the registry did not list, without calling the identity service about it", async () => {
    const { browser, handoff } = world();
    for (const target of ["evil", "https://evil.example", "lms", "", "IDE"]) {
      await expect(handoff.createHandoff(target)).rejects.toMatchObject({ code: "unknown_service" });
      handoff.reset();
    }
    expect(browser.fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/auth/handoff"))).toHaveLength(0);
    expect(browser.posted).toEqual([]);
  });

  it("sends only a safe return path", async () => {
    const { browser, handoff } = world();
    await handoff.createHandoff("ide", { returnTo: "https://evil.example/x" });
    const call = browser.fetchMock.mock.calls.find(([url]) => String(url).endsWith("/auth/handoff")) as [string, RequestInit];
    expect(JSON.parse(String(call[1].body)).return_to).toBe("/");
  });

  it("ignores a second click while one is in progress", async () => {
    let release: (response: Response) => void = () => {};
    const { browser, handoff } = world({ handoff: () => new Promise<Response>((resolve) => (release = resolve)) });
    const first = handoff.createHandoff("ide");
    const second = handoff.createHandoff("ide");
    expect(second).toBe(first);
    await vi.waitFor(() =>
      expect(browser.fetchMock.mock.calls.some(([url]) => String(url).endsWith("/auth/handoff"))).toBe(true),
    );
    expect(handoff.getSnapshot().status).toBe("starting");
    release(json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem` }));
    await first;
    await handoff.createHandoff("ide"); // and one after success still starts nothing
    expect(browser.fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/auth/handoff"))).toHaveLength(1);
    expect(browser.posted).toHaveLength(1);
  });

  it("can be tried again after a failure", async () => {
    let answer = json({}, 429);
    const { browser, handoff } = world({ handoff: () => answer });
    await expect(handoff.createHandoff("ide")).rejects.toMatchObject({ code: "too_many_tickets" });
    answer = json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem` });
    await handoff.createHandoff("ide");
    expect(browser.posted).toHaveLength(1);
  });

  it.each([
    [401, "session_expired"],
    [403, "service_unavailable"],
    [429, "too_many_tickets"],
    [500, "invalid_response"],
  ])("explains a %s from the identity service", async (status, code) => {
    const { browser, handoff } = world({ handoff: () => json({ error: "x" }, status) });
    await expect(handoff.createHandoff("ide")).rejects.toMatchObject({ code });
    expect(handoff.getSnapshot()).toMatchObject({ status: "error", target: null });
    expect(browser.posted).toEqual([]);
  });

  it("reports an unreachable identity service", async () => {
    const { handoff } = world({ handoff: () => Promise.reject(new TypeError("offline")) });
    await expect(handoff.createHandoff("ide")).rejects.toMatchObject({ code: "network" });
  });

  it.each([
    ["a redemption address on another origin", { ticket: TICKET, redeem_url: "https://evil.example/handoff/redeem" }],
    ["a look-alike origin", { ticket: TICKET, redeem_url: "https://ide.vetfab.ai.evil.example/handoff/redeem" }],
    ["another service's origin", { ticket: TICKET, redeem_url: "https://stg.vetfab.ai/handoff/redeem" }],
    ["no redemption address", { ticket: TICKET }],
    ["a malformed ticket", { ticket: "short", redeem_url: `${IDE}/handoff/redeem` }],
    ["no ticket", { redeem_url: `${IDE}/handoff/redeem` }],
    ["a non-string ticket", { ticket: 5, redeem_url: `${IDE}/handoff/redeem` }],
  ])("never posts a ticket given %s", async (_label, body) => {
    const { browser, handoff } = world({ handoff: () => json(body) });
    await expect(handoff.createHandoff("ide")).rejects.toMatchObject({ code: "invalid_response" });
    expect(browser.posted).toEqual([]);
  });
});
