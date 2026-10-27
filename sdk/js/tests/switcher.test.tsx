import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createHandoffClient } from "../src";
import { VetfabServiceSwitcher } from "../src/react";
import { APP, json, setup } from "./helpers";

afterEach(cleanup);

const IDE = "https://ide.vetfab.ai";
const TICKET = "T".repeat(43);
const LISTING = {
  current: "lms",
  services: [
    { id: "lms", display_name: "Vetfab LMS", base_url: APP, environment: "production" },
    { id: "ide", display_name: "Vetfab IDE", base_url: IDE, environment: "production" },
    { id: "staging", display_name: "Vetfab Staging", base_url: "https://stg.vetfab.ai", environment: "staging" },
  ],
};

function mount(overrides: { services?: () => Response; handoff?: () => Promise<Response> | Response } = {}) {
  const ctx = setup();
  const handoff = createHandoffClient(ctx.client);
  ctx.browser.fetchMock.mockImplementation(async (input: unknown) =>
    String(input).endsWith("/auth/services")
      ? (overrides.services ?? (() => json(LISTING)))()
      : (overrides.handoff ?? (() => json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem` })))(),
  );
  const view = render(<VetfabServiceSwitcher handoff={handoff} currentService="lms" returnTo="/workspace" />);
  return { ...ctx, handoff, view };
}

async function openMenu() {
  const button = await screen.findByRole("button", { name: "Vetfab services" });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
  return button;
}

describe("VetfabServiceSwitcher", () => {
  it("lists the other services, with the environment of non-production ones, and not the current one", async () => {
    mount();
    await openMenu();
    const items = screen.getAllByRole("menuitem").map((el) => el.textContent);
    expect(items).toEqual(["Vetfab IDE", "Vetfab Staging (staging)"]);
  });

  it("starts a hand-off to the chosen service with the safe return path", async () => {
    const { browser } = mount();
    await openMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: "Vetfab IDE" }));
    await waitFor(() => expect(browser.posted).toEqual([`${IDE}/handoff/redeem`]));
    expect(browser.postedFields).toEqual([{ ticket: TICKET }]);
    const call = browser.fetchMock.mock.calls.find(([url]) => String(url).endsWith("/auth/handoff")) as [string, RequestInit];
    expect(JSON.parse(String(call[1].body))).toEqual({ target: "ide", return_to: "/workspace" });
    await waitFor(() => expect(screen.getByRole("status").textContent).toBe("Signing you in…"));
  });

  it("shows a loading state while the transition is under way and ignores repeated clicks", async () => {
    let release: (response: Response) => void = () => {};
    const { browser } = mount({ handoff: () => new Promise<Response>((resolve) => (release = resolve)) });
    const button = await openMenu();
    const entry = screen.getByRole("menuitem", { name: "Vetfab IDE" });
    fireEvent.click(entry);
    fireEvent.click(entry);
    fireEvent.click(entry);
    await waitFor(() => expect(button.getAttribute("aria-busy")).toBe("true"));
    expect(button.textContent).toBe("Opening Vetfab IDE…");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    release(json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem` }));
    await waitFor(() => expect(browser.posted).toHaveLength(1));
    expect(browser.fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/auth/handoff"))).toHaveLength(1);
  });

  it.each([
    [403, "That service is not available to you."],
    [401, "Your session has ended. Please sign in again."],
    [429, "Too many requests. Wait a minute and try again."],
  ])("explains a %s and lets the person try again", async (status, text) => {
    const { browser } = mount({ handoff: () => json({ error: "x" }, status) });
    await openMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: "Vetfab IDE" }));
    expect((await screen.findByRole("alert")).textContent).toContain(text);
    expect(browser.posted).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect((screen.getByRole("button", { name: "Vetfab services" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("explains when the list cannot be loaded", async () => {
    mount({ services: () => json({}, 401) });
    expect((await screen.findByRole("alert")).textContent).toContain("Your session has ended");
    expect((screen.getByRole("button", { name: "Vetfab services" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("offers nothing when there is nowhere to go", async () => {
    mount({ services: () => json({ current: "lms", services: [LISTING.services[0]] }) });
    const button = await screen.findByRole("button", { name: "Vetfab services" });
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(true));
  });

  it("works from the keyboard", async () => {
    mount();
    const button = await screen.findByRole("button", { name: "Vetfab services" });
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    fireEvent.keyDown(button, { key: "ArrowDown" });
    const first = await screen.findByRole("menuitem", { name: "Vetfab IDE" });
    await waitFor(() => expect(document.activeElement).toBe(first));
    fireEvent.keyDown(first, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("menuitem", { name: /Staging/ })));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowDown" }); // wraps
    await waitFor(() => expect(document.activeElement).toBe(first));
    fireEvent.keyDown(first, { key: "End" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("menuitem", { name: /Staging/ })));
    fireEvent.keyDown(document.activeElement as Element, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
    expect(document.activeElement).toBe(button);
  });

  it("exposes menu semantics to assistive technology", async () => {
    mount();
    const button = await openMenu();
    expect(button.getAttribute("aria-haspopup")).toBe("menu");
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("menu").id).toBe(button.getAttribute("aria-controls"));
  });

  it("reports where it is going before leaving", async () => {
    const ctx = setup();
    const handoff = createHandoffClient(ctx.client);
    ctx.browser.fetchMock.mockImplementation(async (input: unknown) =>
      String(input).endsWith("/auth/services") ? json(LISTING) : json({ ticket: TICKET, redeem_url: `${IDE}/handoff/redeem` }),
    );
    const onNavigate = vi.fn();
    render(<VetfabServiceSwitcher handoff={handoff} currentService="lms" onNavigate={onNavigate} />);
    await openMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: "Vetfab IDE" }));
    expect(onNavigate).toHaveBeenCalledWith(expect.objectContaining({ id: "ide" }));
  });
});
