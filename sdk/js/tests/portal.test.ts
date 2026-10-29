import { fireEvent, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PortalApiError, createApi, describeError, mountPortal } from "../../../identity/web/static/developer/portal.js";

type Json = Record<string, unknown>;
type Handler = (body: Json | undefined, url: URL) => Response | Promise<Response>;

const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const failure = (error: string, status: number, extra: Json = {}) => reply({ error, ...extra }, status);

const perms = (overrides: Json = {}) => ({ edit: true, edit_trusted: false, enable: false, disable: true, rotate_secret: true, validate: true, ...overrides });
const service = (overrides: Json = {}): Json => ({
  id: "newsvc", display_name: "New Service", description: "Hypothetical", owner_team: "Platform", owner: "dev@vetfab.test",
  environment: "staging", base_url: "https://newsvc.vetfab.ai", callback_path: "/handoff/redeem", redeem_url: "https://newsvc.vetfab.ai/handoff/redeem",
  roles: [], return_path_prefixes: [], session_seconds: 900, status: "pending", source: "managed", previous_secret_valid_until: null,
  created_at: "2026-10-27T10:00:00+00:00", updated_at: "2026-10-27T11:00:00+00:00", permissions: perms(), ...overrides,
});
const listing = (items: Json[], extra: Json = {}) => ({ items, total: items.length, page: 1, page_size: 10, counts: { pending: 1, active: 2, disabled: 0 }, ...extra });
const ME_ADMIN = { user: { id: "1", email: "admin@vetfab.test", name: "Admin" }, is_admin: true, register_environments: ["local", "staging", "production"], limits: { ticket_seconds: 60, rotation_grace_seconds: 3600 }, auth_url: "https://auth.vetfab.ai", deployed: true };
const ME_DEV = { ...ME_ADMIN, user: { id: "2", email: "dev@vetfab.test", name: "Dev" }, is_admin: false, register_environments: ["staging"] };
const CONFIG = {
  service: { id: "newsvc", environment: "staging", base_url: "https://newsvc.vetfab.ai", status: "pending" },
  variables: [
    { key: "VETFAB_AUTH_URL", value: "https://auth.vetfab.ai", origin: "portal", note: "n" },
    { key: "VETFAB_SERVICE_SECRET", value: null, origin: "secret", placeholder: "<shown once>", note: "n" },
    { key: "VETFAB_SESSION_SECRET", value: null, origin: "generate", placeholder: "<generate: openssl rand -base64 48>", note: "n" },
    { key: "VETFAB_CLIENT_ID", value: "newsvc", origin: "portal", optional: true, note: "n" },
  ],
  backend: { package: "vetfab-identity-adapter", install: "pip install ./sdk/python[fastapi]", code: "app.include_router(handoff_router(...))" },
  frontend: { package: "@vetfab/identity-adapter", install: "npm ci && npm run build", code: "createHandoffClient(client)" },
  local_test: [{ step: "Validate the configuration loads", command: "python -c 'print(1)'" }],
  readiness: [
    { id: "registered", label: "Registered", state: "done" },
    { id: "approved", label: "Approved and activated by an administrator", state: "todo" },
    { id: "browser", label: "Verified in a real browser", state: "manual" },
  ],
  production_ready: false,
};

interface Call { method: string; path: string; body: Json | undefined }

function setup(routes: Record<string, Handler>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost:3000");
    const method = init?.method ?? "GET";
    const path = url.pathname.replace("/auth/admin", "") + (url.search ? "" : "");
    const body = init?.body ? (JSON.parse(String(init.body)) as Json) : undefined;
    calls.push({ method, path, body });
    expect(init?.credentials).toBe("same-origin");
    const handler = routes[`${method} ${path}`];
    if (!handler) return reply({ error: "not_found" }, 404);
    return handler(body, url);
  }) as unknown as typeof fetch;
  const writeText = vi.fn().mockResolvedValue(undefined);
  const assign = vi.fn();
  const location = {
    get origin() { return window.location.origin; },
    get hash() { return window.location.hash; },
    set hash(value: string) { window.location.hash = value; },
    assign,
  };
  const root = document.createElement("div");
  document.body.append(root);
  const started = mountPortal(root, { fetch: fetchMock, location, history, navigator: { clipboard: { writeText } }, storage: sessionStorage });
  return { root, calls, writeText, assign, started };
}

const view = (root: HTMLElement) => within(root);
const isOpen = (root: HTMLElement) => root.querySelector("main[aria-busy]") === null;

beforeEach(() => {
  window.location.hash = "";
});
afterEach(() => {
  document.body.replaceChildren();
});

describe("signing in and access", () => {
  it("sends a signed-out visitor to the identity service's sign-in and nothing else", async () => {
    const { root, assign, started } = setup({ "GET /me": () => failure("not_signed_in", 401) });
    await started;
    fireEvent.click(view(root).getByRole("button", { name: /Sign in with your Vetfab account/ }));
    const url = new URL(String(assign.mock.calls[0]?.[0]), "http://localhost:3000");
    expect(url.pathname).toBe("/auth/login");
    expect(url.searchParams.get("redirect")).toBe("http://localhost:3000/developer/services");
    expect(url.searchParams.get("state")).toMatch(/^[0-9a-f]{32}$/);
  });

  it("tells an account without access to ask an administrator", async () => {
    const { root, started } = setup({ "GET /me": () => failure("not_authorised", 403) });
    await started;
    expect(view(root).getByRole("alert").textContent).toContain("not set up");
    expect(view(root).queryByRole("link", { name: "Services" })).toBeNull();
  });

  it("shows an error with a retry when the identity service cannot be reached", async () => {
    let up = false;
    const { root, started } = setup({ "GET /me": () => (up ? reply(ME_ADMIN) : Promise.reject(new TypeError("offline"))), "GET /services": () => reply(listing([])) });
    await started;
    expect(view(root).getByRole("alert").textContent).toContain("could not be reached");
    up = true;
    fireEvent.click(view(root).getByRole("button", { name: "Try again" }));
    await view(root).findByRole("heading", { name: "Services" });
  });

  it("offers navigation by role: developers do not see the Developers page", async () => {
    const admin = setup({ "GET /me": () => reply(ME_ADMIN), "GET /services": () => reply(listing([])) });
    await admin.started;
    expect(view(admin.root).getByRole("link", { name: "Developers" })).toBeTruthy();
    expect(view(admin.root).getAllByRole("link", { name: "Register a service" }).length).toBeGreaterThan(0);
    document.body.replaceChildren();
    const dev = setup({ "GET /me": () => reply(ME_DEV), "GET /services": () => reply(listing([])) });
    await dev.started;
    expect(view(dev.root).queryByRole("link", { name: "Developers" })).toBeNull();
    expect(view(dev.root).getAllByRole("link", { name: "Register a service" }).length).toBeGreaterThan(0);
  });

  it("gives every signed-in person a Sign out that posts to the identity logout and returns to the portal", async () => {
    for (const me of [ME_ADMIN, ME_DEV]) {
      document.body.replaceChildren();
      const { root, started } = setup({ "GET /me": () => reply(me), "GET /services": () => reply(listing([])) });
      await started;
      const button = view(root).getByRole("button", { name: "Sign out" });
      const form = button.closest("form")!;
      expect(form.method).toBe("post");
      const action = new URL(form.getAttribute("action")!, "https://auth.example");
      expect(action.pathname).toBe("/auth/logout");
      expect(new URL(action.searchParams.get("redirect")!).pathname).toBe("/developer/services");
    }
  });
});

describe("dashboard", () => {
  it("lists services with environment, address, status, owner and timestamps", async () => {
    const items = [service(), service({ id: "lms", display_name: "Vetfab LMS", status: "active", environment: "production", base_url: "https://lms.vetfab.ai", source: "bootstrap", owner: null, owner_team: "" })];
    const { root, started } = setup({ "GET /me": () => reply(ME_ADMIN), "GET /services": () => reply(listing(items)) });
    await started;
    const table = await view(root).findByRole("table", { name: "Registered services" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).getByRole("link", { name: "New Service" }).getAttribute("href")).toBe("#/s/newsvc");
    expect(rows[1]!.textContent).toContain("Pending approval");
    expect(rows[1]!.textContent).toContain("Staging");
    expect(rows[1]!.textContent).toContain("2026-10-27 11:00 UTC");
    expect(rows[2]!.textContent).toContain("(from configuration)");
    expect(view(root).getByText(/2 active, 1 pending approval, 0 disabled/)).toBeTruthy();
  });

  it("shows a loading state and then an empty state with a way forward", async () => {
    let release: (r: Response) => void = () => {};
    const { root, started } = setup({ "GET /me": () => reply(ME_DEV), "GET /services": () => new Promise<Response>((resolve) => (release = resolve)) });
    expect(await view(root).findByText("Loading services…")).toBeTruthy();
    expect(root.querySelector("main")?.getAttribute("aria-busy")).toBe("true");
    release(reply(listing([])));
    await started;
    expect(await view(root).findByText(/You have not registered any services yet/)).toBeTruthy();
    const empty = root.querySelector(".empty") as HTMLElement;
    expect(within(empty).getByRole("link", { name: "Register a service" }).getAttribute("href")).toBe("#/new");
  });

  it("shows a backend failure and retries", async () => {
    let fail = true;
    const { root, started } = setup({ "GET /me": () => reply(ME_ADMIN), "GET /services": () => (fail ? failure("too_many_requests", 429) : reply(listing([service()]))) });
    await started;
    expect((await view(root).findByRole("alert")).textContent).toContain("Too many requests");
    fail = false;
    fireEvent.click(view(root).getByRole("button", { name: "Try again" }));
    expect(await view(root).findByRole("link", { name: "New Service" })).toBeTruthy();
  });

  it("filters, searches and pages through the backend", async () => {
    const { root, calls, started } = setup({
      "GET /me": () => reply(ME_ADMIN),
      "GET /services": (_b, url) => reply(listing([service()], { total: 25, page: Number(url.searchParams.get("page")), page_size: 10 })),
    });
    await started;
    await view(root).findByRole("table");
    fireEvent.input(view(root).getByLabelText("Search"), { target: { value: "new" } });
    fireEvent.change(view(root).getByLabelText("Status"), { target: { value: "pending" } });
    fireEvent.click(view(root).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(calls.at(-1)?.path).toBe("/services"));
    const last = () => calls.filter((c) => c.path === "/services").length;
    await waitFor(() => expect(last()).toBeGreaterThan(1));
    fireEvent.click(await view(root).findByRole("button", { name: "Next" }));
    await view(root).findByText(/Page 2 of 3/);
    expect((view(root).getByRole("button", { name: "Previous" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("renders text, never markup, from a service's own fields", async () => {
    const hostile = service({ display_name: '<img src=x onerror="alert(1)">', owner_team: "<script>alert(1)</script>" });
    const { root, started } = setup({ "GET /me": () => reply(ME_ADMIN), "GET /services": () => reply(listing([hostile])) });
    await started;
    await view(root).findByRole("table");
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
    expect(root.textContent).toContain('<img src=x onerror="alert(1)">');
  });
});

describe("registering a service", () => {
  const fill = (root: HTMLElement, values: Record<string, string>) => {
    for (const [label, value] of Object.entries(values)) fireEvent.input(view(root).getByLabelText(label), { target: { value } });
  };

  it("validates in the page before asking the server, and points at the problem", async () => {
    window.location.hash = "#/new";
    const { root, calls, started } = setup({ "GET /me": () => reply(ME_ADMIN) });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fill(root, { "Display name": "", Identifier: "Bad Id", "Base URL": "https://x.example/path", "Session length in seconds": "5" });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    expect(view(root).getByText(/Enter a name/)).toBeTruthy();
    expect(view(root).getByText(/lowercase letters/)).toBeTruthy();
    expect(view(root).getByText(/origin only/)).toBeTruthy();
    expect(view(root).getByText(/from 60 to 3600/)).toBeTruthy();
    expect(view(root).getByLabelText("Identifier").getAttribute("aria-invalid")).toBe("true");
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("insists on https for production and fills the identifier from the name", async () => {
    window.location.hash = "#/new";
    const { root, started } = setup({ "GET /me": () => reply(ME_ADMIN) });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fill(root, { "Display name": "My Cool Service!", "Base URL": "http://svc.example" });
    expect((view(root).getByLabelText("Identifier") as HTMLInputElement).value).toBe("my-cool-service");
    fireEvent.change(view(root).getByLabelText("Environment"), { target: { value: "production" } });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    expect(view(root).getByText(/must use https/)).toBeTruthy();
  });

  it("offers a developer only the environments they were granted", async () => {
    window.location.hash = "#/new";
    const { root, started } = setup({ "GET /me": () => reply(ME_DEV) });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    const options = [...(view(root).getByLabelText("Environment") as HTMLSelectElement).options].map((o) => o.textContent);
    expect(options).toEqual(["Staging"]);
  });

  it("reviews, checks, registers, and shows the secret exactly once", async () => {
    window.location.hash = "#/new";
    const created = service();
    const { root, calls, writeText, started } = setup({
      "GET /me": () => reply(ME_ADMIN),
      "POST /services/validate": () => reply({ ok: true, checks: [{ code: "fields", level: "ok", message: "Well-formed." }, { code: "protocol", level: "info", message: "Tickets are posted to the address." }] }),
      "POST /services": () => reply({ service: created, secret: "S3CRET-VALUE-shown-once-0123456789abcdef", secret_shown_once: true, checks: [] }, 201),
      "GET /services/newsvc": () => reply({ service: created }),
      "GET /services/newsvc/activity": () => reply({ events: [] }),
    });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fill(root, { "Display name": "New Service", Identifier: "newsvc", "Base URL": "https://newsvc.vetfab.ai" });
    fireEvent.change(view(root).getByLabelText("Environment"), { target: { value: "staging" } });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    await view(root).findByRole("heading", { name: "Review" });
    await view(root).findByText(/Passed:/);
    expect(view(root).getAllByText("newsvc").length).toBeGreaterThan(0);
    fireEvent.click(view(root).getByRole("button", { name: "Register service" }));
    const panel = await view(root).findByRole("alert", { name: "Service secret" });
    expect(panel.textContent).toContain("S3CRET-VALUE-shown-once-0123456789abcdef");
    expect(panel.textContent).toContain("shown only once and cannot be retrieved again");
    expect(calls.find((c) => c.method === "POST" && c.path === "/services")?.body).toMatchObject({ id: "newsvc", environment: "staging", base_url: "https://newsvc.vetfab.ai", roles: [] });
    expect(calls.find((c) => c.path === "/services")?.body).not.toHaveProperty("owner");

    fireEvent.click(within(panel).getByRole("button", { name: "Copy secret" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("S3CRET-VALUE-shown-once-0123456789abcdef"));

    fireEvent.click(within(panel).getByRole("button", { name: "I have saved it" }));
    await waitFor(() => expect(root.textContent).not.toContain("S3CRET-VALUE"));
    expect(window.location.href).not.toContain("S3CRET");
    expect(JSON.stringify({ ...sessionStorage, ...localStorage })).not.toContain("S3CRET");
  });

  it("will not register a configuration the server rejects, and says why", async () => {
    window.location.hash = "#/new";
    const { root, started } = setup({
      "GET /me": () => reply(ME_ADMIN),
      "POST /services/validate": () => reply({ ok: false, checks: [{ code: "origin_taken", level: "error", message: "That address is already registered to another service." }] }),
    });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fill(root, { "Display name": "New Service", "Base URL": "https://newsvc.vetfab.ai" });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    await view(root).findByText(/already registered to another service/);
    expect((view(root).getByRole("button", { name: "Register service" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the server's rejection at submit time", async () => {
    window.location.hash = "#/new";
    const { root, started } = setup({
      "GET /me": () => reply(ME_ADMIN),
      "POST /services/validate": () => reply({ ok: true, checks: [] }),
      "POST /services": () => failure("origin_taken", 409),
    });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fill(root, { "Display name": "New Service", "Base URL": "https://newsvc.vetfab.ai" });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    await view(root).findByRole("heading", { name: "Review" });
    await waitFor(() => expect((view(root).getByRole("button", { name: "Register service" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(view(root).getByRole("button", { name: "Register service" }));
    expect((await view(root).findByRole("alert")).textContent).toContain("already registered to another service");
  });
});

describe("one service", () => {
  const detailRoutes = (svc: Json, extra: Record<string, Handler> = {}) => ({
    "GET /me": () => reply(ME_ADMIN),
    "GET /services/newsvc": () => reply({ service: svc }),
    "GET /services/newsvc/activity": () => reply({ events: [{ at: "2026-10-27T10:00:00+00:00", action: "service_created", actor: "admin@vetfab.test", details: {} }] }),
    ...extra,
  });

  it("shows only the actions the server says this person may take", async () => {
    window.location.hash = "#/s/newsvc";
    const dev = setup({ ...detailRoutes(service({ permissions: perms({ enable: false }) })), "GET /me": () => reply(ME_DEV) });
    await dev.started;
    await view(dev.root).findByRole("heading", { name: /New Service/ });
    expect(view(dev.root).getByRole("button", { name: "Disable" })).toBeTruthy();
    expect(view(dev.root).queryByRole("button", { name: "Activate" })).toBeNull();
    document.body.replaceChildren();
    const admin = setup(detailRoutes(service({ permissions: perms({ enable: true }) })));
    await admin.started;
    await view(admin.root).findByRole("button", { name: "Activate" });
    document.body.replaceChildren();
    const readOnly = setup(detailRoutes(service({ permissions: perms({ edit: false, disable: false, rotate_secret: false, validate: false }) })));
    await readOnly.started;
    await view(readOnly.root).findByRole("heading", { name: /New Service/ });
    for (const name of ["Edit", "Disable", "Rotate secret", "Check configuration", "Activate"]) expect(view(readOnly.root).queryByRole("button", { name })).toBeNull();
    expect(view(readOnly.root).getByRole("link", { name: "Integration guide" })).toBeTruthy();
  });

  it("explains the consequences and needs confirmation before disabling", async () => {
    window.location.hash = "#/s/newsvc";
    const disable = vi.fn(() => reply({ service: service({ status: "disabled" }), tickets_spent: 1 }));
    const { root, calls, started } = setup(detailRoutes(service({ status: "active" }), { "POST /services/newsvc/disable": disable }));
    await started;
    const opener = await view(root).findByRole("button", { name: "Disable" });
    opener.focus();
    fireEvent.click(opener);
    const dialog = await view(root).findByRole("dialog");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.textContent).toContain("New hand-offs to and from this service stop immediately");
    expect(dialog.textContent).toContain("accounts and the service's own data are not changed");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(view(root).queryByRole("dialog")).toBeNull());
    expect(disable).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(opener);
    fireEvent.click(opener);
    fireEvent.click(within(await view(root).findByRole("dialog")).getByRole("button", { name: "Disable service" }));
    await waitFor(() => expect(disable).toHaveBeenCalledOnce());
    expect(calls.find((c) => c.path === "/services/newsvc/disable")?.body).toEqual({});
  });

  it("makes a production service's id be typed to disable it", async () => {
    window.location.hash = "#/s/newsvc";
    const disable = vi.fn(() => reply({ service: service({ status: "disabled" }), tickets_spent: 0 }));
    const { root, calls, started } = setup(detailRoutes(service({ status: "active", environment: "production" }), { "POST /services/newsvc/disable": disable }));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Disable" }));
    const dialog = await view(root).findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Disable service" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    const typed = within(dialog).getByLabelText(/Type/);
    fireEvent.input(typed, { target: { value: "newsv" } });
    expect(confirm.disabled).toBe(true);
    fireEvent.input(typed, { target: { value: "newsvc" } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(disable).toHaveBeenCalled());
    expect(calls.find((c) => c.path === "/services/newsvc/disable")?.body).toEqual({ confirm: "newsvc" });
  });

  it("rotates a secret only after the id is typed, can revoke the old one, and shows the new secret once", async () => {
    window.location.hash = "#/s/newsvc";
    const rotate = vi.fn((body?: Json) => reply({ service: service(), secret: "NEW-SECRET-0123456789-0123456789-0123456789", secret_shown_once: true, previous_valid_seconds: body?.revoke_old ? 0 : 3600 }));
    const { root, calls, started } = setup(detailRoutes(service(), { "POST /services/newsvc/rotate-secret": rotate }));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Rotate secret" }));
    const dialog = await view(root).findByRole("dialog");
    expect(dialog.textContent).toContain("60 minutes");
    const confirm = within(dialog).getByRole("button", { name: "Rotate secret" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(within(dialog).getByLabelText(/Revoke the old secret immediately/));
    fireEvent.input(within(dialog).getByLabelText(/Type/), { target: { value: "newsvc" } });
    fireEvent.click(confirm);
    const panel = await view(root).findByRole("alert", { name: "Service secret" });
    expect(panel.textContent).toContain("NEW-SECRET-0123456789");
    expect(calls.find((c) => c.path === "/services/newsvc/rotate-secret")?.body).toEqual({ confirm: "newsvc", revoke_old: true });
  });

  it("does nothing when a dialog is cancelled", async () => {
    window.location.hash = "#/s/newsvc";
    const rotate = vi.fn();
    const { root, started } = setup(detailRoutes(service(), { "POST /services/newsvc/rotate-secret": rotate as unknown as Handler }));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Rotate secret" }));
    fireEvent.click(within(await view(root).findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(view(root).queryByRole("dialog")).toBeNull());
    expect(rotate).not.toHaveBeenCalled();
    expect(root.querySelector(".secret-panel")).toBeNull();
  });

  it("shows a backend refusal where the action was taken", async () => {
    window.location.hash = "#/s/newsvc";
    const { root, started } = setup(detailRoutes(service({ permissions: perms({ enable: true }) }), { "POST /services/newsvc/enable": () => failure("administrator_only", 403) }));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Activate" }));
    fireEvent.click(within(await view(root).findByRole("dialog")).getByRole("button", { name: "Activate" }));
    expect((await view(root).findByRole("alert")).textContent).toContain("Only an administrator");
  });

  it("shows a configuration check's results", async () => {
    window.location.hash = "#/s/newsvc";
    const { root, started } = setup(detailRoutes(service(), { "POST /services/newsvc/validate": () => reply({ ok: false, checks: [{ code: "https", level: "error", message: "Production address must use https." }] }) }));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Check configuration" }));
    expect(await view(root).findByText(/must use https/)).toBeTruthy();
    expect(view(root).getByText("Problem:")).toBeTruthy(); // level is words, not only colour
  });

  it("keeps keyboard focus inside a dialog", async () => {
    window.location.hash = "#/s/newsvc";
    const { root, started } = setup(detailRoutes(service()));
    await started;
    fireEvent.click(await view(root).findByRole("button", { name: "Rotate secret" }));
    const dialog = await view(root).findByRole("dialog");
    const typed = within(dialog).getByLabelText(/Type/) as HTMLInputElement;
    await waitFor(() => expect(document.activeElement).toBe(typed)); // the box to type the id in takes focus first
    const checkbox = within(dialog).getByLabelText(/Revoke the old/);
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });
    cancel.focus();
    fireEvent.keyDown(cancel, { key: "Tab" }); // the confirm button is disabled, so Cancel is the last stop: wrap
    expect(document.activeElement).toBe(checkbox);
    fireEvent.keyDown(checkbox, { key: "Tab", shiftKey: true }); // and back
    expect(document.activeElement).toBe(cancel);
    fireEvent.keyDown(cancel, { key: "Escape" });
    await waitFor(() => expect(view(root).queryByRole("dialog")).toBeNull());
  });

  it("explains a service that does not exist or is not theirs the same way", async () => {
    window.location.hash = "#/s/other";
    const { root, started } = setup({ "GET /me": () => reply(ME_DEV), "GET /services/other": () => failure("not_found", 404) });
    await started;
    expect((await view(root).findByRole("alert")).textContent).toContain("not found, or you do not have access");
  });
});

describe("integration guide", () => {
  const routes = (): Record<string, Handler> => ({
    "GET /me": () => reply(ME_ADMIN),
    "GET /services/newsvc/integration-config": () => reply(CONFIG),
  });

  it("walks through the five steps with the real configuration, forward and back", async () => {
    window.location.hash = "#/s/newsvc/integration/1";
    const { root, started } = setup(routes());
    await started;
    await view(root).findByRole("heading", { name: "A. Registration summary" });
    expect(root.textContent).toContain("https://newsvc.vetfab.ai");
    expect(view(root).getByRole("link", { name: /A\. Registration summary/ }).getAttribute("aria-current")).toBe("step");
    expect((view(root).getByRole("button", { name: "Back" }) as HTMLButtonElement).disabled).toBe(true);
    for (const [index, heading] of [[2, "B. Environment variables"], [3, "C. Installation"], [4, "D. Local testing"], [5, "E. Production readiness"]] as const) {
      fireEvent.click(view(root).getByRole("button", { name: "Next" }));
      await waitFor(() => expect(window.location.hash).toBe(`#/s/newsvc/integration/${index}`));
      await view(root).findByRole("heading", { name: heading });
    }
    expect((view(root).getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
    expect(view(root).getByText(/does not make it production-ready/)).toBeTruthy();
    expect(view(root).getByText("Confirm yourself")).toBeTruthy();
    fireEvent.click(view(root).getByRole("button", { name: "Back" }));
    await view(root).findByRole("heading", { name: "D. Local testing" });
  });

  it("separates values from the portal, one-time secrets and values the developer generates; no secret remains", async () => {
    window.location.hash = "#/s/newsvc/integration/2";
    const { root, writeText, started } = setup(routes());
    await started;
    await view(root).findByRole("heading", { name: "B. Environment variables" });
    expect(view(root).getAllByText("From the portal").length).toBe(2);
    expect(view(root).getByText("One-time secret")).toBeTruthy();
    expect(view(root).getByText("You generate it")).toBeTruthy();
    expect(view(root).getByText(/not shown again/)).toBeTruthy();
    fireEvent.click(within(root.querySelector(".code") as HTMLElement).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const copied = String(writeText.mock.calls[0]?.[0]);
    expect(copied).toContain("VETFAB_AUTH_URL=https://auth.vetfab.ai");
    expect(copied).toContain("VETFAB_SERVICE_SECRET=<shown once>");
    expect(copied).toContain("VETFAB_SESSION_SECRET=<generate: openssl rand -base64 48>");
  });

  it("lists the real package names and the local test commands", async () => {
    window.location.hash = "#/s/newsvc/integration/3";
    const { root, started } = setup(routes());
    await started;
    await view(root).findByRole("heading", { name: "C. Installation" });
    expect(root.textContent).toContain("pip install ./sdk/python[fastapi]");
    expect(root.textContent).toContain("createHandoffClient(client)");
    expect(root.textContent).toContain("load_user");
    window.location.hash = "#/s/newsvc/integration/4";
    await view(root).findByRole("heading", { name: "D. Local testing" });
    expect(root.textContent).toContain("python -c 'print(1)'");
  });

  it("shows the registration's one-time secret in the template only while it is held in memory", async () => {
    window.location.hash = "#/new";
    const created = service();
    const { root, writeText, started } = setup({
      ...routes(),
      "POST /services/validate": () => reply({ ok: true, checks: [] }),
      "POST /services": () => reply({ service: created, secret: "ONE-TIME-0123456789-0123456789-0123456789", secret_shown_once: true, checks: [] }, 201),
      "GET /services/newsvc": () => reply({ service: created }),
      "GET /services/newsvc/activity": () => reply({ events: [] }),
    });
    await started;
    await view(root).findByRole("heading", { name: "Register a service" });
    fireEvent.input(view(root).getByLabelText("Display name"), { target: { value: "New Service" } });
    fireEvent.input(view(root).getByLabelText("Identifier"), { target: { value: "newsvc" } });
    fireEvent.input(view(root).getByLabelText("Base URL"), { target: { value: "https://newsvc.vetfab.ai" } });
    fireEvent.click(view(root).getByRole("button", { name: "Review" }));
    await view(root).findByRole("heading", { name: "Review" });
    await waitFor(() => expect((view(root).getByRole("button", { name: "Register service" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(view(root).getByRole("button", { name: "Register service" }));
    await view(root).findByRole("alert", { name: "Service secret" });
    window.location.hash = "#/s/newsvc/integration/2";
    await view(root).findByRole("heading", { name: "B. Environment variables" });
    expect(view(root).getByText(/includes the secret you just generated/)).toBeTruthy();
    fireEvent.click(within(root.querySelector(".code") as HTMLElement).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    expect(String(writeText.mock.calls[0]?.[0])).toContain("VETFAB_SERVICE_SECRET=ONE-TIME-0123456789");
  });
});

describe("developers (administrators)", () => {
  it("lists, grants and removes developer access with a confirmation", async () => {
    window.location.hash = "#/developers";
    let developers = [{ user_id: "u1", email: "dev@vetfab.test", environments: ["staging"] }];
    const put = vi.fn((body?: Json) => { developers = [...developers, { user_id: "u2", email: String(body?.email), environments: body?.environments as string[] }]; return reply({}); });
    const del = vi.fn(() => { developers = []; return reply({ revoked: true }); });
    const { root, calls, started } = setup({ "GET /me": () => reply(ME_ADMIN), "GET /developers": () => reply({ developers }), "PUT /developers": put as Handler, "DELETE /developers/u1": del });
    await started;
    await view(root).findByRole("cell", { name: "Staging" });
    fireEvent.input(view(root).getByLabelText(/Email address/), { target: { value: "new@vetfab.test" } });
    fireEvent.click(view(root).getByLabelText("Staging"));
    fireEvent.click(view(root).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ email: "new@vetfab.test", environments: ["local", "staging"] });
    fireEvent.click((await view(root).findAllByRole("button", { name: "Remove" }))[0]!);
    fireEvent.click(within(await view(root).findByRole("dialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(del).toHaveBeenCalled());
  });

  it("is closed to developers", async () => {
    window.location.hash = "#/developers";
    const { root, calls, started } = setup({ "GET /me": () => reply(ME_DEV) });
    await started;
    expect((await view(root).findByRole("alert")).textContent).toContain("Only an administrator");
    expect(calls.some((c) => c.path === "/developers")).toBe(false);
  });
});

describe("api helpers", () => {
  it("maps server errors to plain language and never echoes unknown detail", () => {
    expect(describeError(new PortalApiError(403, "trusted_fields_locked"))).toContain("administrator");
    expect(describeError(new PortalApiError(422, "validation_failed", { checks: [{ level: "error", message: "Bad address." }, { level: "ok", message: "Fine." }] }))).toBe("The configuration was rejected: Bad address.");
    expect(describeError(new PortalApiError(500, "weird"))).toBe("Something went wrong (weird).");
    expect(describeError(new Error("boom"))).toBe("Something went wrong. Try again.");
  });

  it("sends same-origin credentials and JSON, and turns a failed request into an error", async () => {
    const fetchMock = vi.fn().mockResolvedValue(reply({ error: "csrf" }, 403));
    const api = createApi(fetchMock as unknown as typeof fetch);
    await expect(api.post("/services", { id: "x" })).rejects.toMatchObject({ status: 403, code: "csrf" });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/auth/admin/services");
    expect(init).toMatchObject({ method: "POST", credentials: "same-origin", body: '{"id":"x"}' });
    await expect(createApi((() => Promise.reject(new TypeError("x"))) as unknown as typeof fetch).get("/me")).rejects.toMatchObject({ code: "network" });
    expect(isOpen(document.body)).toBe(true);
  });
});
