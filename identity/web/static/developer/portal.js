// The Vetfab developer portal: register, configure and manage services connected to the identity service.
//
// A convenience layer over /auth/admin/*. It decides nothing: which buttons exist comes from the `permissions` the
// server returns for each service, and the server re-checks every action. Elements are built from text nodes only
// (never innerHTML), so nothing a service's owner typed can become markup. The one-time secret lives only in memory
// and in the DOM until dismissed; it is never put in a URL, storage or a log.

const ENV_LABELS = { local: "Development", staging: "Staging", production: "Production" };
const STATUS_LABELS = { pending: "Pending approval", active: "Active", disabled: "Disabled" };
const LEVEL_LABELS = { ok: "Passed", info: "Note", warning: "Warning", error: "Problem" };
const ID_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;
const STEPS = ["Registration summary", "Environment variables", "Installation", "Local testing", "Production readiness"];

const ERROR_TEXT = {
  not_signed_in: "Your session has ended. Sign in again.",
  not_authorised: "Your account is not set up to use the developer portal.",
  administrator_only: "Only an administrator can do that.",
  csrf: "That request did not come from this page. Reload and try again.",
  too_many_requests: "Too many requests. Wait a few minutes and try again.",
  network: "The identity service could not be reached. Check your connection and try again.",
  not_found: "That service was not found, or you do not have access to it.",
  unknown_field: "The request included something this form does not allow.",
  trusted_fields_locked: "The address and environment of an approved service can only be changed by an administrator.",
  environment_not_permitted: "You cannot register services in that environment.",
  confirmation_required: "Type the service identifier to confirm.",
  id_taken: "That identifier is already registered.",
  origin_taken: "That address is already registered to another service.",
  already_active: "The service is already active.",
  already_disabled: "The service is already disabled.",
  user_not_found: "No active account has that email address.",
  content_type: "The request was not understood.",
  body: "The request was not understood.",
  no_changes: "There is nothing to change.",
};

export class PortalApiError extends Error {
  constructor(status, code, details = {}) {
    super(code);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function createApi(fetchImpl) {
  async function call(method, path, body) {
    const init = { method, credentials: "same-origin", headers: { accept: "application/json" } };
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetchImpl(`/auth/admin${path}`, init);
    } catch {
      throw new PortalApiError(0, "network");
    }
    let data = {};
    try {
      data = await response.json();
    } catch {
      // an empty or non-JSON body: the status still says what happened
    }
    if (!response.ok) throw new PortalApiError(response.status, data.error ?? "error", data);
    return data;
  }
  return {
    get: (path) => call("GET", path),
    post: (path, body = {}) => call("POST", path, body),
    patch: (path, body) => call("PATCH", path, body),
    put: (path, body) => call("PUT", path, body),
    del: (path) => call("DELETE", path),
  };
}

export function describeError(error) {
  if (!(error instanceof PortalApiError)) return "Something went wrong. Try again.";
  if (error.code === "validation_failed") {
    const problems = (error.details.checks ?? []).filter((c) => c.level === "error").map((c) => c.message);
    return problems.length ? `The configuration was rejected: ${problems.join(" ")}` : "The configuration was rejected.";
  }
  return ERROR_TEXT[error.code] ?? `Something went wrong (${error.code}).`;
}

// ---------------------------------------------------------------------------------------------- DOM helpers

function h(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (name.startsWith("on") && typeof value === "function") element.addEventListener(name.slice(2), value);
    else if (name === "class") element.className = value;
    else if (name === "for") element.htmlFor = value;
    else if (name === "value" || name === "checked" || name === "disabled" || name === "hidden") element[name] = value;
    else element.setAttribute(name, value === true ? "" : String(value));
  }
  append(element, children);
  return element;
}

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

const put = (parent, ...children) => append(parent, children);
const clear = (element) => element.replaceChildren();


/**
 * Moves focus to the page heading after a view renders (so a screen-reader user hears where they are), unless focus is
 * already on content the person reached in the new view, or inside an open dialog.
 */
function focusHeading(main) {
  const active = document.activeElement;
  if (active && active !== main && (main.contains(active) || active.closest?.(".dialogs"))) return;
  main.querySelector("h1")?.focus?.();
}

function badge(kind, text) {
  return h("span", { class: `badge badge-${kind}` }, text);
}

function checkList(checks) {
  return h(
    "ul",
    { class: "checks" },
    checks.map((c) => h("li", { class: `check check-${c.level}` }, h("strong", {}, `${LEVEL_LABELS[c.level]}: `), c.message)),
  );
}

function when(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

// ---------------------------------------------------------------------------------------------- the app

export function mountPortal(root, env) {
  const api = createApi(env.fetch);
  const win = root.ownerDocument.defaultView;
  const state = { me: null, secret: null, draft: null, list: { q: "", status: "", environment: "", page: 1 } };
  let shell = null;
  let navigation = 0;
  let renderedHash = null;

  // ---- shell -----------------------------------------------------------------------------------

  function announce(text) {
    if (shell) shell.status.textContent = text;
  }

  function showError(container, error, retry) {
    container.append(
      h(
        "div",
        { class: "alert", role: "alert" },
        h("p", {}, describeError(error)),
        retry ? h("button", { type: "button", class: "btn", onclick: retry }, "Try again") : null,
      ),
    );
  }

  function buildShell() {
    const nav = h("nav", { "aria-label": "Developer portal" });
    const main = h("main", { id: "portal-main", tabindex: "-1" });
    const status = h("p", { class: "sr-only", role: "status", "aria-live": "polite" });
    const dialogs = h("div", { class: "dialogs" });
    const links = [["Services", "#/"]];
    if (state.me.register_environments.length) links.push(["Register a service", "#/new"]);
    if (state.me.is_admin) links.push(["Developers", "#/developers"]);
    nav.append(h("ul", {}, links.map(([label, href]) => h("li", {}, h("a", { href }, label)))));
    clear(root);
    put(root, 
      h(
        "header",
        { class: "top" },
        h("p", { class: "brand" }, "Vetfab ", h("span", {}, "Developer portal")),
        h("p", { class: "who" }, state.me.user.email, " ", badge(state.me.is_admin ? "admin" : "dev", state.me.is_admin ? "Administrator" : "Developer")),
      ),
      nav,
      main,
      status,
      dialogs,
    );
    shell = { nav, main, status, dialogs };
  }

  function signInScreen(text) {
    clear(root);
    const state_ = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
    const target = `${env.location.origin}/developer/services`;
    const url = `/auth/login?redirect=${encodeURIComponent(target)}&state=${state_}`;
    put(root, 
      h(
        "main",
        { id: "portal-main", class: "narrow" },
        h("p", { class: "brand" }, "Vetfab ", h("span", {}, "Developer portal")),
        h("h1", { tabindex: "-1" }, "Developer portal"),
        h("p", {}, text),
        h("button", { type: "button", class: "btn btn-primary", onclick: () => env.location.assign(url) }, "Sign in with your Vetfab account"),
      ),
    );
  }

  // ---- dialogs ---------------------------------------------------------------------------------

  /** A confirmation dialog. Resolves {confirmed, checked}, or null when cancelled. `expect` makes the person type it. */
  function confirmDialog({ title, body, expect = null, confirmLabel, danger = false, checkbox = null }) {
    return new Promise((resolve) => {
      const previous = document.activeElement;
      const titleId = `dlg-${Math.random().toString(36).slice(2)}`;
      const input = expect ? h("input", { type: "text", id: `${titleId}-in`, autocomplete: "off", spellcheck: "false" }) : null;
      const box = checkbox ? h("input", { type: "checkbox", id: `${titleId}-cb` }) : null;
      const confirm = h("button", { type: "button", class: `btn ${danger ? "btn-danger" : "btn-primary"}`, disabled: Boolean(expect) }, confirmLabel);
      const cancel = h("button", { type: "button", class: "btn" }, "Cancel");
      const dialog = h(
        "div",
        { class: "dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
        h("h2", { id: titleId }, title),
        h("div", { class: "dialog-body" }, body),
        box ? h("p", {}, box, " ", h("label", { for: `${titleId}-cb` }, checkbox)) : null,
        input ? h("p", {}, h("label", { for: `${titleId}-in` }, "Type ", h("code", {}, expect), " to confirm"), input) : null,
        h("p", { class: "actions" }, cancel, confirm),
      );
      const overlay = h("div", { class: "overlay" }, dialog);
      const done = (value) => {
        overlay.remove();
        previous?.focus?.();
        resolve(value);
      };
      input?.addEventListener("input", () => {
        confirm.disabled = input.value !== expect;
      });
      cancel.addEventListener("click", () => done(null));
      confirm.addEventListener("click", () => done({ confirmed: true, checked: Boolean(box?.checked), typed: input?.value ?? null }));
      dialog.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          done(null);
        } else if (event.key === "Tab") {
          const focusable = [...dialog.querySelectorAll("button, input")].filter((el) => !el.disabled);
          if (focusable.length === 0) return;
          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }
      });
      shell.dialogs.append(overlay);
      (input ?? box ?? cancel).focus();
    });
  }

  // ---- one-time secret -------------------------------------------------------------------------

  async function copyText(text, label) {
    try {
      await env.navigator.clipboard.writeText(text);
      announce(`${label} copied to the clipboard.`);
      return true;
    } catch {
      announce(`Could not copy automatically. Select the ${label.toLowerCase()} and copy it by hand.`);
      return false;
    }
  }

  function secretPanel(onDismiss) {
    const secret = state.secret.value;
    const code = h("code", { class: "secret", tabindex: "0" }, secret);
    return h(
      "section",
      { class: "secret-panel", role: "alert", "aria-label": "Service secret" },
      h("h2", {}, "Copy this secret now"),
      h("p", {}, h("strong", {}, "It is shown only once and cannot be retrieved again."), " Install it as ", h("code", {}, "VETFAB_SERVICE_SECRET"), " in the service's server-side secret store. Never put it in a frontend bundle or a repository."),
      code,
      h(
        "p",
        { class: "actions" },
        h("button", { type: "button", class: "btn btn-primary", onclick: () => copyText(secret, "Secret") }, "Copy secret"),
        h("button", { type: "button", class: "btn", onclick: onDismiss }, "I have saved it"),
      ),
    );
  }

  // ---- routes ----------------------------------------------------------------------------------

  async function route() {
    const mine = ++navigation;
    if (!state.me) return;
    renderedHash = env.location.hash;
    const hash = env.location.hash.replace(/^#/, "") || "/";
    const parts = hash.split("/").filter(Boolean);
    const main = shell.main;
    clear(main);
    main.setAttribute("aria-busy", "true");
    try {
      if (parts.length === 0) await dashboard(main, mine);
      else if (parts[0] === "new") await register(main);
      else if (parts[0] === "developers") await developers(main, mine);
      else if (parts[0] === "s" && parts[1] && parts[2] === "integration") await integration(main, parts[1], Number(parts[3] ?? 1), mine);
      else if (parts[0] === "s" && parts[1]) await detail(main, parts[1], mine);
      else put(main, h("h1", { tabindex: "-1" }, "Page not found"), h("p", {}, h("a", { href: "#/" }, "Back to services")));
    } finally {
      if (mine === navigation) {
        main.removeAttribute("aria-busy");
        focusHeading(main);
      }
    }
  }

  // ---- dashboard -------------------------------------------------------------------------------

  async function dashboard(main, mine) {
    const q = state.list;
    const heading = h("h1", { tabindex: "-1" }, "Services");
    put(main, heading, h("p", { class: "loading", role: "status" }, "Loading services…"));
    let data;
    try {
      const query = new URLSearchParams({ q: q.q, status: q.status, environment: q.environment, page: String(q.page), page_size: "10" });
      data = await api.get(`/services?${query}`);
    } catch (error) {
      if (mine !== navigation) return;
      main.querySelector(".loading")?.remove();
      showError(main, error, () => route());
      return;
    }
    if (mine !== navigation) return;
    main.querySelector(".loading")?.remove();
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    const search = h("input", { type: "search", id: "q", value: q.q, autocomplete: "off" });
    const status = h("select", { id: "status" }, [["", "Any status"], ...Object.entries(STATUS_LABELS)].map(([v, l]) => h("option", { value: v, selected: v === q.status }, l)));
    const environment = h("select", { id: "environment" }, [["", "Any environment"], ...Object.entries(ENV_LABELS)].map(([v, l]) => h("option", { value: v, selected: v === q.environment }, l)));
    const apply = (event) => {
      event?.preventDefault();
      state.list = { q: search.value.trim(), status: status.value, environment: environment.value, page: 1 };
      route();
    };
    put(main, 
      h("p", { class: "summary" }, `${data.counts.active} active, ${data.counts.pending} pending approval, ${data.counts.disabled} disabled`),
      h(
        "form",
        { class: "filters", role: "search", onsubmit: apply },
        h("p", {}, h("label", { for: "q" }, "Search"), search),
        h("p", {}, h("label", { for: "status" }, "Status"), status),
        h("p", {}, h("label", { for: "environment" }, "Environment"), environment),
        h("p", {}, h("button", { type: "submit", class: "btn" }, "Apply")),
      ),
    );
    if (data.items.length === 0) {
      const filtered = q.q || q.status || q.environment;
      put(main, 
        h(
          "div",
          { class: "empty" },
          h("p", {}, filtered ? "No services match those filters." : state.me.is_admin ? "No services are registered yet." : "You have not registered any services yet."),
          state.me.register_environments.length && !filtered ? h("p", {}, h("a", { class: "btn btn-primary", href: "#/new" }, "Register a service")) : null,
        ),
      );
    } else {
      put(main, 
        h(
          "div",
          { class: "table-wrap" },
          h(
            "table",
            {},
            h("caption", { class: "sr-only" }, "Registered services"),
            h("thead", {}, h("tr", {}, ["Service", "Environment", "Address", "Status", "Owner", "Updated"].map((c) => h("th", { scope: "col" }, c)))),
            h(
              "tbody",
              {},
              data.items.map((s) =>
                h(
                  "tr",
                  {},
                  h("th", { scope: "row" }, h("a", { href: `#/s/${s.id}` }, s.display_name), h("br"), h("code", {}, s.id)),
                  h("td", {}, ENV_LABELS[s.environment]),
                  h("td", {}, h("code", {}, s.base_url)),
                  h("td", {}, badge(s.status, STATUS_LABELS[s.status]), s.source === "bootstrap" ? " " : "", s.source === "bootstrap" ? h("span", { class: "muted" }, "(from configuration)") : null),
                  h("td", {}, s.owner ?? s.owner_team ?? "", s.owner_team && s.owner ? h("span", { class: "muted" }, ` · ${s.owner_team}`) : null),
                  h("td", {}, when(s.updated_at)),
                ),
              ),
            ),
          ),
        ),
        h(
          "nav",
          { class: "pager", "aria-label": "Pages" },
          h("button", { type: "button", class: "btn", disabled: data.page <= 1, onclick: () => { state.list.page -= 1; route(); } }, "Previous"),
          h("span", {}, `Page ${data.page} of ${pages} (${data.total} services)`),
          h("button", { type: "button", class: "btn", disabled: data.page >= pages, onclick: () => { state.list.page += 1; route(); } }, "Next"),
        ),
      );
    }
    announce(`${data.total} services shown.`);
  }

  // ---- register --------------------------------------------------------------------------------

  const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32);

  function validateDraft(d) {
    const problems = {};
    if (!d.display_name.trim() || d.display_name.trim().length > 60) problems.display_name = "Enter a name of up to 60 characters.";
    if (!ID_PATTERN.test(d.id)) problems.id = "Use lowercase letters, digits and hyphens, starting with a letter (2 to 32 characters).";
    if (!state.me.register_environments.includes(d.environment)) problems.environment = "You cannot register services in that environment.";
    try {
      const url = new URL(d.base_url);
      const plain = (url.pathname === "/" || url.pathname === "") && !url.search && !url.hash && !url.username && !url.password;
      if (!["http:", "https:"].includes(url.protocol) || !plain) problems.base_url = "Enter the service's origin only, such as https://service.example (no path, query or credentials).";
      else if (d.environment === "production" && url.protocol !== "https:") problems.base_url = "A production service must use https.";
    } catch {
      problems.base_url = "Enter the service's origin, such as https://service.example.";
    }
    if (!/^\/[A-Za-z0-9._~/-]{0,128}$/.test(d.callback_path) || d.callback_path.includes("..")) problems.callback_path = "Use a plain path such as /handoff/redeem.";
    const seconds = Number(d.session_seconds);
    if (!Number.isInteger(seconds) || seconds < 60 || seconds > 3600) problems.session_seconds = "Enter a whole number of seconds from 60 to 3600.";
    if (d.description.length > 500) problems.description = "Keep the description to 500 characters.";
    if (d.prefixes.some((p) => !/^\/[A-Za-z0-9._~/-]{0,127}$/.test(p) || p.includes(".."))) problems.prefixes = "Each return path must be a plain path such as /workspace.";
    return problems;
  }

  const toPayload = (d) => ({
    id: d.id,
    display_name: d.display_name.trim(),
    description: d.description.trim(),
    owner_team: d.owner_team.trim(),
    environment: d.environment,
    base_url: d.base_url.trim(),
    callback_path: d.callback_path,
    roles: d.visibility === "admin" ? ["admin"] : [],
    return_path_prefixes: d.prefixes,
    session_seconds: Number(d.session_seconds),
  });

  function field(id, label, control, hint, problem) {
    if (problem) {
      control.setAttribute("aria-invalid", "true");
      control.setAttribute("aria-describedby", `${id}-msg`);
    } else if (hint) control.setAttribute("aria-describedby", `${id}-msg`);
    return h("div", { class: "field" }, h("label", { for: id }, label), control, problem || hint ? h("p", { id: `${id}-msg`, class: problem ? "field-error" : "hint" }, problem ?? hint) : null);
  }

  async function register(main) {
    const envs = state.me.register_environments;
    if (!envs.length) {
      put(main, h("h1", { tabindex: "-1" }, "Register a service"), h("p", { role: "alert" }, "Your account cannot register services."));
      return;
    }
    state.draft ??= {
      display_name: "", id: "", idTouched: false, description: "", owner_team: "", environment: envs[0], base_url: "",
      callback_path: "/handoff/redeem", visibility: "everyone", prefixes: [], session_seconds: "900",
    };
    renderForm(main, {});
  }

  function renderForm(main, problems) {
    const d = state.draft;
    clear(main);
    const text = (id, value, props = {}) => h("input", { id, type: "text", value, autocomplete: "off", ...props });
    const name = text("f-name", d.display_name);
    const id = text("f-id", d.id, { spellcheck: "false" });
    const desc = h("textarea", { id: "f-desc", rows: "3", maxlength: "500" }, d.description);
    const team = text("f-team", d.owner_team);
    const env = h("select", { id: "f-env" }, state.me.register_environments.map((e) => h("option", { value: e, selected: e === d.environment }, ENV_LABELS[e])));
    const base = text("f-base", d.base_url, { inputmode: "url", placeholder: "https://service.example" });
    const cb = text("f-cb", d.callback_path);
    const vis = h("select", { id: "f-vis" }, [["everyone", "Everyone with an account"], ["admin", "Administrators only"]].map(([v, l]) => h("option", { value: v, selected: v === d.visibility }, l)));
    const pre = h("textarea", { id: "f-pre", rows: "3", placeholder: "/workspace\n/courses" }, d.prefixes.join("\n"));
    const secs = text("f-secs", d.session_seconds, { inputmode: "numeric" });
    name.addEventListener("input", () => {
      if (!d.idTouched) {
        d.id = slug(name.value);
        id.value = d.id;
      }
    });
    id.addEventListener("input", () => {
      d.idTouched = true;
    });
    const collect = () => {
      Object.assign(d, {
        display_name: name.value, id: id.value, description: desc.value, owner_team: team.value, environment: env.value,
        base_url: base.value, callback_path: cb.value, visibility: vis.value, session_seconds: secs.value,
        prefixes: pre.value.split("\n").map((l) => l.trim()).filter(Boolean),
      });
    };
    put(main, 
      h("h1", { tabindex: "-1" }, "Register a service"),
      h("p", { class: "lede" }, "A new service starts as ", h("strong", {}, "pending"), ". An administrator reviews and activates it; until then it cannot send or receive a hand-off or be sent a sign-in."),
      h(
        "form",
        {
          novalidate: true,
          onsubmit: (event) => {
            event.preventDefault();
            collect();
            const found = validateDraft(d);
            if (Object.keys(found).length) return renderForm(main, found);
            return review(main);
          },
        },
        h("fieldset", {}, h("legend", {}, "Service"),
          field("f-name", "Display name", name, "Shown to people in the service switcher.", problems.display_name),
          field("f-id", "Identifier", id, "Permanent. Used in configuration and the registry.", problems.id),
          field("f-desc", "Description (optional)", desc, null, problems.description),
          field("f-team", "Owner or responsible team (optional)", team)),
        h("fieldset", {}, h("legend", {}, "Where it runs"),
          field("f-env", "Environment", env, "Production services can only be registered by an administrator.", problems.environment),
          field("f-base", "Base URL", base, "The service's origin: the page address people use and the browser origin it signs in from. No path.", problems.base_url),
          field("f-cb", "Hand-off redemption path", cb, "Where the service receives one-time tickets (a POST route on the base URL).", problems.callback_path)),
        h("fieldset", {}, h("legend", {}, "Access"),
          field("f-vis", "Who sees it in the switcher", vis, "Visibility only. The service's own login and role checks decide access."),
          field("f-pre", "Allowed return paths (optional, one per line)", pre, "If set, a hand-off can only land under these paths.", problems.prefixes),
          field("f-secs", "Session length in seconds", secs, "How long the service's own session lasts after a hand-off (60 to 3600). The service configures this itself.", problems.session_seconds)),
        h("p", { class: "actions" }, h("button", { type: "submit", class: "btn btn-primary" }, "Review")),
      ),
    );
    focusHeading(main);
    if (Object.keys(problems).length) main.querySelector("[aria-invalid]")?.focus?.();
  }

  async function review(main) {
    const d = state.draft;
    const payload = toPayload(d);
    clear(main);
    const results = h("div", { class: "results" }, h("p", { role: "status" }, "Checking the configuration…"));
    const submit = h("button", { type: "button", class: "btn btn-primary", disabled: true }, "Register service");
    put(main, 
      h("h1", { tabindex: "-1" }, "Review"),
      h("dl", { class: "facts" }, [
        ["Name", payload.display_name], ["Identifier", payload.id], ["Environment", ENV_LABELS[payload.environment]],
        ["Base URL", payload.base_url], ["Redemption path", payload.callback_path],
        ["Visible to", payload.roles.length ? "Administrators only" : "Everyone with an account"],
        ["Allowed return paths", payload.return_path_prefixes.join(", ") || "Any path on the service"],
        ["Session length", `${payload.session_seconds} seconds`], ["Owner team", payload.owner_team || "—"],
      ].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      results,
      h("p", { class: "actions" }, h("button", { type: "button", class: "btn", onclick: () => renderForm(main, {}) }, "Back to edit"), submit),
    );
    focusHeading(main);
    const show = (checks, ok) => {
      clear(results);
      put(results, checkList(checks));
      submit.disabled = !ok;
    };
    try {
      const outcome = await api.post("/services/validate", payload);
      show(outcome.checks, outcome.ok);
    } catch (error) {
      clear(results);
      showError(results, error);
      if (error instanceof PortalApiError && error.details.checks) put(results, checkList(error.details.checks));
    }
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      try {
        const created = await api.post("/services", payload);
        state.secret = { id: created.service.id, value: created.secret };
        state.draft = null;
        env.location.hash = `#/s/${created.service.id}`;
      } catch (error) {
        submit.disabled = false;
        clear(results);
        showError(results, error);
        if (error instanceof PortalApiError && error.details.checks) put(results, checkList(error.details.checks));
      }
    });
  }

  // ---- one service -----------------------------------------------------------------------------

  async function detail(main, serviceId, mine) {
    let service;
    let events = [];
    try {
      service = (await api.get(`/services/${encodeURIComponent(serviceId)}`)).service;
      events = (await api.get(`/services/${encodeURIComponent(serviceId)}/activity`)).events;
    } catch (error) {
      if (mine !== navigation) return;
      put(main, h("h1", { tabindex: "-1" }, "Service"));
      showError(main, error);
      put(main, h("p", {}, h("a", { href: "#/" }, "Back to services")));
      return;
    }
    if (mine !== navigation) return;
    renderDetail(main, service, events);
  }

  function renderDetail(main, service, events) {
    clear(main);
    const p = service.permissions;
    const output = h("div", { class: "output", "aria-live": "polite" });
    const reload = async () => {
      const fresh = (await api.get(`/services/${encodeURIComponent(service.id)}`)).service;
      const activity = (await api.get(`/services/${encodeURIComponent(service.id)}/activity`)).events;
      renderDetail(main, fresh, activity);
    };
    const attempt = async (work) => {
      clear(output);
      try {
        await work();
      } catch (error) {
        showError(output, error);
        if (error instanceof PortalApiError && error.details.checks) put(output, checkList(error.details.checks));
      }
    };
    const act = (label, handler, kind = "") => h("button", { type: "button", class: `btn ${kind}`, onclick: handler }, label);
    const needsTyping = service.environment === "production";

    const buttons = [
      p.edit ? act("Edit", () => editForm(main, service, reload)) : null,
      p.validate ? act("Check configuration", () => attempt(async () => {
        const outcome = await api.post(`/services/${service.id}/validate`);
        put(output, h("p", {}, outcome.ok ? "The configuration passes every check." : "The configuration has problems."), checkList(outcome.checks));
      })) : null,
      p.enable ? act(service.status === "disabled" ? "Re-enable" : "Activate", () => attempt(async () => {
        const answer = await confirmDialog({
          title: `Activate ${service.display_name}?`,
          body: h("p", {}, `${service.base_url} will be trusted to receive sign-ins and hand-offs. Only activate a service you have reviewed.`),
          expect: needsTyping ? service.id : null, confirmLabel: "Activate",
        });
        if (!answer) return;
        await api.post(`/services/${service.id}/enable`, { confirm: answer.typed ?? undefined });
        announce("Service activated.");
        await reload();
      }), "btn-primary") : null,
      p.disable ? act("Disable", () => attempt(async () => {
        const answer = await confirmDialog({
          title: `Disable ${service.display_name}?`,
          body: h("div", {}, h("p", {}, "New hand-offs to and from this service stop immediately, and tickets already issued are cancelled."), h("p", {}, "People's accounts and the service's own data are not changed. You can re-enable it later.")),
          expect: needsTyping ? service.id : null, confirmLabel: "Disable service", danger: true,
        });
        if (!answer) return;
        await api.post(`/services/${service.id}/disable`, { confirm: answer.typed ?? undefined });
        announce("Service disabled.");
        await reload();
      }), "btn-danger") : null,
      p.rotate_secret ? act("Rotate secret", () => attempt(async () => {
        const answer = await confirmDialog({
          title: "Rotate the service secret?",
          body: h("div", {}, h("p", {}, `A new secret is generated and shown once. The current one keeps working for ${Math.round(state.me.limits.rotation_grace_seconds / 60)} minutes so the service can be updated, unless you revoke it immediately.`)),
          checkbox: "Revoke the old secret immediately (hand-offs fail until the service has the new one)",
          expect: service.id, confirmLabel: "Rotate secret", danger: true,
        });
        if (!answer) return;
        const rotated = await api.post(`/services/${service.id}/rotate-secret`, { confirm: answer.typed, revoke_old: answer.checked });
        state.secret = { id: service.id, value: rotated.secret };
        await reload();
      })) : null,
    ].filter(Boolean);

    put(main, 
      h("h1", { tabindex: "-1" }, service.display_name, " ", badge(service.status, STATUS_LABELS[service.status])),
      h("p", {}, h("a", { href: "#/" }, "← All services")),
      state.secret?.id === service.id ? secretPanel(() => { state.secret = null; reload(); }) : null,
      service.status === "pending" ? h("p", { class: "notice" }, "Pending approval: this service cannot send or receive hand-offs until an administrator activates it.") : null,
      h("dl", { class: "facts" }, [
        ["Identifier", h("code", {}, service.id)], ["Environment", ENV_LABELS[service.environment]],
        ["Base URL", h("code", {}, service.base_url)], ["Redemption endpoint", h("code", {}, service.redeem_url)],
        ["Owner", service.owner ?? "—"], ["Team", service.owner_team || "—"], ["Description", service.description || "—"],
        ["Visible to", service.roles.length ? "Administrators only" : "Everyone with an account"],
        ["Return paths", service.return_path_prefixes.join(", ") || "Any path on the service"],
        ["Session length", `${service.session_seconds} seconds`],
        ["Previous secret", service.previous_secret_valid_until ? `still valid until ${when(new Date(service.previous_secret_valid_until * 1000).toISOString())}` : "none"],
        ["Source", service.source === "bootstrap" ? "Seeded from configuration" : "Registered in the portal"],
        ["Created", when(service.created_at)], ["Updated", when(service.updated_at)],
      ].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      h("div", { class: "actions" }, h("a", { class: "btn btn-primary", href: `#/s/${service.id}/integration/1` }, "Integration guide"), buttons),
      output,
      h("h2", {}, "Recent activity"),
      events.length
        ? h("ul", { class: "activity" }, events.map((e) => h("li", {}, h("time", {}, when(e.at)), " ", h("strong", {}, e.action.replaceAll("_", " ")), e.actor ? ` by ${e.actor}` : "")))
        : h("p", { class: "muted" }, "Nothing recorded yet."),
    );
    focusHeading(main);
  }

  function editForm(main, service, reload) {
    const p = service.permissions;
    const f = (id, value, props = {}) => h("input", { id, type: "text", value, ...props });
    const name = f("e-name", service.display_name);
    const desc = h("textarea", { id: "e-desc", rows: "3" }, service.description);
    const team = f("e-team", service.owner_team);
    const vis = h("select", { id: "e-vis" }, [["everyone", "Everyone with an account"], ["admin", "Administrators only"]].map(([v, l]) => h("option", { value: v, selected: v === (service.roles.length ? "admin" : "everyone") }, l)));
    const pre = h("textarea", { id: "e-pre", rows: "3" }, service.return_path_prefixes.join("\n"));
    const secs = f("e-secs", String(service.session_seconds));
    const base = f("e-base", service.base_url, { disabled: !p.edit_trusted });
    const cb = f("e-cb", service.callback_path, { disabled: !p.edit_trusted });
    const result = h("div", { class: "output", "aria-live": "polite" });
    const form = h(
      "form",
      {
        novalidate: true,
        onsubmit: async (event) => {
          event.preventDefault();
          const changes = {};
          const next = {
            display_name: name.value.trim(), description: desc.value.trim(), owner_team: team.value.trim(),
            roles: vis.value === "admin" ? ["admin"] : [], session_seconds: Number(secs.value),
            return_path_prefixes: pre.value.split("\n").map((l) => l.trim()).filter(Boolean),
            ...(p.edit_trusted ? { base_url: base.value.trim(), callback_path: cb.value } : {}),
          };
          for (const [key, value] of Object.entries(next)) {
            if (JSON.stringify(value) !== JSON.stringify(service[key])) changes[key] = value;
          }
          if (!Object.keys(changes).length) return announce("Nothing to save.");
          const trusted = ["base_url", "callback_path"].some((k) => k in changes);
          if (trusted && service.status === "active") {
            const answer = await confirmDialog({
              title: "Change an active service's address?", expect: service.id, confirmLabel: "Save changes", danger: true,
              body: h("p", {}, "Tickets already issued for this service will be cancelled, and the new address becomes the one trusted for sign-ins."),
            });
            if (!answer) return;
            changes.confirm = answer.typed;
          }
          clear(result);
          try {
            await api.patch(`/services/${service.id}`, changes);
            announce("Changes saved.");
            await reload();
          } catch (error) {
            showError(result, error);
            if (error instanceof PortalApiError && error.details.checks) put(result, checkList(error.details.checks));
          }
        },
      },
      field("e-name", "Display name", name), field("e-desc", "Description", desc), field("e-team", "Owner or responsible team", team),
      field("e-vis", "Who sees it in the switcher", vis), field("e-pre", "Allowed return paths (one per line)", pre),
      field("e-secs", "Session length in seconds", secs),
      field("e-base", "Base URL", base, p.edit_trusted ? null : "Locked: only an administrator can change the address of an approved service."),
      field("e-cb", "Hand-off redemption path", cb),
      h("p", { class: "actions" }, h("button", { type: "button", class: "btn", onclick: () => reload() }, "Cancel"), h("button", { type: "submit", class: "btn btn-primary" }, "Save changes")),
    );
    clear(main);
    put(main, h("h1", { tabindex: "-1" }, `Edit ${service.display_name}`), form, result);
    focusHeading(main);
  }

  // ---- integration wizard ----------------------------------------------------------------------

  async function integration(main, serviceId, step, mine) {
    let config;
    try {
      config = await api.get(`/services/${encodeURIComponent(serviceId)}/integration-config`);
    } catch (error) {
      if (mine !== navigation) return;
      put(main, h("h1", { tabindex: "-1" }, "Integration guide"));
      showError(main, error);
      return;
    }
    if (mine !== navigation) return;
    const index = Math.min(Math.max(Number.isInteger(step) ? step : 1, 1), STEPS.length);
    const oneTime = state.secret?.id === serviceId ? state.secret.value : null;
    const steps = h("ol", { class: "steps", "aria-label": "Integration steps" }, STEPS.map((label, i) => h("li", {}, h("a", { href: `#/s/${serviceId}/integration/${i + 1}`, "aria-current": i + 1 === index ? "step" : null }, `${String.fromCharCode(65 + i)}. ${label}`))));
    const body = h("section", { "aria-labelledby": "step-title" });
    const code = (text) => h("div", { class: "code" }, h("pre", {}, h("code", {}, text)), h("button", { type: "button", class: "btn", onclick: () => copyText(text, "Text") }, "Copy"));

    if (index === 1) {
      put(body, 
        h("h2", { id: "step-title" }, "A. Registration summary"),
        h("dl", { class: "facts" }, [["Identifier", config.service.id], ["Environment", ENV_LABELS[config.service.environment]], ["Approved base URL", config.service.base_url], ["Status", STATUS_LABELS[config.service.status]]].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
        h("h3", {}, "Setup actions"),
        h("ol", {}, h("li", {}, config.service.status === "active" ? "An administrator has activated the service." : "Ask an administrator to review and activate the service."), h("li", {}, "Set the environment variables (step B) in the service's server-side configuration."), h("li", {}, "Install the adapter and wire the routes (step C), then test (step D).")),
      );
    } else if (index === 2) {
      const lines = config.variables.map((v) => `${v.key}=${v.key === "VETFAB_SERVICE_SECRET" && oneTime ? oneTime : (v.value ?? v.placeholder)}`).join("\n");
      put(body, 
        h("h2", { id: "step-title" }, "B. Environment variables"),
        h("div", { class: "table-wrap" }, h("table", {}, h("caption", { class: "sr-only" }, "Environment variables"),
          h("thead", {}, h("tr", {}, ["Variable", "Value", "Where it comes from"].map((c) => h("th", { scope: "col" }, c)))),
          h("tbody", {}, config.variables.map((v) => h("tr", {}, h("th", { scope: "row" }, h("code", {}, v.key), v.optional ? h("span", { class: "muted" }, " (optional)") : null),
            h("td", {}, h("code", {}, v.value ?? v.placeholder)),
            h("td", {}, v.origin === "portal" ? badge("active", "From the portal") : v.origin === "secret" ? badge("pending", "One-time secret") : badge("disabled", "You generate it"), " ", v.note)))))),
        oneTime ? h("p", { class: "notice", role: "note" }, "The template below includes the secret you just generated. It disappears when you leave this page.") : h("p", { class: "muted" }, "The secret is not shown again; rotate it from the service page if you no longer have it."),
        code(lines),
      );
    } else if (index === 3) {
      put(body, 
        h("h2", { id: "step-title" }, "C. Installation"),
        h("h3", {}, "Backend"), code(config.backend.install), code(config.backend.code),
        h("p", {}, "Pass your own ", h("code", {}, "load_user"), " (it decides whether a signed-in person has an account and what they may do), keep state-changing routes behind the guard (cookie sessions require the service's own Origin), and set a unique session secret."),
        h("h3", {}, "Frontend"), code(config.frontend.install), code(config.frontend.code),
      );
    } else if (index === 4) {
      put(body, 
        h("h2", { id: "step-title" }, "D. Local testing"),
        h("ol", { class: "checklist" }, config.local_test.map((t) => h("li", {}, h("p", {}, t.step), code(t.command)))),
      );
    } else {
      put(body, 
        h("h2", { id: "step-title" }, "E. Production readiness"),
        h("p", { class: "notice", role: "note" }, "Registering a service does not make it production-ready. The items marked for a person to confirm cannot be verified from here."),
        h("ul", { class: "readiness" }, config.readiness.map((r) => h("li", { class: `ready-${r.state}` }, h("strong", {}, { done: "Done", todo: "To do", manual: "Confirm yourself", "n/a": "Not applicable" }[r.state]), ": ", r.label))),
      );
    }
    clear(main);
    put(main, 
      h("h1", { tabindex: "-1" }, "Integration guide"),
      h("p", {}, h("a", { href: `#/s/${serviceId}` }, "← Back to the service")),
      steps, body,
      h("p", { class: "actions" },
        h("button", { type: "button", class: "btn", disabled: index <= 1, onclick: () => { env.location.hash = `#/s/${serviceId}/integration/${index - 1}`; } }, "Back"),
        h("button", { type: "button", class: "btn btn-primary", disabled: index >= STEPS.length, onclick: () => { env.location.hash = `#/s/${serviceId}/integration/${index + 1}`; } }, "Next")),
    );
    focusHeading(main);
  }

  // ---- developers (administrators) -------------------------------------------------------------

  async function developers(main, mine) {
    if (!state.me.is_admin) {
      put(main, h("h1", { tabindex: "-1" }, "Developers"), h("p", { role: "alert" }, ERROR_TEXT.administrator_only));
      return;
    }
    let data;
    try {
      data = await api.get("/developers");
    } catch (error) {
      if (mine !== navigation) return;
      put(main, h("h1", { tabindex: "-1" }, "Developers"));
      showError(main, error, () => route());
      return;
    }
    if (mine !== navigation) return;
    const email = h("input", { id: "d-email", type: "email", autocomplete: "off" });
    const boxes = ["local", "staging"].map((e) => h("input", { type: "checkbox", id: `d-${e}`, value: e, checked: e === "local" }));
    const result = h("div", { class: "output", "aria-live": "polite" });
    put(main, 
      h("h1", { tabindex: "-1" }, "Developers"),
      h("p", { class: "lede" }, "A developer can register services in the environments granted here, and manage their own. They cannot register production services, activate anything or change anyone's permissions."),
      data.developers.length
        ? h("table", {}, h("caption", { class: "sr-only" }, "Developers"), h("thead", {}, h("tr", {}, ["Person", "Environments", ""].map((c) => h("th", { scope: "col" }, c)))),
            h("tbody", {}, data.developers.map((d) => h("tr", {}, h("th", { scope: "row" }, d.email), h("td", {}, d.environments.map((e) => ENV_LABELS[e]).join(", ")),
              h("td", {}, h("button", { type: "button", class: "btn btn-danger", onclick: async () => {
                const answer = await confirmDialog({ title: `Remove ${d.email}?`, body: h("p", {}, "They keep any services they registered but can no longer register new ones."), confirmLabel: "Remove", danger: true });
                if (!answer) return;
                try { await api.del(`/developers/${d.user_id}`); announce("Developer removed."); route(); } catch (error) { showError(result, error); }
              } }, "Remove"))))))
        : h("p", { class: "empty" }, "No developers have been granted access."),
      h("form", { novalidate: true, onsubmit: async (event) => {
        event.preventDefault();
        clear(result);
        const environments = boxes.filter((b) => b.checked).map((b) => b.value);
        if (!email.value.trim() || !environments.length) return showError(result, new PortalApiError(400, "body"));
        try { await api.put("/developers", { email: email.value.trim(), environments }); announce("Developer saved."); route(); } catch (error) { showError(result, error); }
      } },
        h("h2", {}, "Grant developer access"),
        field("d-email", "Email address of an existing account", email),
        h("fieldset", {}, h("legend", {}, "Environments"), boxes.map((b) => h("p", {}, b, " ", h("label", { for: b.id }, ENV_LABELS[b.value])))),
        h("p", { class: "actions" }, h("button", { type: "submit", class: "btn btn-primary" }, "Save"))),
      result,
    );
  }

  // ---- start -----------------------------------------------------------------------------------

  async function start() {
    try {
      state.me = await api.get("/me");
    } catch (error) {
      if (error instanceof PortalApiError && error.code === "not_signed_in") return signInScreen("Sign in with your Vetfab account to register and manage services.");
      if (error instanceof PortalApiError && (error.code === "not_authorised" || error.status === 403)) {
        clear(root);
        put(root, h("main", { id: "portal-main", class: "narrow" }, h("p", { class: "brand" }, "Vetfab ", h("span", {}, "Developer portal")), h("h1", { tabindex: "-1" }, "No access"), h("p", { role: "alert" }, ERROR_TEXT.not_authorised), h("p", {}, "Ask a Vetfab administrator to grant you developer access.")));
        return;
      }
      clear(root);
      const box = h("main", { id: "portal-main", class: "narrow" }, h("h1", { tabindex: "-1" }, "Developer portal"));
      showError(box, error, () => start());
      put(root, box);
      return;
    }
    buildShell();
    win.addEventListener("hashchange", () => {
      if (env.location.hash !== renderedHash) route();
    });
    await route();
  }

  return start();
}
