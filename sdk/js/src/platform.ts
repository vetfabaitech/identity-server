/** Everything the client needs from the browser, in one replaceable object (so tests need no real navigation). */

export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface Platform {
  /** Origin of the running page. */
  origin(): string;
  /** `pathname + search` of the running page. */
  currentPath(): string;
  /** The page's current `#fragment`, including the leading `#` (empty when none). */
  hash(): string;
  /** Leave the page for `url` (a full navigation). */
  navigate(url: string): void;
  /** Rewrite the address bar without navigating (used to drop the token fragment). */
  replaceUrl(path: string): void;
  /** Submit a form `POST` to `url` as a full navigation. `fields` go in the body, never the URL. */
  postForm(url: string, fields?: Record<string, string>): void;
  /** Per-tab storage for the pending sign-in. Never used for tokens. */
  storage(): KeyValueStore | null;
  fetch: typeof fetch;
  now(): number;
  sleep(ms: number): Promise<void>;
  /** Cryptographically random bytes. */
  randomBytes(length: number): Uint8Array;
}

export function browserPlatform(): Platform {
  return {
    origin: () => window.location.origin,
    currentPath: () => window.location.pathname + window.location.search,
    hash: () => window.location.hash,
    navigate: (url) => window.location.assign(url),
    replaceUrl: (path) => window.history.replaceState(window.history.state, "", path),
    postForm: (url, fields = {}) => {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = url;
      form.style.display = "none";
      for (const [name, value] of Object.entries(fields)) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        form.appendChild(input);
      }
      document.body.appendChild(form);
      form.submit();
    },
    storage: () => {
      try {
        return window.sessionStorage;
      } catch {
        return null; // blocked storage: sign-in cannot be verified, so it will fail closed
      }
    },
    fetch: (...args) => window.fetch(...args),
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
  };
}
