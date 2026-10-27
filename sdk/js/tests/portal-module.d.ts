declare module "*/developer/portal.js" {
  export class PortalApiError extends Error {
    status: number;
    code: string;
    details: Record<string, unknown>;
    constructor(status: number, code: string, details?: Record<string, unknown>);
  }
  export function describeError(error: unknown): string;
  export function createApi(fetchImpl: typeof fetch): {
    get(path: string): Promise<Record<string, unknown>>;
    post(path: string, body?: unknown): Promise<Record<string, unknown>>;
  };
  export function mountPortal(
    root: HTMLElement,
    env: {
      fetch: typeof fetch;
      location: { origin: string; hash: string; assign(url: string): void };
      history: unknown;
      navigator: { clipboard: { writeText(text: string): Promise<void> } };
      storage: unknown;
    },
  ): Promise<void>;
}
