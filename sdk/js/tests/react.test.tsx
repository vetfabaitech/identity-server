import { StrictMode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthCallback, RequireAuth, VetfabAuthProvider, useVetfabAuth } from "../src/react";
import { json, makeToken, setup, startLogin } from "./helpers";

afterEach(cleanup);

function Who() {
  const auth = useVetfabAuth<{ name: string }>();
  return <p>{auth.isAuthenticated ? `${auth.userId}|${auth.profile?.name ?? "no-profile"}` : "anonymous"}</p>;
}

describe("RequireAuth", () => {
  it("shows loading, then starts one sign-in redirect for a signed-out visitor", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockResolvedValue(json({ error: "no_session" }, 401));
    render(
      <StrictMode>
        <VetfabAuthProvider client={client}>
          <RequireAuth loading={<p>loading</p>}>
            <p>secret</p>
          </RequireAuth>
        </VetfabAuthProvider>
      </StrictMode>,
    );
    expect(screen.getByText("loading")).toBeTruthy();
    await waitFor(() => expect(browser.navigated).toHaveLength(1));
    expect(screen.queryByText("secret")).toBeNull();
  });

  it("renders the page for a signed-in person, with the app's own profile", async () => {
    const { browser, client } = setup();
    browser.fetchMock.mockImplementation(async (input: unknown) =>
      String(input).endsWith("/auth/session/token")
        ? json({ access_token: makeToken(browser), expires_in: 900 })
        : json({ name: "Asha" }),
    );
    render(
      <VetfabAuthProvider client={client} loadProfile={async (c) => (await c.fetch("/api/me")).json()}>
        <RequireAuth>
          <Who />
        </RequireAuth>
      </VetfabAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("00000000-0000-4000-8000-000000000001|Asha")).toBeTruthy());
    expect(browser.navigated).toEqual([]);
  });

  it("shows an error instead of redirecting when sign-in cannot be verified", async () => {
    const { browser, client } = setup();
    browser.storageBlocked = true;
    browser.fetchMock.mockResolvedValue(json({}, 401));
    render(
      <VetfabAuthProvider client={client}>
        <RequireAuth onError={(error) => <p>{error.code}</p>}>
          <p>secret</p>
        </RequireAuth>
      </VetfabAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("storage_unavailable")).toBeTruthy());
    expect(browser.navigated).toEqual([]);
  });
});

describe("AuthCallback", () => {
  it("completes the sign-in once under StrictMode and reports where to go", async () => {
    const { browser, client } = setup();
    const state = startLogin(browser, client, "/lab/3");
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&state=${state}`;
    const onSuccess = vi.fn();
    render(
      <StrictMode>
        <VetfabAuthProvider client={client}>
          <AuthCallback onSuccess={onSuccess} onError={(e) => <p>{e.code}</p>} />
        </VetfabAuthProvider>
      </StrictMode>,
    );
    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    expect(new Set(onSuccess.mock.calls.map(([path]) => path))).toEqual(new Set(["/lab/3"]));
    expect(browser.fetchMock).not.toHaveBeenCalled();
    expect(client.getSnapshot().status).toBe("authenticated");
  });

  it("renders the error for a hand-off it did not ask for", async () => {
    const { browser, client } = setup();
    browser.path = "/handoff";
    browser.fragment = `#token=${makeToken(browser)}&state=${"A".repeat(43)}`;
    render(
      <VetfabAuthProvider client={client}>
        <AuthCallback onSuccess={() => {}} onError={(e) => <p>{e.code}</p>} />
      </VetfabAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("callback_state")).toBeTruthy());
  });
});
