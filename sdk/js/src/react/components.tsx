import { createContext, type ReactNode, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";

import type { IdentityClaims, IdentityError } from "../index.js";
import { type AuthSnapshot, type IdentityClient, type LoginOptions } from "../client.js";

const Context = createContext<{ client: IdentityClient; profile: unknown } | null>(null);

export interface VetfabAuthProviderProps {
  client: IdentityClient;
  /**
   * Loads the application's own record of the signed-in person (name, roles, ...) from its backend, which is where
   * that data lives: the token carries only the user's id. Receives the client so it can call `client.fetch`.
   */
  loadProfile?: (client: IdentityClient) => Promise<unknown>;
  children: ReactNode;
}

export interface VetfabAuth<P = unknown> {
  /** True until the first answer (signed in or not) is known. Render a loading state, not a login prompt. */
  loading: boolean;
  isAuthenticated: boolean;
  /** The user's id, once known. */
  userId: string | null;
  claims: IdentityClaims | null;
  /** The application's own profile from `loadProfile`, once loaded. */
  profile: P | null;
  error: IdentityError | null;
  login: (options?: LoginOptions) => void;
  logout: (options?: LoginOptions) => Promise<void>;
  /** `fetch` with the access token attached (this app's API only). */
  fetch: IdentityClient["fetch"];
  getAccessToken: () => Promise<string | null>;
}

export function VetfabAuthProvider({ client, loadProfile, children }: VetfabAuthProviderProps) {
  const snapshot = useSyncExternalStore(client.subscribe, client.getSnapshot, client.getSnapshot);
  const [profile, setProfile] = useState<unknown>(null);

  useEffect(() => {
    void client.init();
  }, [client]);

  const sub = snapshot.claims?.sub ?? null;
  useEffect(() => {
    if (!loadProfile || !sub) {
      setProfile(null);
      return;
    }
    let cancelled = false;
    loadProfile(client).then(
      (loaded) => !cancelled && setProfile(loaded),
      () => !cancelled && setProfile(null),
    );
    return () => {
      cancelled = true;
    };
  }, [client, loadProfile, sub]);

  const value = useMemo(() => ({ client, profile }), [client, profile]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useVetfabAuth<P = unknown>(): VetfabAuth<P> {
  const context = useContext(Context);
  if (!context) throw new Error("useVetfabAuth must be used inside <VetfabAuthProvider>.");
  const { client, profile } = context;
  const snapshot: AuthSnapshot = useSyncExternalStore(client.subscribe, client.getSnapshot, client.getSnapshot);
  return {
    loading: snapshot.status === "loading",
    isAuthenticated: snapshot.status === "authenticated",
    userId: snapshot.claims?.sub ?? null,
    claims: snapshot.claims,
    profile: profile as P | null,
    error: snapshot.error,
    login: (options) => client.login(options),
    logout: (options) => client.logout(options),
    fetch: (input, init) => client.fetch(input, init),
    getAccessToken: () => client.getAccessToken(),
  };
}

export interface RequireAuthProps {
  children: ReactNode;
  /** Shown while the first answer is pending. */
  loading?: ReactNode;
  /** Shown instead of redirecting when `autoLogin` is false. */
  fallback?: ReactNode;
  /** Render for an authentication error (e.g. a sign-in loop or an unreachable identity service). */
  onError?: (error: IdentityError) => ReactNode;
  /** Redirect to sign-in straight away when signed out. Default true. */
  autoLogin?: boolean;
}

/**
 * Renders `children` only for a signed-in person. This is a convenience for the interface: the backend enforces
 * access on every request regardless of what the browser shows.
 */
export function RequireAuth({ children, loading = null, fallback = null, onError, autoLogin = true }: RequireAuthProps) {
  const auth = useVetfabAuth();
  const started = useRef(false);
  const unauthenticated = !auth.loading && !auth.isAuthenticated && !auth.error;

  useEffect(() => {
    if (autoLogin && unauthenticated && !started.current) {
      started.current = true; // one redirect per mount: a re-render must not start a second sign-in
      try {
        auth.login();
      } catch {
        // surfaced through `auth.error` (login loop, blocked storage)
      }
    }
  }, [autoLogin, unauthenticated, auth]);

  if (auth.loading) return <>{loading}</>;
  if (auth.error && !auth.isAuthenticated) return <>{onError ? onError(auth.error) : fallback}</>;
  if (!auth.isAuthenticated) return <>{autoLogin ? loading : fallback}</>;
  return <>{children}</>;
}

export interface AuthCallbackProps {
  /** Called once the sign-in completes, with the path to return to. Navigate there with your router. */
  onSuccess: (returnTo: string) => void;
  /** Rendered while the hand-off is processed. */
  loading?: ReactNode;
  /** Rendered when it fails (state mismatch, expired or foreign token). Offer `login()` again. */
  onError: (error: IdentityError) => ReactNode;
}

/** The page at the hand-off path (`/handoff`): completes the sign-in exactly once, then reports where to go. */
export function AuthCallback({ onSuccess, loading = null, onError }: AuthCallbackProps) {
  const { client } = useContext(Context) ?? (() => { throw new Error("AuthCallback must be used inside <VetfabAuthProvider>."); })();
  const [error, setError] = useState<IdentityError | null>(null);
  const done = useRef(onSuccess);
  done.current = onSuccess;

  useEffect(() => {
    // handleCallback() is idempotent per fragment, so StrictMode's double effect does not process the state twice.
    client.handleCallback().then(
      ({ returnTo }) => done.current(returnTo),
      (failure: unknown) => setError(failure as IdentityError),
    );
  }, [client]);

  return <>{error ? onError(error) : loading}</>;
}
