import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef, useState, useSyncExternalStore } from "react";

import type { HandoffClient, ServiceInfo } from "../handoff.js";

export interface VetfabServiceSwitcherProps {
  handoff: HandoffClient;
  /** Id of the service this app is (shown as the current one, never offered as a destination). */
  currentService?: string;
  /** A path on the destination to open, e.g. `/workspace`. Anything not a plain path becomes `/`. */
  returnTo?: string;
  /** Text of the menu button. */
  label?: string;
  /** Called with the destination id just before the page leaves. */
  onNavigate?: (service: ServiceInfo) => void;
  /** Replace how one entry looks. */
  renderService?: (service: ServiceInfo) => ReactNode;
  className?: string;
}

const MESSAGES: Record<string, string> = {
  session_expired: "Your session has ended. Please sign in again.",
  service_unavailable: "That service is not available to you.",
  unknown_service: "That service is not available.",
  too_many_tickets: "Too many requests. Wait a minute and try again.",
  network: "Could not reach the sign-in service. Check your connection and try again.",
  source_not_registered: "Switching services is not set up for this app.",
  invalid_response: "Something went wrong. Please try again.",
};

/**
 * A menu of the other Vetfab services this person may open. Choosing one starts an SSO hand-off (`createHandoff`).
 *
 * It lists what the identity service says is visible to this person; that is a convenience, not authorisation. The
 * destination's backend and the identity service decide whether the hand-off is allowed. Keyboard: Enter/Space/ArrowDown
 * opens, arrows move, Home/End jump, Escape closes and returns focus to the button.
 */
export function VetfabServiceSwitcher({
  handoff,
  currentService,
  returnTo = "/",
  label = "Vetfab services",
  onNavigate,
  renderService,
  className,
}: VetfabServiceSwitcherProps) {
  const snapshot = useSyncExternalStore(handoff.subscribe, handoff.getSnapshot, handoff.getSnapshot);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const button = useRef<HTMLButtonElement>(null);
  const items = useRef<(HTMLButtonElement | null)[]>([]);
  const menuId = useId();

  useEffect(() => {
    void handoff.listAvailableServices().catch(() => {
      // the error is in the snapshot and rendered below
    });
  }, [handoff]);

  const busy = snapshot.status === "starting" || snapshot.status === "redirecting";
  const services = snapshot.services.filter((s) => s.id !== currentService);

  useEffect(() => {
    if (open) items.current[active]?.focus();
  }, [open, active]);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) button.current?.focus();
  };

  const choose = (service: ServiceInfo) => {
    if (busy) return; // the SDK also ignores a second hand-off; this keeps the interface quiet too
    onNavigate?.(service);
    close(false);
    void handoff.createHandoff(service.id, { returnTo }).catch(() => {
      // shown from the snapshot
    });
  };

  const onMenuKey = (event: KeyboardEvent) => {
    const last = services.length - 1;
    const move = (to: number) => {
      event.preventDefault();
      setActive(to);
    };
    if (event.key === "ArrowDown") move(active >= last ? 0 : active + 1);
    else if (event.key === "ArrowUp") move(active <= 0 ? last : active - 1);
    else if (event.key === "Home") move(0);
    else if (event.key === "End") move(last);
    else if (event.key === "Escape") {
      event.preventDefault();
      close(true);
    } else if (event.key === "Tab") setOpen(false);
  };

  const onButtonKey = (event: KeyboardEvent) => {
    if (event.key === "ArrowDown" && !busy && services.length > 0) {
      event.preventDefault();
      setActive(0);
      setOpen(true);
    }
  };

  const message = snapshot.error ? (MESSAGES[snapshot.error.code] ?? "Something went wrong. Please try again.") : null;
  const target = busy ? services.find((s) => s.id === snapshot.target) : undefined;

  return (
    <div className={className} data-vetfab-service-switcher>
      <button
        ref={button}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-busy={busy}
        disabled={busy || snapshot.status === "loading" || services.length === 0}
        onClick={() => {
          setActive(0);
          setOpen((value) => !value);
        }}
        onKeyDown={onButtonKey}
      >
        {busy ? `Opening ${target?.displayName ?? "service"}…` : label}
      </button>
      {open && (
        <ul id={menuId} role="menu" aria-label={label} onKeyDown={onMenuKey}>
          {services.map((service, index) => (
            <li key={service.id} role="none">
              <button
                ref={(element) => {
                  items.current[index] = element;
                }}
                type="button"
                role="menuitem"
                tabIndex={index === active ? 0 : -1}
                onClick={() => choose(service)}
              >
                {renderService ? renderService(service) : service.displayName}
                {service.environment !== "production" ? ` (${service.environment})` : ""}
              </button>
            </li>
          ))}
        </ul>
      )}
      <span role="status" aria-live="polite">
        {snapshot.status === "loading" ? "Loading services…" : busy ? "Signing you in…" : ""}
      </span>
      {message && (
        <p role="alert">
          {message}{" "}
          <button type="button" onClick={() => handoff.reset()}>
            Dismiss
          </button>
        </p>
      )}
    </div>
  );
}
