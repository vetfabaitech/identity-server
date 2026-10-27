import { mountPortal } from "./portal.js";

mountPortal(document.getElementById("portal"), { fetch: window.fetch.bind(window), location, history, navigator, storage: window.sessionStorage });
