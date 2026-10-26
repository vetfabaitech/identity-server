// Identity service load tests (load/README.md). One script, one scenario per run, chosen with SCENARIO:
//
//   signin  RATE sign-ins/s for DURATION: GET the sign-in page, POST the form, a different account each time.
//           A 503 (busy) is retried after Retry-After, as a person pressing the button again would, up to MAX_TRIES.
//   burst   VUS people all pressing "Sign in" at the same moment (same retry rule).
//   renew   Background renewals (POST /auth/session/token from a product origin) by signed-in users, ramping the
//           arrival rate through STAGES (rate:duration,...). Each VU owns one seeded session and rotates it.
//   storm   VUS renewals at the same moment (every open tab waking up together).
//   mixed   A class starting: RATE sign-ins/s for DURATION while every seeded user renews at RENEW_RATE/s and
//           product backends fetch the JWKS.
//   nat     Like signin, but everyone shares one client address (a college network) and TYPO_RATE of attempts use a
//           wrong password first. Counts correct passwords refused with 429.
//
//   k6 run -e SCENARIO=signin -e RATE=10 -e DURATION=1m -e LOAD_PASSWORD=... -e SESSIONS=/abs/sessions.json load/k6/identity.js
import http from "k6/http";
import { check, sleep } from "k6";
import exec from "k6/execution";
import { Counter, Rate, Trend } from "k6/metrics";

const BASE = (__ENV.BASE_URL || "https://localhost:9443").replace(/\/$/, "");
const PRODUCT = __ENV.PRODUCT_ORIGIN || "https://localhost:8443"; // an IDENTITY_APP_ORIGINS entry
const PASSWORD = __ENV.LOAD_PASSWORD || "";
const USERS = parseInt(__ENV.USERS || "1000", 10);
const SCENARIO = __ENV.SCENARIO || "signin";
const RATE = parseFloat(__ENV.RATE || "5");
const DURATION = __ENV.DURATION || "1m";
const VUS = parseInt(__ENV.VUS || "1000", 10);
const MAX_TRIES = parseInt(__ENV.MAX_TRIES || "15", 10);
const TYPO_RATE = parseFloat(__ENV.TYPO_RATE || "0.03");
const RENEW_RATE = parseFloat(__ENV.RENEW_RATE || "1.2");
const COOKIE = "__Secure-vf_refresh";
const SESSIONS = ["renew", "storm", "mixed"].includes(SCENARIO) ? JSON.parse(open(__ENV.SESSIONS)) : [];

if (!PASSWORD && SCENARIO !== "renew" && SCENARIO !== "storm") throw new Error("Set LOAD_PASSWORD.");

export const signinTime = new Trend("signin_time", true); // first click to signed in, retries included
export const attemptTime = new Trend("attempt_time", true); // one POST /auth/login
export const signinTries = new Trend("signin_tries");
export const signedIn = new Rate("signed_in");
export const attempts = new Counter("attempts");
export const renewTime = new Trend("renew_time", true);
export const renewOk = new Rate("renew_ok");
export const lockedOut = new Counter("correct_password_429");
export const people = new Counter("people"); // sign-ins started

function stagesFrom(spec) {
  return spec.split(",").map((s) => {
    const [target, duration] = s.split(":");
    return { target: parseFloat(target), duration };
  });
}

// gracefulStop: everyone who started signing in is followed until they are in or give up (MAX_TRIES), so the
// signed_in rate counts every person, not only those who finished before the arrival window closed.
// Rates are per second and may be fractional (1.5): k6 wants whole numbers, so they are scheduled per minute.
const arrival = (rate, duration, exec) => ({
  executor: "constant-arrival-rate", rate: Math.round(rate * 60), timeUnit: "1m", duration, preAllocatedVUs: 200, maxVUs: 2000, exec,
  gracefulStop: "10m",
});
const allAtOnce = (vus, exec) => ({
  executor: "per-vu-iterations", vus, iterations: 1, maxDuration: "15m", gracefulStop: "1m", exec,
});

const SCENARIOS = {
  signin: { signin: arrival(RATE, DURATION, "signin") },
  nat: { nat: arrival(RATE, DURATION, "nat") },
  burst: { burst: allAtOnce(VUS, "signin") },
  storm: { storm: allAtOnce(VUS, "renew") },
  renew: {
    renew: {
      executor: "ramping-arrival-rate", startRate: 10, timeUnit: "1s", preAllocatedVUs: USERS, maxVUs: USERS,
      stages: stagesFrom(__ENV.STAGES || "50:30s,50:1m,100:30s,100:1m,200:30s,200:1m,400:30s,400:1m"), exec: "renew",
    },
  },
  mixed: {
    signin: arrival(RATE, DURATION, "signin"),
    renew: { ...arrival(RENEW_RATE, DURATION, "renew"), preAllocatedVUs: 50, maxVUs: 300 },
    jwks: arrival(2, DURATION, "jwks"),
  },
};

export const options = {
  insecureSkipTLSVerify: true, // Caddy's internal CA on a laptop run
  // k6 inside the compose network (load/README.md): BASE_URL keeps the site's hostname, CADDY_IP is where it lives.
  // Through Docker Desktop's port forwarding a thousand simultaneous connections stall for over a minute.
  hosts: __ENV.CADDY_IP ? { [BASE.replace(/^https?:\/\//, "")]: `${__ENV.CADDY_IP}:443` } : {},
  // k6 empties each VU's cookie jar after every iteration unless told not to; a renewing VU must keep the rotated
  // refresh cookie, or its next request replays the old token and, after the 30-second grace, revokes the session.
  noCookiesReset: true,
  scenarios: SCENARIOS[SCENARIO],
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max", "count"],
  thresholds: { http_req_failed: [{ threshold: "rate<1", abortOnFail: false }] },
};

const email = (n) => `load-${String(n).padStart(4, "0")}@load.vetfab.local`;
const next = () => (exec.scenario.iterationInTest % USERS) + 1;

// One person signing in: open the page, submit, press again after Retry-After while the service says busy.
function signInAs(n, password, track) {
  if (track) people.add(1);
  const jar = new http.CookieJar(); // a fresh browser: no refresh cookie, so the page is the form
  http.get(`${BASE}/auth/login?redirect=%2Flearn`, { jar, tags: { name: "GET /auth/login" } });
  const started = Date.now();
  for (let tries = 1; tries <= MAX_TRIES; tries++) {
    const res = http.post(
      `${BASE}/auth/login`,
      { email: email(n), password, redirect: "/learn" },
      {
        jar, redirects: 0, timeout: "60s", tags: { name: "POST /auth/login" },
        headers: { Origin: BASE, "Sec-Fetch-Site": "same-origin" },
      },
    );
    attempts.add(1, { status: String(res.status) });
    attemptTime.add(res.timings.duration, { status: String(res.status) });
    if (res.status === 503) {
      sleep(parseInt(res.headers["Retry-After"] || "2", 10));
      continue;
    }
    if (track) {
      const ok = res.status === 303 && (res.headers.Location || "").includes("#token=");
      signedIn.add(ok);
      if (ok) {
        signinTime.add(Date.now() - started);
        signinTries.add(tries);
      }
      check(res, { "signed in (303 with token)": () => ok });
    }
    return res.status;
  }
  if (track) signedIn.add(false);
  return 503;
}

export function signin() {
  signInAs(next(), PASSWORD, true);
}

export function nat() {
  const n = next();
  if (Math.random() < TYPO_RATE) signInAs(n, `${PASSWORD}x`, false); // a typo first
  const status = signInAs(n, PASSWORD, true);
  if (status === 429) lockedOut.add(1);
}

export function renew() {
  const session = SESSIONS[(exec.vu.idInTest - 1) % SESSIONS.length];
  const jar = http.cookieJar();
  if (!jar.cookiesForURL(`${BASE}/auth/session/token`)[COOKIE]) {
    jar.set(`${BASE}/auth/session/token`, COOKIE, session.refresh, { path: "/auth", secure: true });
  }
  const res = http.post(`${BASE}/auth/session/token`, null, {
    headers: { Origin: PRODUCT }, timeout: "60s", tags: { name: "POST /auth/session/token" },
  });
  const ok = res.status === 200 && res.json("access_token") !== undefined;
  renewOk.add(ok);
  renewTime.add(res.timings.duration);
  check(res, { "renewed (200 with token)": () => ok });
}

export function jwks() {
  const res = http.get(`${BASE}/auth/.well-known/jwks.json`, { tags: { name: "GET jwks" } });
  check(res, { "jwks 200": (r) => r.status === 200 });
}
