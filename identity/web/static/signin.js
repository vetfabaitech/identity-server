// Automatic retry when sign-in is busy (load test 2026-10-26, finding 2).
//
// The service answers a sign-in it cannot take within its queue wait with 503 and a Retry-After header, and the
// form page asks the person to try again. During a burst (a class signing in together) that meant pressing the
// button a dozen times. This script submits the form itself, waits out Retry-After (with a growing margin and
// some jitter, so a thousand pages do not retry in the same instant) and tries again, within a budget the form
// states in data-retry-budget-seconds. It never retries anything but 503: a wrong password, a refused request or
// a limit is shown as the page the service answered with. The password stays in the form field; nothing is stored.
// Without JavaScript (or without fetch) the form works exactly as before.
(function () {
  "use strict";
  var form = document.querySelector("form[data-retry-budget-seconds]");
  if (!form || !window.fetch || !window.URLSearchParams) return;
  var budgetMs = Number(form.dataset.retryBudgetSeconds) * 1000;
  var button = form.querySelector("button[type=submit]");
  var notice = form.querySelector(".notice");
  var busy = false;

  function say(text) {
    if (!notice) return;
    notice.textContent = text;
    notice.hidden = !text;
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  // The page the service answered with (wrong password, refused, too many attempts, still busy) replaces this one,
  // so the person sees exactly what a plain submit would have shown, without a second password check.
  function show(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function handoff() {
    // Signed in: the response set the refresh cookie. A GET of the sign-in page with the same redirect and state is
    // the silent sign-in, which sends the person on to the product with a token, exactly as the 303 would have.
    var params = new URLSearchParams();
    params.set("redirect", form.elements.redirect.value);
    if (form.elements.state.value) params.set("state", form.elements.state.value);
    window.location.assign(form.action + "?" + params.toString());
  }

  form.addEventListener("submit", function (event) {
    if (busy) { event.preventDefault(); return; }
    event.preventDefault();
    busy = true;
    if (button) button.disabled = true;
    var started = Date.now();
    var attempt = 0;

    function finish(text) {
      busy = false;
      if (button) button.disabled = false;
      say(text);
    }

    function once() {
      attempt += 1;
      return fetch(form.action, {
        method: "POST",
        body: new URLSearchParams(new FormData(form)),
        credentials: "same-origin",
        redirect: "manual",
        headers: { Accept: "text/html" },
      }).then(function (response) {
        if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
          handoff();
          return;
        }
        if (response.status !== 503) {
          return response.text().then(show);
        }
        var retryAfter = Number(response.headers.get("Retry-After")) || 2;
        // Retry-After plus a margin that grows with each attempt (up to double) and up to a second of jitter.
        var wait = retryAfter * 1000 * (1 + Math.min(attempt, 4) * 0.25) + Math.random() * 1000;
        if (Date.now() - started + wait > budgetMs) {
          finish("Sign-in is still busy. Please try again in a minute.");
          return;
        }
        say("High traffic right now. Signing you in automatically\u2026");
        return sleep(wait).then(once);
      }, function () {
        // The network, not the service: let the browser submit the form itself.
        busy = false;
        form.submit();
      });
    }

    once();
  });
})();
