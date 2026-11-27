// The signed-in page's idle sign-out (#149).
//
// The server ends a session after the idle limit and stays the authority: any request after that
// gets 401. This script is the patient's end of it: a warning 60 seconds before the limit, a
// keep-alive while the patient is really using the page, and a page that is blanked (and left)
// when the time is up, so that records do not stay on a screen nobody is at.
//
//  - The page is given how long is left as a number of SECONDS (data-idle-remaining-seconds, and
//    each keep-alive answer), never a time: the countdown runs on the page's own clocks, so a
//    patient's clock cannot make it wrong. Two clocks are kept (performance.now, which cannot be
//    set back, and the wall clock, which keeps counting while a computer sleeps) and the smaller
//    remainder counts.
//  - Any activity (pointer, key, scroll, touch) sends a keep-alive POST, at most one per
//    `activityThrottleMs`; the server writes the idle clock at most once per 10 seconds. The
//    session's absolute lifetime is never extended by any of it; the server's answer already
//    holds the smaller of the two limits.
//  - A tab only moves its deadline LATER from another tab's message (the other tab got a server
//    answer for it); a deadline from this tab's own answer replaces it, even if shorter.
//  - A page hidden for `hiddenBlankMs` is blanked, and reloaded when it comes back.
//  - Pure logic (`createIdleSession`) is separate from the page wiring below it so it is tested
//    with a fake clock (tests/idle-session.test.js); the browser journey is in
//    scripts/patient-portal-session-playwright-checks.js.
"use strict";

(() => {
  const WARNING_LEAD_SECONDS = 60;
  const HIDDEN_BLANK_SECONDS = 120;
  const COUNTDOWN_STEP_SECONDS = 10;
  const MAX_TICK_MS = 30 * 1000;

  // 60 seconds before the limit; for a limit under three minutes (the setting allows 60 seconds)
  // a third of it, so the warning never opens the moment the page does.
  const warningLeadSeconds = (limitSeconds) => (
    limitSeconds < 3 * WARNING_LEAD_SECONDS
      ? Math.max(1, Math.floor(limitSeconds / 3))
      : WARNING_LEAD_SECONDS
  );
  // At most one keep-alive per minute (a sixth of a short limit, never under the server's 10 s).
  const activityThrottleMs = (limitSeconds) => Math.min(
    60 * 1000,
    Math.max(10 * 1000, Math.round((limitSeconds * 1000) / 6)),
  );
  const hiddenBlankMs = (limitSeconds) => (
    Math.min(HIDDEN_BLANK_SECONDS, Math.max(5, Math.floor(limitSeconds / 2))) * 1000
  );

  // `env.now()` gives {page, wall} in milliseconds; `env.setTimer/clearTimer` are setTimeout's;
  // `env.keepalive()` resolves {status, remainingSeconds?}; `env.ui` is what the page does.
  const createIdleSession = (config, env) => {
    const limitSeconds = config.limitSeconds;
    const throttleMs = activityThrottleMs(limitSeconds);
    const blankAfterMs = hiddenBlankMs(limitSeconds);
    const leadMs = warningLeadSeconds(limitSeconds) * 1000;
    let deadline = null;
    let lastKeepalivePage = 0;
    let inFlight = false;
    let warningSeconds = null;
    let blanked = false;
    let ended = false;
    let stale = false;
    let tickTimer = null;
    let hiddenTimer = null;
    let hiddenSince = null;

    const remainingMs = () => {
      const now = env.now();
      return Math.min(deadline.page - now.page, deadline.wall - now.wall);
    };
    // Sets the deadline `seconds` from now. With `onlyLater` it is ignored unless it is further
    // away than the one held (what another tab may say); returns whether it was taken.
    const setFromSeconds = (seconds, onlyLater) => {
      if (!Number.isFinite(seconds) || seconds < 0) {
        return false;
      }
      if (onlyLater && deadline !== null && seconds * 1000 <= remainingMs()) {
        return false;
      }
      const now = env.now();
      deadline = { page: now.page + seconds * 1000, wall: now.wall + seconds * 1000 };
      return true;
    };
    const clearTick = () => {
      if (tickTimer !== null) {
        env.clearTimer(tickTimer);
        tickTimer = null;
      }
    };
    const finish = (idle) => {
      ended = true;
      clearTick();
      if (hiddenTimer !== null) {
        env.clearTimer(hiddenTimer);
        hiddenTimer = null;
      }
      env.ui.blank();
      env.ui.leave(idle);
    };
    const end = () => {
      if (ended) {
        return;
      }
      env.ui.broadcast({ type: "ended", reason: "idle" });
      finish(true);
    };
    const tick = () => {
      clearTick();
      if (ended) {
        return;
      }
      const remaining = remainingMs();
      if (remaining <= 0) {
        end();
        return;
      }
      if (remaining <= leadMs) {
        // A coarse countdown (steps of ten), so that it is not read out every second.
        const shown = Math.max(
          COUNTDOWN_STEP_SECONDS,
          Math.ceil(remaining / 1000 / COUNTDOWN_STEP_SECONDS) * COUNTDOWN_STEP_SECONDS,
        );
        if (shown !== warningSeconds) {
          warningSeconds = shown;
          env.ui.showWarning(shown);
        }
        tickTimer = env.setTimer(tick, Math.min(1000, remaining));
        return;
      }
      if (warningSeconds !== null) {
        warningSeconds = null;
        env.ui.hideWarning();
      }
      tickTimer = env.setTimer(tick, Math.min(remaining - leadMs + 5, MAX_TICK_MS));
    };
    const sendKeepalive = (forced) => {
      if (inFlight || ended) {
        return Promise.resolve();
      }
      inFlight = true;
      lastKeepalivePage = env.now().page;
      return env
        .keepalive()
        .then((answer) => {
          inFlight = false;
          if (ended) {
            return;
          }
          if (answer.status === 200 && Number.isFinite(answer.remainingSeconds)) {
            // The server is the authority for this tab's own answer, longer or shorter.
            setFromSeconds(answer.remainingSeconds, false);
            env.ui.broadcast({ type: "extended", remainingSeconds: answer.remainingSeconds });
            tick();
          } else if (answer.status === 401) {
            end();
          } else if (answer.status === 403) {
            // A newer page of this browser took the form token this page holds. Activity stops
            // asking; "Stay signed in" reloads the page (which is itself a request) to get one.
            stale = true;
            if (forced) {
              env.ui.reload();
            }
          }
        })
        .catch(() => {
          inFlight = false;
        });
    };

    return {
      start() {
        lastKeepalivePage = env.now().page;
        setFromSeconds(config.remainingSeconds, false);
        tick();
      },
      noteActivity() {
        if (ended || blanked || stale || inFlight) {
          return;
        }
        if (env.now().page - lastKeepalivePage < throttleMs) {
          return;
        }
        void sendKeepalive(false);
      },
      stay() {
        if (stale) {
          env.ui.reload();
          return Promise.resolve();
        }
        return sendKeepalive(true);
      },
      receive(message) {
        if (ended || message === undefined || message === null) {
          return;
        }
        if (message === "ended") {
          // Signed out in another tab: this page leaves too.
          finish(false);
        } else if (message.type === "ended") {
          finish(message.reason === "idle");
        } else if (message.type === "extended") {
          if (setFromSeconds(message.remainingSeconds, true)) {
            tick();
          }
        }
      },
      hidden() {
        if (ended) {
          return;
        }
        if (hiddenTimer !== null) {
          env.clearTimer(hiddenTimer);
        }
        if (hiddenSince === null) {
          hiddenSince = env.now();
        }
        hiddenTimer = env.setTimer(() => {
          hiddenTimer = null;
          blanked = true;
          env.ui.blank();
        }, blankAfterMs);
      },
      visible() {
        if (hiddenTimer !== null) {
          env.clearTimer(hiddenTimer);
          hiddenTimer = null;
        }
        if (ended) {
          return;
        }
        const now = env.now();
        const away = hiddenSince === null
          ? 0
          : Math.max(now.page - hiddenSince.page, now.wall - hiddenSince.wall);
        hiddenSince = null;
        if (blanked || away >= blankAfterMs) {
          // Nothing blanked is shown again as it was: a page that is still signed in is
          // fetched afresh, and one that is not goes to the sign-in page.
          if (remainingMs() <= 0) {
            end();
          } else {
            env.ui.reload();
          }
          return;
        }
        tick();
      },
      check() {
        tick();
      },
      state: () => ({
        remainingMs: deadline === null ? null : remainingMs(),
        warningSeconds,
        blanked,
        ended,
        stale,
        inFlight,
      }),
    };
  };

  const api = {
    createIdleSession,
    warningLeadSeconds,
    activityThrottleMs,
    hiddenBlankMs,
  };
  globalThis.CarlosIdleSession = api;

  // ---- The page -------------------------------------------------------------------------
  if (typeof document === "undefined" || !document.body || !document.body.dataset) {
    return;
  }
  const data = document.body.dataset;
  const remainingSeconds = Number(data.idleRemainingSeconds);
  const limitSeconds = Number(data.idleLimitSeconds);
  if (
    !data.idleKeepaliveUrl
    || !Number.isFinite(remainingSeconds)
    || !Number.isFinite(limitSeconds)
    || limitSeconds <= 0
  ) {
    return;
  }
  const shell = document.querySelector(".app-shell");
  const dialog = document.getElementById("portal-idle-warning");
  const dialogBody = document.getElementById("portal-idle-body");
  const stayButton = dialog ? dialog.querySelector("[data-idle-stay]") : null;
  const bodyTemplate = dialog
    ? (dialog.querySelector("[data-idle-body-template]") || dialog).dataset.idleBodyTemplate || ""
    : "";
  const signedOutUrl = data.idleSignedOutUrl || "/";
  const signInUrl = signedOutUrl.split("?")[0] || "/";
  const csrfToken = data.idleCsrfToken || "";
  // The channel portal.js already opened (a classic script's top-level const is visible here),
  // not a second one: a channel does not hear its own posts, but another channel object of the
  // same page does, and this page's own sign-out ("ended") would then make it leave while its
  // logout form was still being sent.
  const channel = typeof sessionChannel !== "undefined" && sessionChannel
    ? sessionChannel
    : (typeof BroadcastChannel === "function" ? new BroadcastChannel("carlos-portal-session") : null);
  let focusBeforeWarning = null;

  const ui = {
    showWarning(seconds) {
      if (!dialog || !dialogBody) {
        return;
      }
      if (dialog.hidden) {
        focusBeforeWarning = document.activeElement;
        dialog.hidden = false;
        if (shell) {
          shell.inert = true;
        }
        if (stayButton) {
          stayButton.focus();
        }
      }
      dialogBody.textContent = bodyTemplate.replace("{seconds}", String(seconds));
    },
    hideWarning() {
      if (!dialog || dialog.hidden) {
        return;
      }
      dialog.hidden = true;
      if (shell) {
        shell.inert = false;
      }
      if (focusBeforeWarning instanceof HTMLElement) {
        focusBeforeWarning.focus();
      }
      focusBeforeWarning = null;
    },
    // Nothing of the signed-in page stays visible. The page is also left or reloaded by the
    // caller; this is for the moment between, and for a page that is hidden.
    blank() {
      if (dialog) {
        dialog.hidden = true;
      }
      if (shell) {
        shell.inert = true;
        shell.style.setProperty("display", "none");
      }
      document.body.setAttribute("data-idle-blank", "");
    },
    // `replace`, not `assign`: Back must not return to the page of records.
    leave(idle) {
      window.location.replace(idle ? signedOutUrl : signInUrl);
    },
    reload() {
      window.location.reload();
    },
    broadcast(message) {
      if (channel) {
        channel.postMessage(message);
      }
    },
  };
  const env = {
    now: () => ({ page: performance.now(), wall: Date.now() }),
    setTimer: (callback, ms) => window.setTimeout(callback, ms),
    clearTimer: (id) => window.clearTimeout(id),
    keepalive: () => fetch(data.idleKeepaliveUrl, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf_token: csrfToken }).toString(),
    }).then(async (response) => {
      let remaining;
      if (response.ok) {
        try {
          remaining = (await response.json()).remaining_seconds;
        } catch {
          remaining = undefined;
        }
      }
      return { status: response.status, remainingSeconds: remaining };
    }),
    ui,
  };
  const session = createIdleSession({ remainingSeconds, limitSeconds }, env);
  // Exposed so that the browser journey can read the state; it carries no patient data.
  globalThis.carlosIdleSession = session;

  for (const type of ["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "scroll"]) {
    document.addEventListener(type, () => session.noteActivity(), { capture: true, passive: true });
  }
  if (stayButton) {
    stayButton.addEventListener("click", () => {
      void session.stay();
    });
  }
  if (dialog) {
    dialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        // Escape is "Stay signed in", the safe answer.
        event.preventDefault();
        void session.stay();
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const focusable = [...dialog.querySelectorAll("button:not([disabled])")];
      if (focusable.length === 0) {
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }
  if (channel) {
    channel.addEventListener("message", (message) => session.receive(message.data));
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      session.hidden();
    } else {
      session.visible();
    }
  });
  // A sleeping computer stops timers; coming back to the page re-checks both clocks at once.
  window.addEventListener("focus", () => session.check());
  window.addEventListener("pageshow", () => session.check());
  session.start();
})();
