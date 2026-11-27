'use strict';

// The idle sign-out logic of static/idle-session.js (#149), driven with a fake clock. The page
// wiring below the logic is covered by the browser journey in
// scripts/patient-portal-session-playwright-checks.js.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.join(__dirname, '../carlos_patient_portal/static/idle-session.js'),
  'utf8',
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: 'idle-session.js' });
const { createIdleSession, warningLeadSeconds, activityThrottleMs, hiddenBlankMs } = sandbox.CarlosIdleSession;

const settle = async () => {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
  }
};

// A page with a fake clock. `advance` moves both clocks (as time does), running due timers in
// order; `sleep` moves only the wall clock (a computer that slept: timers did not run).
function pageWith({ remainingSeconds, limitSeconds }) {
  const clock = { page: 1000, wall: 1_700_000_000_000 };
  const timers = [];
  let nextId = 1;
  const events = [];
  const answers = [];
  const requests = [];
  const env = {
    now: () => ({ page: clock.page, wall: clock.wall }),
    setTimer: (callback, ms) => {
      const id = nextId;
      nextId += 1;
      timers.push({ id, due: clock.page + ms, callback });
      return id;
    },
    clearTimer: (id) => {
      const index = timers.findIndex((timer) => timer.id === id);
      if (index >= 0) {
        timers.splice(index, 1);
      }
    },
    keepalive: () => {
      requests.push(clock.page);
      return Promise.resolve(answers.shift() ?? { status: 200, remainingSeconds: limitSeconds });
    },
    ui: {
      showWarning: (seconds) => events.push(['warn', seconds]),
      hideWarning: () => events.push(['unwarn']),
      blank: () => events.push(['blank']),
      leave: (idle) => events.push(['leave', idle]),
      reload: () => events.push(['reload']),
      // Round-tripped: the script ran in its own realm, and strict equality compares prototypes.
      broadcast: (message) => events.push(['broadcast', JSON.parse(JSON.stringify(message))]),
    },
  };
  const session = createIdleSession({ remainingSeconds, limitSeconds }, env);
  const advance = (ms) => {
    const target = clock.page + ms;
    for (;;) {
      timers.sort((a, b) => a.due - b.due);
      const next = timers[0];
      if (!next || next.due > target) {
        break;
      }
      timers.shift();
      clock.wall += next.due - clock.page;
      clock.page = next.due;
      next.callback();
    }
    clock.wall += target - clock.page;
    clock.page = target;
  };
  const names = () => events.map((event) => event[0]);
  return {
    session,
    advance,
    sleep: (ms) => {
      clock.wall += ms;
    },
    events,
    answers,
    requests,
    names,
  };
}

test('the warning opens 60 seconds before the limit, and not before', () => {
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.advance(538_000);
  assert.deepEqual(page.names(), []);
  page.advance(3_000); // 59 s left
  assert.deepEqual(page.events[0], ['warn', 60]);
  // The countdown is coarse: steps of ten seconds, not every second.
  page.advance(10_000);
  assert.deepEqual(page.events.filter((event) => event[0] === 'warn').map((e) => e[1]), [60, 50]);
});

test('a limit under three minutes warns a third before the end', () => {
  assert.equal(warningLeadSeconds(600), 60);
  assert.equal(warningLeadSeconds(180), 60);
  assert.equal(warningLeadSeconds(179), 59);
  assert.equal(warningLeadSeconds(60), 20);
  const page = pageWith({ remainingSeconds: 60, limitSeconds: 60 });
  page.session.start();
  page.advance(39_000);
  assert.deepEqual(page.names(), []);
  page.advance(2_000);
  assert.deepEqual(page.events[0], ['warn', 20]);
});

test('at the limit the page is blanked, the other tabs are told, and it leaves for the idle sign-in', () => {
  const page = pageWith({ remainingSeconds: 60, limitSeconds: 60 });
  page.session.start();
  page.advance(61_000);
  assert.deepEqual(page.events.slice(-3), [
    ['broadcast', { type: 'ended', reason: 'idle' }],
    ['blank'],
    ['leave', true],
  ]);
  assert.equal(page.session.state().ended, true);
  // Nothing more happens once it has ended.
  page.advance(120_000);
  assert.equal(page.events.filter((event) => event[0] === 'leave').length, 1);
});

test('activity sends at most one keep-alive per throttle interval, and none at once after loading', async () => {
  assert.equal(activityThrottleMs(600), 60_000);
  assert.equal(activityThrottleMs(60), 10_000);
  assert.equal(activityThrottleMs(24 * 60 * 60), 60_000);
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.advance(1_000);
  page.session.noteActivity();
  assert.equal(page.requests.length, 0);
  page.advance(60_000);
  page.session.noteActivity();
  page.session.noteActivity();
  assert.equal(page.requests.length, 1);
  await settle();
  // Right after an answer the next one waits for the interval again.
  page.session.noteActivity();
  assert.equal(page.requests.length, 1);
  page.advance(60_000);
  page.session.noteActivity();
  assert.equal(page.requests.length, 2);
});

test('an answer restarts the countdown and closes the warning', async () => {
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.advance(545_000);
  assert.ok(page.names().includes('warn'));
  page.answers.push({ status: 200, remainingSeconds: 600 });
  const stayed = page.session.stay();
  await stayed;
  assert.equal(page.requests.length, 1);
  assert.deepEqual(page.events.slice(-2), [
    ['broadcast', { type: 'extended', remainingSeconds: 600 }],
    ['unwarn'],
  ]);
  assert.ok(page.session.state().remainingMs > 595_000);
  assert.equal(page.session.state().warningSeconds, null);
});

test('Stay signed in asks at once, whatever the activity throttle says', async () => {
  const page = pageWith({ remainingSeconds: 60, limitSeconds: 60 });
  page.session.start();
  page.advance(45_000);
  page.session.noteActivity(); // 45 s after loading, past the 10 s interval: sent
  await settle();
  const before = page.requests.length;
  await page.session.stay();
  assert.equal(page.requests.length, before + 1);
});

test("the page's own answer may be shorter than what it holds (the server is the authority)", async () => {
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.advance(61_000);
  page.answers.push({ status: 200, remainingSeconds: 30 });
  page.session.noteActivity();
  await settle();
  assert.ok(page.session.state().remainingMs <= 30_000);
  assert.deepEqual(page.events.find((event) => event[0] === 'warn'), ['warn', 30]);
});

test("another tab's message moves the deadline later only", () => {
  const page = pageWith({ remainingSeconds: 300, limitSeconds: 600 });
  page.session.start();
  page.session.receive({ type: 'extended', remainingSeconds: 100 });
  assert.ok(page.session.state().remainingMs > 290_000);
  page.session.receive({ type: 'extended', remainingSeconds: 900 });
  assert.ok(page.session.state().remainingMs > 890_000);
  // Nonsense is ignored.
  page.session.receive({ type: 'extended', remainingSeconds: -5 });
  page.session.receive({ type: 'extended', remainingSeconds: 'soon' });
  page.session.receive(undefined);
  page.session.receive({ type: 'other' });
  assert.ok(page.session.state().remainingMs > 890_000);
});

test('a sign-out in another tab, or an idle end there, takes this page away too', () => {
  const out = pageWith({ remainingSeconds: 300, limitSeconds: 600 });
  out.session.start();
  out.session.receive('ended');
  assert.deepEqual(out.events.slice(-2), [['blank'], ['leave', false]]);
  const idle = pageWith({ remainingSeconds: 300, limitSeconds: 600 });
  idle.session.start();
  idle.session.receive({ type: 'ended', reason: 'idle' });
  assert.deepEqual(idle.events.slice(-2), [['blank'], ['leave', true]]);
  // An ended page does not announce it again.
  assert.equal(idle.events.filter((event) => event[0] === 'broadcast').length, 0);
});

test('a refused keep-alive ends the page; a stale form token stops asking and Stay reloads', async () => {
  const expired = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  expired.session.start();
  expired.advance(61_000);
  expired.answers.push({ status: 401 });
  expired.session.noteActivity();
  await settle();
  assert.deepEqual(expired.events.slice(-1), [['leave', true]]);

  const stale = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  stale.session.start();
  stale.advance(61_000);
  stale.answers.push({ status: 403 });
  stale.session.noteActivity();
  await settle();
  assert.equal(stale.session.state().stale, true);
  stale.advance(61_000);
  stale.session.noteActivity();
  assert.equal(stale.requests.length, 1);
  await stale.session.stay();
  assert.deepEqual(stale.events.slice(-1), [['reload']]);
  // And a network failure is no answer at all: asking again is allowed.
  const offline = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  offline.session.start();
  offline.advance(61_000);
  offline.answers.push(Promise.reject(new Error('offline')));
  offline.session.noteActivity();
  await settle();
  assert.equal(offline.session.state().inFlight, false);
});

test('a computer that slept past the limit leaves when the page wakes, and a clock set back gives nothing', () => {
  const slept = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  slept.session.start();
  slept.advance(10_000);
  slept.sleep(700_000); // the wall clock went on; the page clock did not
  slept.session.check();
  assert.deepEqual(slept.events.slice(-1), [['leave', true]]);

  const setBack = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  setBack.session.start();
  setBack.advance(100_000);
  setBack.sleep(-3_600_000); // a patient sets the clock back an hour
  assert.ok(setBack.session.state().remainingMs <= 500_000);
});

test('a page hidden for the limit is blanked, and reloaded (not shown again) on return', () => {
  assert.equal(hiddenBlankMs(600), 120_000);
  assert.equal(hiddenBlankMs(60), 30_000);
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.session.hidden();
  page.advance(119_000);
  assert.deepEqual(page.names(), []);
  page.advance(2_000);
  assert.deepEqual(page.events.slice(-1), [['blank']]);
  page.session.visible();
  assert.deepEqual(page.events.slice(-1), [['reload']]);
  // While blanked, activity sends nothing.
  assert.equal(page.requests.length, 0);
  page.session.noteActivity();
  assert.equal(page.requests.length, 0);
});

test('a short look at another tab does not blank the page', () => {
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.session.hidden();
  page.advance(30_000);
  page.session.visible();
  assert.deepEqual(page.names(), []);
  assert.equal(page.session.state().blanked, false);
});

test('a hidden page that comes back after the limit leaves rather than reloads', () => {
  const page = pageWith({ remainingSeconds: 60, limitSeconds: 60 });
  page.session.start();
  page.session.hidden();
  page.advance(31_000); // blanked
  page.sleep(60_000); // and the computer slept
  page.session.visible();
  assert.deepEqual(page.events.slice(-1), [['leave', true]]);
  assert.equal(page.events.filter((event) => event[0] === 'reload').length, 0);
});

test('the warning closes by itself when another tab extends the session', () => {
  const page = pageWith({ remainingSeconds: 600, limitSeconds: 600 });
  page.session.start();
  page.advance(550_000);
  assert.ok(page.names().includes('warn'));
  page.session.receive({ type: 'extended', remainingSeconds: 600 });
  assert.deepEqual(page.events.slice(-1), [['unwarn']]);
});
