'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createRequire } = require('node:module');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = path.join(__dirname, '../scripts/patient-portal-session-playwright-checks.js');
const source = fs.readFileSync(script, 'utf8');
const scriptRequire = createRequire(script);

async function bootstrap(limit, maintenance = false) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-session-preflight-'));
  const fixture = path.join(directory, 'fixture.json');
  const payload = {
    settings: { defaultLocale: 'en', localeCookieName: 'FAKE-locale' },
    locales: ['en', 'fr', 'es', 'pl', 'pt-BR'].map((code) => ({ code, text: {} })),
    text: {},
  };
  if (!maintenance) {
    payload.settings.authRateLimitMaxRequests = limit;
    payload.settings.idleTimeoutSeconds = 60;
    payload.accounts = Object.fromEntries(['sms', 'phone', 'locale', 'throttle', 'idle', 'warning'].map(
      (role) => [role, {
        username: `FAKE-${role}`, password: 'FAKE-preflight-only', email: `${role}@example.test`,
        phone: '+15555550141',
      }],
    ));
    payload.newPhone = '+15555550142';
  }
  fs.writeFileSync(fixture, JSON.stringify(payload), { mode: 0o600 });
  const env = { PORTAL_SESSION_FIXTURE_FILE: fixture, PORTAL_BASE_URL: 'http://127.0.0.1:8495' };
  if (maintenance) env.PORTAL_SESSION_STEPS = 'maintenance';
  else {
    env.PORTAL_USE_DEVELOPMENT_MFA_CODE = 'true';
    env.PORTAL_SMS_CAPTURE_FILE = path.join(directory, 'unused-sms.jsonl');
  }
  let launches = 0;
  let error = null;
  const sandbox = {
    URL,
    process: { env, exit: () => {} },
    console: { error: () => {} },
    require: (name) => name === 'playwright' ? {
      chromium: { launch: async () => {
        launches += 1;
        throw new Error('Preflight accepted; stop before Chromium or any patient flow');
      } },
    } : scriptRequire(name),
  };
  try {
    try { vm.runInNewContext(source, sandbox, { filename: script }); }
    catch (caught) { error = caught.message; }
    await new Promise((resolve) => setImmediate(resolve));
    return { launches, error };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

// The steps before the throttle step include both idle sign-out journeys and make 15 sign-ins.
for (const limit of [14, 15]) {
  test(`full session preflight refuses a ${limit}-request budget before launching Chromium`, async () => {
    const observed = await bootstrap(limit);
    assert.equal(observed.launches, 0);
    assert.match(observed.error, /must exceed the 15 sign-ins/);
  });
}

test('a 16-request budget passes real preflight', async () => {
  assert.deepEqual(await bootstrap(16), { launches: 1, error: null });
});

test('maintenance preflight still needs no account, MFA, SMS or login budget', async () => {
  assert.deepEqual(await bootstrap(undefined, true), { launches: 1, error: null });
});
