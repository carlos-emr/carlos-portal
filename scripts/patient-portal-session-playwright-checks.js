#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Live browser checks for the sign-in and session flows that scripts/patient-portal-playwright-checks.js
 * and scripts/patient-portal-account-playwright-checks.js do not drive:
 *
 *   1. Signing in with a code sent by SMS: the code arrives at the clinic's SMS webhook (a
 *      capture-only receiver here, scripts/patient-portal-sms-capture.js), a wrong code is refused,
 *      the right one signs in; Resend inside the cooldown is refused, after it a NEW code arrives
 *      and the old one no longer works. The same resend proof for the email method.
 *   2. Changing the phone number: the number is confirmed by a code sent by SMS to the new number
 *      (wrong code refused, Resend gives a second code, the first is then refused), and once
 *      confirmed SMS can be chosen as the sign-in method.
 *   3. The signed-in pages in every locale the portal defines: sign-in, code page, dashboard,
 *      account, messages and help render that locale's catalog (html lang, headings, navigation,
 *      status text), nothing overflows at phone width, and logout returns to the localized sign-in.
 *   4. The notice pages a browser gets instead of JSON: an unknown route, a form posted with a
 *      stale CSRF token, and the sign-in throttle (429 with Retry-After).
 *   5. Idle session expiry: a session alive halfway through the limit ends once the limit has
 *      passed with no request, and the old cookie is then dead.
 *
 * Separate script, own seed (tests/seed_browser_session.py) and fixture file; it never touches the
 * fixtures or steps of scripts/patient-portal-playwright-checks.js.
 * The helpers between readFixtures and assertNoHorizontalOverflow are the ones that script and
 * scripts/patient-portal-account-playwright-checks.js use, copied so the three scripts stay
 * independent.
 *
 * Run recipe. The throttle and the idle expiry are stateful, so every run needs a fresh database.
 * From the repository root:
 *
 *   export PORTAL_SESSION_CHECK_DIR="$(mktemp -d)"
 *   new_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
 *   export PATIENT_PORTAL_ENVIRONMENT=development
 *   export PATIENT_PORTAL_DATABASE_URL="sqlite+pysqlite:///$PORTAL_SESSION_CHECK_DIR/portal.db"
 *   export PATIENT_PORTAL_IDENTITY_PROOF_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_AUDIT_HASH_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_SESSION_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_UNLOCK_SECRET_ENCRYPTION_SECRET="$(new_secret)"
 *   # The SMS capture: the portal posts codes here; the token is shared with the receiver only.
 *   export PATIENT_PORTAL_SMS_WEBHOOK_TOKEN="$(new_secret)"
 *   export PATIENT_PORTAL_SMS_WEBHOOK_URL=http://127.0.0.1:8496/sms
 *   export PORTAL_SMS_CAPTURE_FILE="$PORTAL_SESSION_CHECK_DIR/sms.jsonl"
 *   # Short waits so the check finishes in minutes: the resend cooldowns, the idle limit (its
 *   # minimum), and a sign-in budget the throttle step can exhaust on purpose at the end.
 *   export PATIENT_PORTAL_MFA_EMAIL_RESEND_COOLDOWN_SECONDS=30
 *   export PATIENT_PORTAL_MFA_SMS_RESEND_COOLDOWN_SECONDS=60
 *   export PATIENT_PORTAL_SESSION_IDLE_TIMEOUT_SECONDS=60
 *   export PATIENT_PORTAL_AUTH_RATE_LIMIT_MAX_REQUESTS=30
 *   export PATIENT_PORTAL_AUTH_RATE_LIMIT_WINDOW_SECONDS=60
 *   export PYTHONPATH=.
 *   export PORTAL_BASE_URL=http://127.0.0.1:8495
 *   export PORTAL_SESSION_FIXTURE_FILE="$PORTAL_SESSION_CHECK_DIR/session-fixtures.json"
 *   export PORTAL_USE_DEVELOPMENT_MFA_CODE=true
 *   export PORTAL_SCREENSHOT_DIR="$PORTAL_SESSION_CHECK_DIR/screenshots"
 *   node scripts/patient-portal-sms-capture.js --serve --port 8496 --file "$PORTAL_SMS_CAPTURE_FILE" &
 *   python -m alembic -c alembic.ini upgrade head
 *   python tests/seed_browser_session.py
 *   python -m uvicorn carlos_patient_portal.main:create_app --factory --host 127.0.0.1 --port 8495 &
 *   npm run test:patient-portal-session-playwright
 *
 * PORTAL_SESSION_STEPS=locales (or any comma list of sms,phone,locales,idle,notices) runs a subset.
 *
 * Every 4xx the check provokes is declared before it happens; any other 4xx/5xx fails the run.
 */
'use strict';

const { randomBytes } = require('node:crypto');
const { mkdirSync, readFileSync, statSync } = require('node:fs');
const { isIP } = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { readCapturedSmsCode, readCaptures } = require('./patient-portal-sms-capture');

const baseUrl = validateBaseUrl(process.env.PORTAL_BASE_URL || 'http://127.0.0.1:8495');
const fixturePath = process.env.PORTAL_SESSION_FIXTURE_FILE
  || path.join(os.tmpdir(), 'patient-portal-session-fixtures.json');
const useDevelopmentMfaCode = process.env.PORTAL_USE_DEVELOPMENT_MFA_CODE === 'true';
const smsCaptureFile = process.env.PORTAL_SMS_CAPTURE_FILE || '';
const screenshotDir = path.resolve(process.env.PORTAL_SCREENSHOT_DIR || os.tmpdir());
const chromePath = process.env.PORTAL_CHROME_PATH || process.env.CHROME_PATH || '';
// PORTAL_SESSION_STEPS=sms,phone,locales,idle,notices runs only those steps (default: all).
const STEP_NAMES = ['sms', 'phone', 'locales', 'idle', 'notices'];
const selectedSteps = (process.env.PORTAL_SESSION_STEPS || '').split(',').map((name) => name.trim()).filter(Boolean);

const fixtures = readFixtures(fixturePath);
const settings = fixtures.settings;
const accounts = fixtures.accounts;
const locales = fixtures.locales;

assert(useDevelopmentMfaCode, 'this check reads email codes from the page: set PORTAL_USE_DEVELOPMENT_MFA_CODE=true');
assert(smsCaptureFile, 'PORTAL_SMS_CAPTURE_FILE must name the SMS capture file');
for (const role of ['sms', 'phone', 'locale', 'throttle', 'idle']) {
  assert(accounts[role] && accounts[role].username && accounts[role].password && accounts[role].email,
    `${role} account fixture is incomplete in ${fixturePath}`);
}
assert(accounts.sms.phone && fixtures.newPhone, 'the SMS account needs a phone number and the fixture a new one');
assert(Array.isArray(locales) && locales.length >= 2 && locales.some((locale) => locale.code === settings.defaultLocale),
  'the fixture must list the portal locales including the default');
for (const name of selectedSteps) {
  assert(STEP_NAMES.includes(name), `PORTAL_SESSION_STEPS names an unknown step ${name}; known: ${STEP_NAMES.join(', ')}`);
}
const runs = (name) => selectedSteps.length === 0 || selectedSteps.includes(name);
// The sign-in budget is one bucket per client: every POST /auth/login of this run counts. The
// steps below spend at most this many before the throttle step empties the bucket on purpose.
const plannedSignInRequests = 1 + 1 + 2 + (locales.length - 1) + 1 + 1;
assert(settings.authRateLimitMaxRequests > plannedSignInRequests,
  `PATIENT_PORTAL_AUTH_RATE_LIMIT_MAX_REQUESTS is ${settings.authRateLimitMaxRequests}; it must exceed the `
    + `${plannedSignInRequests} sign-ins the steps before the throttle step make (the recipe uses 30)`);
assert(settings.idleTimeoutSeconds <= 120,
  `PATIENT_PORTAL_SESSION_IDLE_TIMEOUT_SECONDS is ${settings.idleTimeoutSeconds}; the idle step waits it out, keep it at the 60 s minimum`);

function readFixtures(filePath) {
  // The fixture holds generated test passwords and a one-time confirmation token.
  const mode = statSync(filePath).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `${filePath} has mode ${mode.toString(8)}; it must be readable by its owner only (0600)`
    );
  }
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

// Loopback only, with no override: this check exhausts a sign-in budget and lets sessions expire, so it is only
// ever meant for a throwaway local portal.
function validateBaseUrl(rawBaseUrl) {
  const parsed = new URL(rawBaseUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`PORTAL_BASE_URL must use HTTP or HTTPS, got ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('PORTAL_BASE_URL must not contain embedded credentials');
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const isLoopback = host === 'localhost'
    || host === '::1'
    || (isIP(host) === 4 && host.split('.')[0] === '127');
  if (!isLoopback) {
    throw new Error(`Refusing non-loopback PORTAL_BASE_URL host ${host}`);
  }
  parsed.pathname = parsed.pathname.replace(/\/$/, '');
  return parsed;
}

// portalUrl and portalPathname: copied from scripts/patient-portal-playwright-checks.js.
function portalUrl(portalPath) {
  if (!portalPath.startsWith('/') || portalPath.startsWith('//')) {
    throw new Error(`Portal path must be root-relative, got ${portalPath}`);
  }
  return new URL(portalPathname(portalPath), baseUrl.origin).toString();
}

function portalPathname(portalPath) {
  const basePath = baseUrl.pathname === '/' ? '' : baseUrl.pathname.replace(/\/+$/, '');
  return `${basePath}${portalPath}`;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// The portal's own English string for `key`, exported by the seed from carlos_patient_portal/i18n.
function t(key) {
  const value = fixtures.text && fixtures.text[key];
  assert(typeof value === 'string' && value.length > 0, `fixture text is missing ${key}`);
  return value;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function exactText(value) {
  return new RegExp(`^\\s*${escapeRegExp(value)}\\s*$`);
}

// A throwaway credential for wrong-password attempts; random, never a literal in the source.
function fakePassword() {
  return randomBytes(18).toString('base64url');
}

function emailDomain(address) {
  return address.slice(address.indexOf('@'));
}

// assertAccessiblePage: copied from scripts/patient-portal-playwright-checks.js.
async function assertAccessiblePage(page, surface) {
  const problems = await page.evaluate(() => {
    const duplicateIds = [...document.querySelectorAll('[id]')]
      .map((element) => element.id)
      .filter((id, index, ids) => id && ids.indexOf(id) !== index);
    const visibleControls = [...document.querySelectorAll(
      'input:not([type="hidden"]), select, textarea, button'
    )].filter((element) => element.getClientRects().length > 0);
    const unnamedControls = visibleControls.filter((element) => {
      const labelledBy = (element.getAttribute('aria-labelledby') || '')
        .split(/\s+/)
        .filter(Boolean)
        .map((id) => document.getElementById(id)?.textContent || '')
        .join(' ')
        .trim();
      return !(
        (element.getAttribute('aria-label') || '').trim()
        || labelledBy
        || [...(element.labels || [])].some((label) => (label.textContent || '').trim())
        || (element instanceof HTMLButtonElement && (element.textContent || '').trim())
        || (element.getAttribute('title') || '').trim()
      );
    });
    const imagesWithoutAlt = [...document.querySelectorAll('img:not([alt])')];
    return {
      duplicateIds: [...new Set(duplicateIds)],
      imagesWithoutAlt: imagesWithoutAlt.length,
      mainLandmarks: document.querySelectorAll('main').length,
      unnamedControls: unnamedControls.map((element) => (
        `${element.tagName.toLowerCase()}[name="${element.getAttribute('name') || ''}"]`
      )),
      visibleHeadings: [...document.querySelectorAll('h1')]
        .filter((element) => element.getClientRects().length > 0).length,
    };
  });
  assert(problems.mainLandmarks === 1, `${surface} must have exactly one main landmark`);
  assert(problems.visibleHeadings === 1, `${surface} must have exactly one visible h1`);
  assert(problems.duplicateIds.length === 0,
    `${surface} has duplicate IDs: ${problems.duplicateIds.join(', ')}`);
  assert(problems.imagesWithoutAlt === 0, `${surface} has an image without alt text`);
  assert(problems.unnamedControls.length === 0,
    `${surface} has unnamed controls: ${problems.unnamedControls.join(', ')}`);
}

function screenshotPath(name) {
  const safeName = name.replace(/[^a-z0-9_-]/gi, '-');
  return path.join(screenshotDir, `${safeName}.png`);
}

const badResponses = [];
const browserIssues = [];
// HTTP errors a step provokes on purpose. Each is matched once, by status and exact pathname;
// any other 4xx/5xx is a failure, and an expected one that never happened is a failure too.
const expectedErrors = [];
// Chromium logs "Failed to load resource" for each error response. Those are allowed per status,
// up to the number of errors expected with that status; the response match above stays strict.
const allowedConsoleErrors = new Map();

function expectHttpError(status, pathname) {
  expectedErrors.push({ status, pathname, seen: false });
  allowedConsoleErrors.set(status, (allowedConsoleErrors.get(status) || 0) + 1);
}

function watchContext(context, label) {
  context.on('response', (response) => {
    const status = response.status();
    if (status < 400) {
      return;
    }
    const responsePath = new URL(response.url()).pathname;
    const expected = expectedErrors.find((candidate) => (
      !candidate.seen && candidate.status === status && candidate.pathname === responsePath
    ));
    if (expected) {
      expected.seen = true;
      return;
    }
    badResponses.push({ context: label, status, url: response.url() });
  });
}

function watchPage(page, label) {
  page.on('console', (message) => {
    if (message.type() !== 'error') {
      return;
    }
    const statusMatch = message.text().match(
      /Failed to load resource: the server responded with a status of (\d{3})/
    );
    const status = statusMatch ? Number(statusMatch[1]) : null;
    if (status !== null && (allowedConsoleErrors.get(status) || 0) > 0) {
      allowedConsoleErrors.set(status, allowedConsoleErrors.get(status) - 1);
      return;
    }
    browserIssues.push(`${label} console: ${message.text()}`);
  });
  page.on('pageerror', (error) => {
    browserIssues.push(`${label} pageerror: ${error.stack || error.message}`);
  });
}

function atPath(page, pathname) {
  return new URL(page.url()).pathname === pathname;
}

async function open(page, portalPath) {
  // portalUrl requires a root-relative path; validateBaseUrl allows loopback hosts only.
  // nosemgrep: javascript.playwright.security.audit.playwright-goto-injection.playwright-goto-injection
  return page.goto(portalUrl(portalPath), { waitUntil: 'load', timeout: 30000 });
}

// Click a control that submits a form, and wait for both the form's own response (status and
// headers are asserted on it, before any redirect is followed) and the document that ends up
// shown. Waiting on the navigation, not the URL, matters when a form posts to the page's own URL.
async function submit(page, control, { pathname, method = 'POST' }) {
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === method
    && new URL(response.url()).pathname === pathname
  ));
  const navigated = page.waitForEvent('framenavigated', {
    predicate: (frame) => frame === page.mainFrame(),
  });
  // If the click itself fails, these waits time out later; keep that from surfacing as an
  // unhandled rejection on top of the real error. Awaiting them below still sees a rejection.
  responsePromise.catch(() => {});
  navigated.catch(() => {});
  await control.click();
  const response = await responsePromise;
  await navigated;
  await page.waitForLoadState('load');
  return response;
}


/* Drops expectations that were declared for a status that then did not happen (a loop that stops
 * at the first throttled answer declares both outcomes for each attempt). */
function forgetUnseen(status, pathname) {
  for (let index = expectedErrors.length - 1; index >= 0; index -= 1) {
    const candidate = expectedErrors[index];
    if (!candidate.seen && candidate.status === status && candidate.pathname === pathname) {
      expectedErrors.splice(index, 1);
      allowedConsoleErrors.set(status, Math.max(0, (allowedConsoleErrors.get(status) || 0) - 1));
    }
  }
}

function wait(milliseconds) {
  return new Promise((resolve) => { setTimeout(resolve, milliseconds); });
}

async function waitForCooldown(account, seconds, what) {
  if (!account.lastCodeSentAt) return;
  const remaining = account.lastCodeSentAt + (seconds * 1000) + 2000 - Date.now();
  if (remaining > 0) {
    console.log(`Waiting ${Math.ceil(remaining / 1000)}s for the ${what} cooldown of ${account.username}`);
    await wait(remaining);
  }
}

function developmentCode(page) {
  return page.locator('[data-development-mfa-code]').getAttribute('data-development-mfa-code');
}

/* The code the portal just sent by SMS to `to` (captured after `since`), cross-checked against the
 * development code the page shows: the SMS carried what the server expects. */
async function smsCode(page, to, since) {
  const captured = await readCapturedSmsCode({ file: smsCaptureFile, to, after: since, wait });
  assert(captured.senderId === settings.smsSenderId,
    `the SMS came from sender ${captured.senderId}, expected ${settings.smsSenderId}`);
  const shown = await developmentCode(page);
  assert(captured.code === shown, 'the SMS did not carry the code the server expects');
  return captured.code;
}

async function fillSignIn(page, username, password, text = t) {
  await page.getByRole('heading', { name: text('sign_in_heading'), exact: true }).waitFor();
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(password);
}

function signInButton(page, text = t) {
  return page.getByRole('button', { name: text('sign_in_button'), exact: true });
}

/* Posts the sign-in form and lands on the code page; returns the login response. */
async function startSignIn(page, account, text = t) {
  await open(page, '/');
  await fillSignIn(page, account.username, account.password, text);
  const loginResponse = await submit(page, signInButton(page, text), { pathname: portalPathname('/auth/login') });
  assert(loginResponse.status() === 200, `sign-in for ${account.username} returned ${loginResponse.status()}`);
  account.lastCodeSentAt = Date.now();
  await page.getByRole('heading', { name: text('mfa_heading'), exact: true }).waitFor();
  return loginResponse;
}

async function verifyCode(page, code, { expectRefused = false, text = t } = {}) {
  await page.locator('input[name="code"]').fill(code);
  if (expectRefused) expectHttpError(401, portalPathname('/auth/mfa/verify'));
  const response = await submit(page, page.getByRole('button', { name: text('mfa_verify'), exact: true }),
    { pathname: portalPathname('/auth/mfa/verify') });
  if (expectRefused) {
    assert(response.status() === 401, `a wrong code returned ${response.status()}`);
    await page.getByRole('alert').waitFor();
    return response;
  }
  assert(response.status() === 303, `the code returned ${response.status()}`);
  assert(atPath(page, portalPathname('/portal')), 'the code did not open the dashboard');
  await page.getByRole('heading', { name: text('dashboard_greeting'), exact: true }).waitFor();
  return response;
}

async function signInWithEmailCode(page, account, text = t) {
  await waitForCooldown(account, settings.mfaEmailCooldownSeconds, 'email');
  await startSignIn(page, account, text);
  await verifyCode(page, await developmentCode(page), { text });
}

async function signOut(page, context, text = t) {
  const response = await submit(page, page.getByRole('button', { name: text('logout'), exact: true }),
    { pathname: portalPathname('/portal/logout') });
  assert(response.status() === 303, `logout returned ${response.status()}`);
  assert(atPath(page, portalPathname('/')), 'logout did not return to sign-in');
  await page.getByRole('heading', { name: text('sign_in_heading'), exact: true }).waitFor();
  assert(!(await context.cookies()).some((cookie) => cookie.name === settings.sessionCookieName),
    'logout left the portal session cookie behind');
}

async function openModule(page, labelKey, portalPath, text = t) {
  await page.locator('.module-nav').getByRole('link', { name: text(labelKey), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname(portalPath));
  await page.locator('.module-workspace h1').waitFor();
}

function accountDetail(page, labelKey, text = t) {
  return page.locator('.detail-list > div')
    .filter({ has: page.locator('dt', { hasText: exactText(text(labelKey)) }) })
    .locator('dd');
}

async function assertNoHorizontalOverflow(page, surface) {
  const layout = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
  }));
  assert(layout.documentWidth <= layout.viewportWidth + 1,
    `${surface} overflows horizontally: ${layout.documentWidth}px > ${layout.viewportWidth}px`);
}

async function accountStatus(page, key) {
  await page.waitForURL((url) => url.pathname === portalPathname('/portal/account') && url.searchParams.get('status') === key);
  await page.getByRole('status').filter({ hasText: t(`account_status_${key.replace(/-/g, '_')}`) }).waitFor();
}

/* The resend form on the code page: declared status (429 inside a cooldown), then the page again. */
async function resendCode(page, { expectThrottled = false } = {}) {
  if (expectThrottled) expectHttpError(429, portalPathname('/auth/mfa/resend'));
  const response = await submit(page, page.getByRole('button', { name: t('mfa_resend'), exact: true }),
    { pathname: portalPathname('/auth/mfa/resend') });
  await page.getByRole('heading', { name: t('mfa_heading'), exact: true }).waitFor();
  return response;
}

// ---- Step 1: sign in by SMS; resend after the cooldown (SMS and email) ----
async function checkSmsSignInAndResend(page, context) {
  const account = accounts.sms;
  const since = Date.now();
  await startSignIn(page, account);
  const sentTo = (await page.locator('.mfa-destination').innerText()).trim();
  assert(sentTo.includes(t('mfa_sms')), `the code page should say the code went by SMS, page says: ${sentTo}`);
  assert(!sentTo.includes(account.phone), `the code page shows the full phone number: ${sentTo}`);
  const first = await smsCode(page, account.phone, since);

  // Inside the cooldown a resend is refused and no second SMS is sent.
  const sentBefore = readCaptures(smsCaptureFile).filter((entry) => entry.to === account.phone).length;
  await resendCode(page, { expectThrottled: true });
  await wait(1000);
  assert(readCaptures(smsCaptureFile).filter((entry) => entry.to === account.phone).length === sentBefore,
    'a refused resend still sent an SMS');

  await verifyCode(page, `${first.slice(1)}${first[0] === '9' ? '0' : '9'}`, { expectRefused: true });
  await verifyCode(page, first);
  await signOut(page, context);

  // After the cooldown, Resend sends a new code by SMS; the old one no longer works.
  await waitForCooldown(account, settings.mfaSmsCooldownSeconds, 'SMS');
  const secondStart = Date.now();
  await startSignIn(page, account);
  const before = await smsCode(page, account.phone, secondStart);
  await waitForCooldown(account, settings.mfaSmsCooldownSeconds, 'SMS');
  const resendAt = Date.now();
  const resent = await resendCode(page);
  assert(resent.status() === 200 || resent.status() === 303, `resend returned ${resent.status()}`);
  account.lastCodeSentAt = Date.now();
  const after = await smsCode(page, account.phone, resendAt);
  assert(after !== before, 'Resend did not send a new code');
  await verifyCode(page, before, { expectRefused: true });
  await verifyCode(page, after);
  await signOut(page, context);

  // The email method: the same resend proof with the code shown on the page.
  const emailAccount = accounts.throttle;
  await waitForCooldown(emailAccount, settings.mfaEmailCooldownSeconds, 'email');
  await startSignIn(page, emailAccount);
  const emailBefore = await developmentCode(page);
  await resendCode(page, { expectThrottled: true });
  await waitForCooldown(emailAccount, settings.mfaEmailCooldownSeconds, 'email');
  await resendCode(page);
  emailAccount.lastCodeSentAt = Date.now();
  const emailAfter = await developmentCode(page);
  assert(emailAfter && emailAfter !== emailBefore, 'Resend by email did not show a new code');
  await verifyCode(page, emailBefore, { expectRefused: true });
  await verifyCode(page, emailAfter);
  await signOut(page, context);
}

// ---- Step 2: change the phone number, confirmed by SMS ----
async function checkPhoneChange(page, context) {
  const account = accounts.phone;
  const newPhone = fixtures.newPhone;
  await signInWithEmailCode(page, account);
  await openModule(page, 'account', '/portal/account');

  const contactForm = page.locator('form[action$="/portal/account/contact"]');
  await contactForm.locator('input[name="phone_number"]').fill(newPhone);
  await contactForm.locator('input[name="current_password"]').fill(account.password);
  const since = Date.now();
  const requested = await submit(page, contactForm.getByRole('button', { name: t('update_contact'), exact: true }),
    { pathname: portalPathname('/portal/account/contact') });
  assert(requested.status() === 303, `the phone change returned ${requested.status()}`);
  await accountStatus(page, 'phone-confirmation-required');
  // The account page carries the number only in the contact form; it stays empty until confirmed.
  assert(await page.locator('form[action$="/portal/account/contact"] input[name="phone_number"]').inputValue() === '',
    'the new number is shown before it is confirmed');
  const confirmForm = page.locator('form[action$="/portal/account/contact/confirm-phone"]');
  await confirmForm.locator('input[name="phone_confirmation_code"]').waitFor();
  const first = await readCapturedSmsCode({ file: smsCaptureFile, to: newPhone, after: since, wait });

  // A wrong code changes nothing.
  await confirmForm.locator('input[name="phone_confirmation_code"]').fill(`${first.code.slice(1)}${first.code[0] === '9' ? '0' : '9'}`);
  const wrong = await submit(page, confirmForm.getByRole('button', { name: t('confirm_phone'), exact: true }),
    { pathname: portalPathname('/portal/account/contact/confirm-phone') });
  assert(wrong.status() === 303, `a wrong phone code returned ${wrong.status()}`);
  await accountStatus(page, 'phone-confirmation-invalid');

  // Resend inside the cooldown is refused (status, no SMS); after the cooldown a second code
  // arrives and the first is then refused.
  const resendForm = () => page.locator('form[action$="/portal/account/contact/resend-phone"]');
  const resendButton = () => resendForm().getByRole('button', { name: t('resend_phone_confirmation'), exact: true });
  const sentSoFar = readCaptures(smsCaptureFile).filter((entry) => entry.to === newPhone).length;
  const early = await submit(page, resendButton(), { pathname: portalPathname('/portal/account/contact/resend-phone') });
  assert(early.status() === 303, `resend inside the cooldown returned ${early.status()}`);
  await accountStatus(page, 'phone-confirmation-rate-limited');
  assert(readCaptures(smsCaptureFile).filter((entry) => entry.to === newPhone).length === sentSoFar,
    'a refused phone-code resend still sent an SMS');
  // The cooldown is waited out signed out (the pending change outlives the session), then the
  // patient signs in again and asks for a new code.
  await signOut(page, context);
  console.log(`Waiting ${settings.mfaSmsCooldownSeconds + 2}s for the phone-code resend cooldown`);
  await wait((settings.mfaSmsCooldownSeconds + 2) * 1000);
  await signInWithEmailCode(page, account);
  await openModule(page, 'account', '/portal/account');
  const resendAt = Date.now();
  const resent = await submit(page, resendButton(), { pathname: portalPathname('/portal/account/contact/resend-phone') });
  assert(resent.status() === 303, `resend returned ${resent.status()}`);
  await accountStatus(page, 'phone-confirmation-required');
  const second = await readCapturedSmsCode({ file: smsCaptureFile, to: newPhone, after: resendAt, wait });
  assert(second.code !== first.code, 'the resent phone code is the first one again');
  const confirmAgain = page.locator('form[action$="/portal/account/contact/confirm-phone"]');
  await confirmAgain.locator('input[name="phone_confirmation_code"]').fill(first.code);
  const stale = await submit(page, confirmAgain.getByRole('button', { name: t('confirm_phone'), exact: true }),
    { pathname: portalPathname('/portal/account/contact/confirm-phone') });
  assert(stale.status() === 303, `the first phone code returned ${stale.status()}`);
  await accountStatus(page, 'phone-confirmation-invalid');

  // The right code applies the number. Moving a contact destination signs every session out
  // (the result page says so and the cookie is cleared), so the patient signs in again to see it.
  const confirmLast = page.locator('form[action$="/portal/account/contact/confirm-phone"]');
  await confirmLast.locator('input[name="phone_confirmation_code"]').fill(second.code);
  const applied = await submit(page, confirmLast.getByRole('button', { name: t('confirm_phone'), exact: true }),
    { pathname: portalPathname('/portal/account/contact/confirm-phone') });
  assert(applied.status() === 200, `the right phone code returned ${applied.status()}`);
  await page.getByRole('heading', { name: t('contact_change_success_heading'), exact: true }).waitFor();
  assert(!(await context.cookies()).some((cookie) => cookie.name === settings.sessionCookieName),
    'applying the contact change left the session cookie behind');
  await page.screenshot({ path: screenshotPath('patient-portal-session-phone-confirmed'), fullPage: true });
  await signInWithEmailCode(page, account);
  await openModule(page, 'account', '/portal/account');
  assert(await page.locator('form[action$="/portal/account/contact"] input[name="phone_number"]').inputValue() === newPhone,
    'the confirmed number is not shown on the account page');

  // With a confirmed number, SMS can be chosen as the sign-in method.
  const mfaForm = page.locator('form[action$="/portal/account/mfa"]');
  await mfaForm.locator('select[name="preferred_mfa_method"]').selectOption('sms');
  await mfaForm.locator('input[name="current_password"]').fill(account.password);
  const chosen = await submit(page, mfaForm.getByRole('button', { name: t('update_mfa'), exact: true }),
    { pathname: portalPathname('/portal/account/mfa') });
  assert(chosen.status() === 303, `choosing SMS after confirming the number returned ${chosen.status()}`);
  await accountStatus(page, 'mfa-updated');
  assert(await page.locator('form[action$="/portal/account/mfa"] select[name="preferred_mfa_method"]').inputValue() === 'sms',
    'the account page does not show SMS as the chosen method');
  await signOut(page, context);
}

// ---- Step 3: every locale on the signed-in pages ----
async function checkLocales(page, context) {
  const account = accounts.locale;
  const english = locales.find((locale) => locale.code === settings.defaultLocale);
  const keysOnPages = ['sign_in_heading', 'mfa_heading', 'dashboard_greeting', 'account', 'messages', 'help', 'logout'];
  for (const locale of locales) {
    if (locale.code === settings.defaultLocale) continue;
    const text = (key) => {
      const value = locale.text[key];
      assert(typeof value === 'string' && value.length > 0, `locale ${locale.code} is missing ${key}`);
      return value;
    };
    // Switch on the sign-in page: the link named in its own language, the choice kept in a cookie.
    await open(page, '/');
    await page.locator(`.language-switch a.text-tab[lang="${locale.code}"]`).click();
    await page.waitForURL((url) => url.pathname === portalPathname('/'));
    assert((await context.cookies()).some((cookie) => cookie.name === settings.localeCookieName),
      `choosing ${locale.code} set no locale cookie`);
    assert(await page.locator('html').getAttribute('lang') === locale.code, `the sign-in page is not lang=${locale.code}`);
    await page.getByRole('heading', { name: text('sign_in_heading'), exact: true }).waitFor();

    await signInWithEmailCode(page, account, text);
    for (const [key, portalPath] of [['account', '/portal/account'], ['messages', '/portal/messages'], ['help', '/portal/help']]) {
      await openModule(page, key, portalPath, text);
      assert(await page.locator('html').getAttribute('lang') === locale.code, `${portalPath} is not lang=${locale.code} in ${locale.code}`);
      const body = await page.locator('body').innerText();
      for (const other of keysOnPages) {
        // A key whose translation differs from English must not show the English on the page.
        if (locale.text[other] && english.text[other] && locale.text[other] !== english.text[other]
            && ['account', 'messages', 'help', 'logout'].includes(other)) {
          assert(!new RegExp(`(^|\\s)${escapeRegExp(english.text[other])}(\\s|$)`).test(body),
            `${portalPath} in ${locale.code} still shows the English "${english.text[other]}"`);
        }
      }
      await assertAccessiblePage(page, `${portalPath} in ${locale.code}`);
      await page.setViewportSize({ width: 360, height: 780 });
      await assertNoHorizontalOverflow(page, `${portalPath} in ${locale.code} at 360px`);
      await page.setViewportSize({ width: 1280, height: 900 });
    }
    await page.screenshot({ path: screenshotPath(`patient-portal-session-locale-${locale.code}`), fullPage: true });
    await signOut(page, context, text);
  }
  // Back to the default locale for the steps that follow.
  await open(page, '/');
  await page.locator(`.language-switch a.text-tab[lang="${english.code}"]`).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/'));
  await page.getByRole('heading', { name: t('sign_in_heading'), exact: true }).waitFor();
}

// ---- Step 4: the notice pages a browser gets ----
async function checkNoticePages(page) {
  // An unknown route: the notice page, not JSON.
  expectHttpError(404, portalPathname('/no-such-page'));
  const missing = await page.goto(portalUrl('/no-such-page'), { waitUntil: 'load', timeout: 30000 });
  assert(missing.status() === 404, `an unknown route returned ${missing.status()}`);
  assert((missing.headers()['content-type'] || '').includes('text/html'), 'an unknown route answered a browser without HTML');
  await page.getByRole('heading', { name: t('request_failed_heading'), exact: true }).waitFor();
  await page.getByRole('alert').filter({ hasText: t('request_failed_details') }).waitFor();
  await page.getByRole('link', { name: t('back_to_sign_in'), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/'));

  // A form posted with a stale CSRF token: the notice page with a way back, not JSON.
  await fillSignIn(page, accounts.throttle.username, fakePassword());
  await page.evaluate(() => {
    document.querySelector('form[action$="/auth/login"] input[name="csrf_token"]').value = 'stale';
  });
  expectHttpError(403, portalPathname('/auth/login'));
  const refused = await submit(page, signInButton(page), { pathname: portalPathname('/auth/login') });
  assert(refused.status() === 403, `a stale CSRF token returned ${refused.status()}`);
  await page.getByRole('heading', { name: t('request_failed_heading'), exact: true }).waitFor();
  await page.getByRole('link', { name: t('back_to_sign_in'), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/'));

  // The sign-in throttle: wrong passwords until the bucket is empty, then the 429 notice.
  let throttled = null;
  for (let attempt = 1; attempt <= settings.authRateLimitMaxRequests + 1 && !throttled; attempt += 1) {
    await fillSignIn(page, accounts.throttle.username, fakePassword());
    expectHttpError(401, portalPathname('/auth/login'));
    expectHttpError(429, portalPathname('/auth/login'));
    const response = await submit(page, signInButton(page), { pathname: portalPathname('/auth/login') });
    if (response.status() === 429) {
      throttled = response;
      forgetUnseen(401, portalPathname('/auth/login'));
    } else {
      assert(response.status() === 401, `wrong password ${attempt} returned ${response.status()}`);
      forgetUnseen(429, portalPathname('/auth/login'));
      await page.getByRole('alert').filter({ hasText: t('incorrect_username_or_password') }).waitFor();
    }
  }
  assert(throttled, `no 429 after ${settings.authRateLimitMaxRequests + 1} sign-ins`);
  assert(/^\d+$/.test(throttled.headers()['retry-after'] || ''), 'the throttle answer has no Retry-After');
  await page.getByRole('alert').waitFor();
  assert(await page.locator('input[name="password"]').count() === 0, 'the throttle notice still offers the sign-in form');
  await page.getByRole('link', { name: t('back_to_sign_in'), exact: true }).waitFor();
  await page.screenshot({ path: screenshotPath('patient-portal-session-throttled'), fullPage: true });
}

// ---- Step 5: idle session expiry ----
// The portal ends a session `idle limit` after its last recorded activity. (It records activity at
// most once per SESSION_LAST_SEEN_UPDATE_INTERVAL, 5 minutes, so with a limit below that a page
// opened halfway does not extend the session; the step waits the full limit after that page, so
// it holds whether or not the page counted.)
async function checkIdleExpiry(page, context) {
  const account = accounts.idle;
  const limitMs = settings.idleTimeoutSeconds * 1000;
  await signInWithEmailCode(page, account);
  const cookie = (await context.cookies()).find((candidate) => candidate.name === settings.sessionCookieName);
  assert(cookie, 'no session cookie while signed in');
  // Halfway through the limit the session is alive.
  await wait(limitMs * 0.5);
  await open(page, '/portal/account');
  assert(atPath(page, portalPathname('/portal/account')), 'the session ended before the idle limit');
  const lastPageAt = Date.now();
  // Idle for the whole limit after that page: the next request lands on sign-in and the old
  // cookie is dead.
  console.log(`Waiting ${Math.ceil(limitMs / 1000) + 5}s for the idle limit`);
  await wait(Math.max(0, lastPageAt + limitMs + 5000 - Date.now()));
  await open(page, '/portal');
  assert(atPath(page, portalPathname('/')), 'an idle session was not ended');
  await page.getByRole('heading', { name: t('sign_in_heading'), exact: true }).waitFor();
  await context.addCookies([cookie]);
  await open(page, '/portal/account');
  assert(atPath(page, portalPathname('/')), 'the expired session cookie still opens the account page');
}

(async () => {
  mkdirSync(screenshotDir, { recursive: true, mode: 0o700 });
  const browser = await chromium.launch({
    executablePath: chromePath || undefined,
    headless: true,
  });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-CA' });
  watchContext(context, 'main');
  const page = await context.newPage();
  watchPage(page, 'main');
  try {
    if (runs('sms')) await checkSmsSignInAndResend(page, context);
    if (runs('phone')) await checkPhoneChange(page, context);
    if (runs('locales')) await checkLocales(page, context);
    if (runs('idle')) await checkIdleExpiry(page, context);
    if (runs('notices')) await checkNoticePages(page);
    const unseen = expectedErrors.filter((candidate) => !candidate.seen);
    assert(unseen.length === 0,
      `expected HTTP errors never happened: ${unseen.map((e) => `${e.status} ${e.pathname}`).join(', ')}`);
    assert(badResponses.length === 0, `unexpected HTTP errors: ${JSON.stringify(badResponses)}`);
    assert(browserIssues.length === 0, `browser issues: ${browserIssues.join('; ')}`);
    console.log(`Patient portal session Playwright checks passed${selectedSteps.length ? ` (steps: ${selectedSteps.join(', ')})` : ''}`);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
