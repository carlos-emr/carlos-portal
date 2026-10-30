#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Live browser checks for patient account flows that scripts/patient-portal-playwright-checks.js
 * does not drive:
 *
 *   1. Confirming an email change from the emailed link, and the replay being refused.
 *   2. Link myCarlos: creating one-time codes with their QR code, and the MFA-proof gate.
 *   3. Linked devices: the list, the removal confirmation, Keep, and Remove.
 *   4. A wrong current password on the account forms, then the locked-account page.
 *   5. Offered appointment times: "None of these work".
 *
 * It is a separate script, with its own seed (tests/seed_browser_account.py), so it never edits or
 * depends on the main check's fixtures or steps.
 *
 * Run recipe. The fixtures are single-use (a confirmation token is spent, a device removed, an
 * account locked), so every run needs a fresh database. From the repository root:
 *
 *   export PORTAL_ACCOUNT_CHECK_DIR="$(mktemp -d)"
 *   new_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
 *   export PATIENT_PORTAL_ENVIRONMENT=development
 *   export PATIENT_PORTAL_DATABASE_URL="sqlite+pysqlite:///$PORTAL_ACCOUNT_CHECK_DIR/portal.db"
 *   export PATIENT_PORTAL_IDENTITY_PROOF_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_AUDIT_HASH_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_SESSION_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_UNLOCK_SECRET_ENCRYPTION_SECRET="$(new_secret)"
 *   export PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED=true
 *   # Shown on the linking page and put in the QR code, which needs https. Nothing is served on
 *   # it: the browser still talks plain http to uvicorn on PORTAL_BASE_URL.
 *   export PATIENT_PORTAL_PUBLIC_BASE_URL=https://127.0.0.1:8491
 *   # Room for three wrong account-form passwords before the lockout (step 4), sign-in budget
 *   # for the lockout attempts, and shorter waits between two sign-ins to one account.
 *   export PATIENT_PORTAL_AUTH_MAX_FAILED_PASSWORD_ATTEMPTS=4
 *   export PATIENT_PORTAL_AUTH_RATE_LIMIT_MAX_REQUESTS=100
 *   export PATIENT_PORTAL_MFA_EMAIL_RESEND_COOLDOWN_SECONDS=30
 *   export PYTHONPATH=.
 *   export PORTAL_BASE_URL=http://127.0.0.1:8491
 *   export PORTAL_ACCOUNT_FIXTURE_FILE="$PORTAL_ACCOUNT_CHECK_DIR/account-fixtures.json"
 *   export PORTAL_USE_DEVELOPMENT_MFA_CODE=true
 *   export PORTAL_SCREENSHOT_DIR="$PORTAL_ACCOUNT_CHECK_DIR/screenshots"
 *   python -m alembic -c alembic.ini upgrade head
 *   python tests/seed_browser_account.py
 *   python -m uvicorn carlos_patient_portal.main:create_app --factory \
 *     --host 127.0.0.1 --port 8491 > "$PORTAL_ACCOUNT_CHECK_DIR/uvicorn.log" 2>&1 &
 *   server_pid=$!
 *   trap 'kill "$server_pid" 2>/dev/null || true' EXIT
 *   for attempt in $(seq 1 30); do
 *     curl -fsS http://127.0.0.1:8491/health >/dev/null && break
 *     sleep 1
 *   done
 *   npm run test:patient-portal-account-playwright
 *
 * The server must run with exactly the environment the seed ran with: the email-change token is
 * keyed by the session secret, and the seed records the lockout threshold, sign-in rate limit,
 * MFA email cooldown and whether a mail server is configured, which this script plans around.
 *
 * Without PATIENT_PORTAL_SMTP_HOST the myCarlos MFA step-up cannot send its email code, so step 2
 * asserts that it refuses (409) and recovers by signing in again. With a capture-only SMTP host
 * (the devcontainer's Postfix) it completes the step-up instead.
 *
 * Optional environment:
 *   PORTAL_USE_DEVELOPMENT_MFA_CODE=true to read codes rendered by a development server, otherwise
 *     they are read through PORTAL_MAIL_COMMAND (default /scripts/mail), as the main check does
 *   PORTAL_CHROME_PATH=/path/to/chrome-or-chromium
 */

const { execFileSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { mkdirSync, readFileSync, statSync } = require('node:fs');
const { isIP } = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { readCapturedMfaCode } = require('./patient-portal-mail-capture');

const baseUrl = validateBaseUrl(process.env.PORTAL_BASE_URL || 'http://127.0.0.1:8491');
const fixturePath = process.env.PORTAL_ACCOUNT_FIXTURE_FILE
  || path.join(os.tmpdir(), 'patient-portal-account-fixtures.json');
const useDevelopmentMfaCode = process.env.PORTAL_USE_DEVELOPMENT_MFA_CODE === 'true';
const mailCommand = process.env.PORTAL_MAIL_COMMAND || '/scripts/mail';
const screenshotDir = path.resolve(process.env.PORTAL_SCREENSHOT_DIR || os.tmpdir());
const chromePath = process.env.PORTAL_CHROME_PATH || process.env.CHROME_PATH || '';

const fixtures = readFixtures(fixturePath);
const settings = fixtures.settings;
const emailAccount = fixtures.emailChange;
const linkAccount = fixtures.mycarlos;
const lockAccount = fixtures.lock;
const linkCodePattern = new RegExp(settings.linkCodePattern);
// Step 4 makes one wrong attempt on each of the three password-protected account forms.
const wrongStepUps = 3;

assert(
  emailAccount && emailAccount.username && emailAccount.password && emailAccount.oldEmail
    && emailAccount.newEmail && emailAccount.token,
  `email-change fixture is incomplete in ${fixturePath}`
);
assert(
  linkAccount && linkAccount.username && linkAccount.password && linkAccount.email
    && Array.isArray(linkAccount.devices) && linkAccount.devices.length === 2
    && linkAccount.decline && linkAccount.decline.title && linkAccount.decline.contactText,
  `myCarlos fixture is incomplete in ${fixturePath}`
);
assert(
  lockAccount && lockAccount.username && lockAccount.password && lockAccount.email,
  `lock fixture is incomplete in ${fixturePath}`
);
assert(
  typeof settings.publicBaseUrl === 'string' && settings.publicBaseUrl.startsWith('https://'),
  'the seed must run with an https PATIENT_PORTAL_PUBLIC_BASE_URL'
);
assert(
  Number.isInteger(settings.lockThreshold) && settings.lockThreshold > wrongStepUps,
  `PATIENT_PORTAL_AUTH_MAX_FAILED_PASSWORD_ATTEMPTS is ${settings.lockThreshold}; it must be at `
    + `least ${wrongStepUps + 1} so the wrong account-form passwords do not lock the account `
    + 'before the sign-in lockout is checked (the recipe uses 4)'
);
// Every POST /auth/login shares one per-client bucket: the lock account's first sign-in, its
// wrong passwords, the locked sign-in and one wrong password after it; the email-change account's
// two sign-ins; and the myCarlos account's sign-in plus, without a mail server, a second one.
const plannedSignInRequests = 1 + settings.lockThreshold + 2 + 2
  + (settings.stepUpEmailAvailable ? 1 : 2);
assert(
  settings.authRateLimitMaxRequests >= plannedSignInRequests,
  `this check sends ${plannedSignInRequests} sign-in requests but the portal allows `
    + `${settings.authRateLimitMaxRequests} per ${settings.authRateLimitWindowSeconds}s; set `
    + `PATIENT_PORTAL_AUTH_RATE_LIMIT_MAX_REQUESTS to at least ${plannedSignInRequests} `
    + '(the recipe uses 100)'
);

mkdirSync(screenshotDir, { recursive: true });

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

// Loopback only, with no override: this check locks an account, moves an email address and
// removes a linked device, so it is only ever meant for a throwaway local portal.
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

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function runMailCommand(...args) {
  return execFileSync(mailCommand, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10000,
  });
}

// readBrowserMfaCode: copied from scripts/patient-portal-playwright-checks.js.
async function readBrowserMfaCode(page, expectedRecipient) {
  if (useDevelopmentMfaCode) {
    const code = await page.locator('[data-development-mfa-code]').getAttribute(
      'data-development-mfa-code'
    );
    assert(code, 'development MFA code was not available');
    return code;
  }

  return readCapturedMfaCode({
    expectedRecipient,
    readLatest: () => runMailCommand('read', 'latest'),
    wait: sleep,
  });
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

async function waitForMfaCooldown(account) {
  // The portal refuses a new email code to the same account inside the resend cooldown, even for
  // a fresh sign-in (auth.create_mfa_challenge), so a second sign-in waits it out.
  if (!account.lastMfaSentAt) {
    return;
  }
  const remaining = account.lastMfaSentAt
    + (settings.mfaEmailCooldownSeconds * 1000) + 2000 - Date.now();
  if (remaining > 0) {
    console.log(
      `Waiting ${Math.ceil(remaining / 1000)}s for the MFA email cooldown of ${account.username}`
    );
    await new Promise((resolve) => {
      setTimeout(resolve, remaining);
    });
  }
}

async function enterMfaCode(page, account, recipient) {
  account.lastMfaSentAt = Date.now();
  const code = await readBrowserMfaCode(page, recipient);
  await page.locator('input[name="code"]').fill(code);
  const verifyResponse = await submit(
    page,
    page.getByRole('button', { name: t('mfa_verify'), exact: true }),
    { pathname: portalPathname('/auth/mfa/verify') },
  );
  assert(verifyResponse.status() === 303,
    `MFA verification for ${account.username} returned ${verifyResponse.status()}`);
  assert(atPath(page, portalPathname('/portal')), 'MFA verification did not open the dashboard');
  await page.getByRole('heading', { name: t('dashboard_greeting'), exact: true }).waitFor();
  assert(
    (await page.locator('.signed-in-user').textContent() || '').trim() === account.username,
    `the dashboard is not signed in as ${account.username}`
  );
}

async function fillSignIn(page, username, password) {
  await page.getByRole('heading', { name: t('sign_in_heading'), exact: true }).waitFor();
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(password);
}

function signInButton(page) {
  return page.getByRole('button', { name: t('sign_in_button'), exact: true });
}

async function signIn(page, account, { recipient = account.email, destination } = {}) {
  await waitForMfaCooldown(account);
  await open(page, '/');
  await fillSignIn(page, account.username, account.password);
  if (!useDevelopmentMfaCode) {
    runMailCommand('clear');
  }
  const loginResponse = await submit(page, signInButton(page), {
    pathname: portalPathname('/auth/login'),
  });
  assert(loginResponse.status() === 200,
    `sign-in for ${account.username} returned ${loginResponse.status()}`);
  await page.getByRole('heading', { name: t('mfa_heading'), exact: true }).waitFor();
  if (destination) {
    // "Code sent to fa***@domain by EMAIL." The masked address keeps the domain.
    const sentTo = (await page.locator('.mfa-destination').innerText()).trim();
    assert(sentTo.includes(destination.includes),
      `MFA code should go to ${destination.includes}, page says: ${sentTo}`);
    assert(!sentTo.includes(destination.excludes),
      `MFA code must no longer go to ${destination.excludes}, page says: ${sentTo}`);
  }
  await enterMfaCode(page, account, recipient);
}

async function signOut(page, context) {
  const response = await submit(
    page,
    page.getByRole('button', { name: t('logout'), exact: true }),
    { pathname: portalPathname('/portal/logout') },
  );
  assert(response.status() === 303, `logout returned ${response.status()}`);
  assert(atPath(page, portalPathname('/')), 'logout did not return to sign-in');
  await page.getByRole('heading', { name: t('sign_in_heading'), exact: true }).waitFor();
  assert(
    !(await context.cookies()).some((cookie) => cookie.name === settings.sessionCookieName),
    'logout left the portal session cookie behind'
  );
}

async function openModule(page, labelKey, portalPath) {
  await page.locator('.module-nav').getByRole('link', { name: t(labelKey), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname(portalPath));
  await page.locator('.module-workspace h1').waitFor();
}

// The value shown beside a label in the account page's summary list (dashboard.jinja:104-121).
function accountDetail(page, labelKey) {
  return page.locator('.detail-list > div')
    .filter({ has: page.locator('dt', { hasText: exactText(t(labelKey)) }) })
    .locator('dd');
}

async function assertNoHorizontalOverflow(page, surface) {
  const layout = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
  }));
  assert(
    layout.documentWidth <= layout.viewportWidth + 1,
    `${surface} overflows horizontally: ${layout.documentWidth}px > ${layout.viewportWidth}px`
  );
}

// ---- Step 4: wrong current password on the account forms, then the locked-account page ----
async function checkWrongPasswordsAndLockout(page, context) {
  await signIn(page, lockAccount);
  await openModule(page, 'account', '/portal/account');
  await assertAccessiblePage(page, 'account page');
  assert((await accountDetail(page, 'email').innerText()).trim() === lockAccount.email,
    'the account page does not show the seeded email address');

  const passwordForm = page.locator('form', { has: page.locator('input[name="new_password"]') });
  const contactForm = page.locator('form', { has: page.locator('input[name="email"]') });
  const mfaForm = page.locator('form', {
    has: page.locator('select[name="preferred_mfa_method"]'),
  });

  // Each refusal re-renders the account page in place (portal.py render_account_change_error):
  // same URL as the form's action, the generic error, nothing typed echoed back, still signed in,
  // and the stored address unchanged.
  async function assertStepUpRefused(response, actionPath, surface) {
    assert(response.status() === 403,
      `${surface} with a wrong current password returned ${response.status()}`);
    assert(atPath(page, portalPathname(actionPath)), `${surface} refusal left ${page.url()}`);
    await page.getByRole('heading', { name: t('account'), exact: true }).waitFor();
    const alerts = page.locator('.module-workspace [role="alert"]');
    assert(await alerts.count() === 1
      && (await alerts.innerText()).trim() === t('account_change_error'),
    `${surface} refusal should show exactly the account-change error`);
    assert(await page.locator('.module-workspace [role="status"]').count() === 0,
      `${surface} refusal must not show a success notice`);
    const typedPasswords = await page.locator('input[type="password"]').evaluateAll(
      (inputs) => inputs.filter((input) => input.value !== '').length
    );
    assert(typedPasswords === 0, `${surface} refusal echoed a password back into the page`);
    assert((await page.locator('.signed-in-user').textContent() || '').trim()
      === lockAccount.username, `${surface} refusal signed the patient out`);
    assert((await accountDetail(page, 'email').innerText()).trim() === lockAccount.email,
      `${surface} refusal changed the displayed email address`);
    assert(await contactForm.locator('input[name="email"]').inputValue() === lockAccount.email,
      `${surface} refusal changed the email address in the contact form`);
  }

  const attemptedPassword = fakePassword();
  await passwordForm.locator('input[name="current_password"]').fill(fakePassword());
  await passwordForm.locator('input[name="new_password"]').fill(attemptedPassword);
  await passwordForm.locator('input[name="new_password_confirmation"]').fill(attemptedPassword);
  expectHttpError(403, portalPathname('/portal/account/password'));
  await assertStepUpRefused(
    await submit(page, passwordForm.getByRole('button', { name: t('update_password'), exact: true }),
      { pathname: portalPathname('/portal/account/password') }),
    '/portal/account/password',
    'password change',
  );

  const attemptedEmail = 'fake.lock.attempt@example.com';
  await contactForm.locator('input[name="email"]').fill(attemptedEmail);
  await contactForm.locator('input[name="current_password"]').fill(fakePassword());
  expectHttpError(403, portalPathname('/portal/account/contact'));
  await assertStepUpRefused(
    await submit(page, contactForm.getByRole('button', { name: t('update_contact'), exact: true }),
      { pathname: portalPathname('/portal/account/contact') }),
    '/portal/account/contact',
    'contact change',
  );
  assert(!(await page.locator('body').innerText()).includes(attemptedEmail),
    'a refused contact change echoed the attempted address');

  await mfaForm.locator('select[name="preferred_mfa_method"]').selectOption('email');
  await mfaForm.locator('input[name="current_password"]').fill(fakePassword());
  expectHttpError(403, portalPathname('/portal/account/mfa'));
  await assertStepUpRefused(
    await submit(page, mfaForm.getByRole('button', { name: t('update_mfa'), exact: true }),
      { pathname: portalPathname('/portal/account/mfa') }),
    '/portal/account/mfa',
    'MFA change',
  );

  // The seeded password still passes the same step-up, so the refused password change changed
  // nothing. A good step-up also clears the failure count the three refusals built up.
  await mfaForm.locator('select[name="preferred_mfa_method"]').selectOption('email');
  await mfaForm.locator('input[name="current_password"]').fill(lockAccount.password);
  const goodStepUp = await submit(
    page,
    mfaForm.getByRole('button', { name: t('update_mfa'), exact: true }),
    { pathname: portalPathname('/portal/account/mfa') },
  );
  assert(goodStepUp.status() === 303, `the seeded password was refused: ${goodStepUp.status()}`);
  await page.waitForURL((url) => (
    url.pathname === portalPathname('/portal/account')
    && url.searchParams.get('status') === 'mfa-updated'
  ));
  await page.getByRole('status').filter({ hasText: t('account_status_mfa_updated') }).waitFor();
  assert((await accountDetail(page, 'email').innerText()).trim() === lockAccount.email,
    'the email address moved although every contact change was refused');
  await signOut(page, context);

  // Wrong passwords at sign-in up to the configured threshold. The last one locks the account
  // but still answers like any wrong password.
  for (let attempt = 1; attempt <= settings.lockThreshold; attempt += 1) {
    await fillSignIn(page, lockAccount.username, fakePassword());
    expectHttpError(401, portalPathname('/auth/login'));
    const wrong = await submit(page, signInButton(page), {
      pathname: portalPathname('/auth/login'),
    });
    assert(wrong.status() === 401,
      `wrong password ${attempt} of ${settings.lockThreshold} returned ${wrong.status()}`);
    await page.getByRole('alert').filter({ hasText: t('incorrect_username_or_password') })
      .waitFor();
  }

  // Now the right password reaches the locked page (423), with no way to sign in from it.
  await fillSignIn(page, lockAccount.username, lockAccount.password);
  expectHttpError(423, portalPathname('/auth/login'));
  const locked = await submit(page, signInButton(page), {
    pathname: portalPathname('/auth/login'),
  });
  assert(locked.status() === 423, `the locked account's sign-in returned ${locked.status()}`);
  await page.getByRole('heading', { name: t('session_locked_heading'), exact: true }).waitFor();
  await page.getByRole('alert').filter({ hasText: t('session_locked_details') }).waitFor();
  assert(
    await page.locator('input[name="username"], input[name="password"], input[name="code"]')
      .count() === 0,
    'the locked page must not offer a sign-in or code form'
  );
  assert(await page.getByRole('button', { name: t('clinic_help'), exact: true }).count() === 1,
    'the locked page should offer clinic help');
  assert(
    !(await context.cookies()).some((cookie) => cookie.name === settings.sessionCookieName),
    'a locked sign-in must not receive a session cookie'
  );
  await assertAccessiblePage(page, 'locked page');
  await page.screenshot({ path: screenshotPath('patient-portal-account-locked'), fullPage: true });

  // A wrong password on the locked account gets the ordinary answer: only the right password
  // learns that the account is locked.
  await page.getByRole('link', { name: t('back_to_sign_in'), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/'));
  await fillSignIn(page, lockAccount.username, fakePassword());
  expectHttpError(401, portalPathname('/auth/login'));
  const wrongWhileLocked = await submit(page, signInButton(page), {
    pathname: portalPathname('/auth/login'),
  });
  assert(wrongWhileLocked.status() === 401,
    `a wrong password on the locked account returned ${wrongWhileLocked.status()}`);
  await page.getByRole('alert').filter({ hasText: t('incorrect_username_or_password') }).waitFor();
  assert(
    await page.getByRole('heading', { name: t('session_locked_heading'), exact: true }).count()
      === 0,
    'a wrong password revealed that the account is locked'
  );
}

// ---- Step 1, first half: confirm the pending email change from another browser ----
async function checkEmailChangeConfirmation(page, context, confirmPage) {
  await signIn(page, emailAccount, {
    recipient: emailAccount.oldEmail,
    destination: {
      includes: emailDomain(emailAccount.oldEmail),
      excludes: emailDomain(emailAccount.newEmail),
    },
  });
  await openModule(page, 'account', '/portal/account');
  // The change is pending, so nothing has moved yet.
  assert((await accountDetail(page, 'email').innerText()).trim() === emailAccount.oldEmail,
    'a pending email change already moved the displayed address');
  assert(await page.locator('input[name="email"]').inputValue() === emailAccount.oldEmail,
    'a pending email change already moved the contact form address');

  // Without a fragment there is no token: the page says so at once and the form never posts.
  await open(confirmPage, '/auth/email-change/confirm');
  await confirmPage.getByRole('heading', {
    name: t('email_change_complete_heading'), exact: true,
  }).waitFor();
  const tokenError = confirmPage.locator('[data-reset-token-error]');
  await tokenError.waitFor({ state: 'visible' });
  assert((await tokenError.innerText()).trim() === t('email_change_complete_error'),
    'the missing-token error has the wrong text');
  let emptyPosts = 0;
  const countEmptyPost = (request) => {
    if (request.method() === 'POST'
      && new URL(request.url()).pathname === portalPathname('/auth/email-change/confirm')) {
      emptyPosts += 1;
    }
  };
  confirmPage.on('request', countEmptyPost);
  await confirmPage.getByRole('button', { name: t('email_change_confirm'), exact: true }).click();
  await confirmPage.waitForFunction(
    () => document.activeElement?.hasAttribute('data-reset-token-error') === true
  );
  confirmPage.off('request', countEmptyPost);
  assert(emptyPosts === 0, 'the email-change form posted without a token');

  // A real navigation in between: going from the bare page to the same path with a fragment would
  // only scroll, and the page script that reads the fragment would not run again.
  await confirmPage.getByRole('link', { name: t('back_to_sign_in'), exact: true }).click();
  await confirmPage.waitForURL((url) => url.pathname === portalPathname('/'));

  const confirmationPath = (
    `/auth/email-change/confirm#token=${encodeURIComponent(emailAccount.token)}`
  );
  await open(confirmPage, confirmationPath);
  await confirmPage.waitForFunction(() => window.location.hash === '');
  assert(!confirmPage.url().includes('#'), 'the confirmation token stayed in the address bar');
  assert(
    await confirmPage.locator('input[name="reset_token"]').inputValue() === emailAccount.token,
    'the confirmation token was not copied from the fragment into the form'
  );
  assert(await tokenError.isHidden(), 'the missing-token error showed although a token arrived');
  await assertAccessiblePage(confirmPage, 'email-change confirmation page');

  const confirmButton = confirmPage.getByRole('button', {
    name: t('email_change_confirm'), exact: true,
  });
  const confirmed = await submit(confirmPage, confirmButton, {
    pathname: portalPathname('/auth/email-change/confirm'),
  });
  assert(confirmed.status() === 200, `confirming the email change returned ${confirmed.status()}`);
  await confirmPage.getByRole('heading', {
    name: t('email_change_success_heading'), exact: true,
  }).waitFor();
  await confirmPage.getByRole('status').filter({ hasText: t('email_change_success') }).waitFor();
  assert(!(await confirmPage.locator('body').innerText()).includes(emailAccount.token),
    'the confirmation result echoed the token');
  await confirmPage.screenshot({
    path: screenshotPath('patient-portal-account-email-confirmed'),
    fullPage: true,
  });

  // The same link again is refused with the generic invalid-link message.
  await confirmPage.getByRole('link', { name: t('sign_in_button'), exact: true }).click();
  await confirmPage.waitForURL((url) => url.pathname === portalPathname('/'));
  await open(confirmPage, confirmationPath);
  await confirmPage.waitForFunction(() => window.location.hash === '');
  expectHttpError(400, portalPathname('/auth/email-change/confirm'));
  const replayed = await submit(confirmPage, confirmButton, {
    pathname: portalPathname('/auth/email-change/confirm'),
  });
  assert(replayed.status() === 400, `a replayed confirmation returned ${replayed.status()}`);
  await confirmPage.locator('p.form-error[role="alert"]:not([data-reset-token-error])')
    .filter({ hasText: t('email_change_complete_error') })
    .waitFor();
  assert(
    await confirmPage.getByRole('heading', {
      name: t('email_change_success_heading'), exact: true,
    }).count() === 0,
    'a replayed confirmation reported success'
  );

  // Moving the address signs out every session, including this one opened before the change.
  await open(page, '/portal/account');
  await page.waitForURL((url) => url.pathname === portalPathname('/'));
  await page.getByRole('heading', { name: t('sign_in_heading'), exact: true }).waitFor();
  assert(
    !(await context.cookies()).some((cookie) => cookie.name === settings.sessionCookieName),
    'the session from before the email change was not cleared'
  );
}

// ---- Step 1, second half: the new address is the account's address and MFA destination ----
async function checkEmailChangeApplied(page, context) {
  await signIn(page, emailAccount, {
    recipient: emailAccount.newEmail,
    destination: {
      includes: emailDomain(emailAccount.newEmail),
      excludes: emailDomain(emailAccount.oldEmail),
    },
  });
  await openModule(page, 'account', '/portal/account');
  assert((await accountDetail(page, 'email').innerText()).trim() === emailAccount.newEmail,
    'the account page does not show the confirmed address');
  assert(await page.locator('input[name="email"]').inputValue() === emailAccount.newEmail,
    'the contact form does not hold the confirmed address');
  await signOut(page, context);
}

// ---- Step 3: linked devices, removal confirmation, Keep and Remove ----
async function checkLinkedDevices(page) {
  await openModule(page, 'account', '/portal/account');
  const markupDevice = linkAccount.devices.find((device) => device.name.includes('<'));
  const keptDevice = linkAccount.devices.find((device) => device !== markupDevice);
  assert(markupDevice && keptDevice, 'the device fixture needs one name with markup in it');
  const section = page.locator('section.settings-section', {
    has: page.locator('#mycarlos-devices-heading'),
  });
  assert((await section.locator('#mycarlos-devices-heading').innerText()).trim()
    === t('mycarlos_devices'), 'the linked-devices section is missing');
  const listedNames = async () => (
    await section.locator('ul.mycarlos-devices > li h3.mycarlos-device-name').allTextContents()
  ).map((name) => name.trim()).sort();
  assert(
    JSON.stringify(await listedNames())
      === JSON.stringify(linkAccount.devices.map((device) => device.name).sort()),
    `the account page should list both seeded devices, got ${JSON.stringify(await listedNames())}`
  );
  // The markup in a device name is shown as text, never parsed into an element.
  assert(await section.locator('ul.mycarlos-devices b').count() === 0,
    'a device name was rendered as HTML');
  const deviceItem = (device) => section.locator('ul.mycarlos-devices > li').filter({
    has: page.locator('h3.mycarlos-device-name', { hasText: exactText(device.name) }),
  });
  // Linked, then Last seen (_mycarlos_devices.jinja:9-10).
  assert((await deviceItem(markupDevice).locator('dd').nth(1).innerText()).trim()
    === t('mycarlos_not_seen'), 'a device never seen should say so');
  assert((await deviceItem(keptDevice).locator('dd').nth(1).innerText()).trim()
    !== t('mycarlos_not_seen'), 'a seen device should show when it was last seen');

  const removeLink = (device) => section.getByRole('link', {
    name: `${t('mycarlos_remove')}: ${device.name}`,
    exact: true,
  });
  const removePortalPath = (
    `/portal/account/mycarlos/devices/${encodeURIComponent(markupDevice.deviceKeyId)}/remove`
  );
  const removePath = portalPathname(removePortalPath);
  assert((await removeLink(markupDevice).getAttribute('href') || '').endsWith(removePath),
    'the remove link does not name the device');

  async function openRemovalConfirmation() {
    await removeLink(markupDevice).click();
    await page.waitForURL((url) => url.pathname === removePath);
    await page.getByRole('heading', { name: t('mycarlos_remove_question'), exact: true })
      .waitFor();
    assert((await page.locator('.mycarlos-device-name strong').innerText()).trim()
      === markupDevice.name, 'the confirmation page names the wrong device');
    await page.getByText(t('mycarlos_remove_effect'), { exact: true }).waitFor();
    assert(await page.locator(`form[action$="${removePath}"]`).count() === 1,
      'the confirmation page has no removal form for this device');
    assert(await page.locator('.mycarlos-code, .mycarlos-portal-address').count() === 0,
      'the confirmation page must not show linking details');
  }

  await openRemovalConfirmation();
  await assertAccessiblePage(page, 'device removal confirmation');
  // Keep leaves the device linked.
  await page.getByRole('link', { name: t('mycarlos_keep'), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/portal/account'));
  assert((await listedNames()).length === 2, 'Keep device removed a device');
  assert(await page.getByRole('status').filter({ hasText: t('mycarlos_removed') }).count() === 0,
    'Keep device reported a removal');

  // Remove removes that device only.
  await openRemovalConfirmation();
  const removed = await submit(
    page,
    page.getByRole('button', { name: t('mycarlos_remove'), exact: true }),
    { pathname: removePath },
  );
  assert(removed.status() === 303, `removing a device returned ${removed.status()}`);
  await page.waitForURL((url) => (
    url.pathname === portalPathname('/portal/account')
    && url.searchParams.get('status') === 'mycarlos-device-removed'
  ));
  await page.getByRole('status').filter({ hasText: t('mycarlos_removed') }).waitFor();
  assert(JSON.stringify(await listedNames()) === JSON.stringify([keptDevice.name]),
    `only the other device should remain, got ${JSON.stringify(await listedNames())}`);
  assert(await removeLink(markupDevice).count() === 0, 'the removed device still has a link');
  assert(await removeLink(keptDevice).count() === 1, 'the remaining device lost its link');
  await page.screenshot({
    path: screenshotPath('patient-portal-account-device-removed'),
    fullPage: true,
  });

  // The removed device is gone server-side: its old confirmation link now finds nothing.
  expectHttpError(404, removePath);
  const gone = await open(page, removePortalPath);
  assert(gone && gone.status() === 404,
    `the removed device's link returned ${gone && gone.status()}`);
  await page.getByRole('heading', { name: t('request_failed_heading'), exact: true }).waitFor();
  assert(await page.locator('form[action*="/mycarlos/devices/"]').count() === 0,
    'a removed device can still be removed');
  await open(page, '/portal');
  await page.getByRole('heading', { name: t('dashboard_greeting'), exact: true }).waitFor();
}

function createCodeButton(page, labelKey) {
  return page.getByRole('button', { name: t(labelKey), exact: true });
}

async function createLinkCode(page, labelKey) {
  const response = await submit(page, createCodeButton(page, labelKey), {
    pathname: portalPathname('/portal/mycarlos/code'),
  });
  assert(response.status() === 200, `creating a link code returned ${response.status()}`);
  const headers = response.headers();
  assert(headers['cache-control'] === 'no-store', 'a page with a link code must not be cached');
  assert((headers['content-security-policy'] || '').includes("img-src 'self' data:"),
    'the link code page must allow its inline QR image and nothing more');
  const code = (await page.locator('.mycarlos-code code').innerText()).trim();
  assert(linkCodePattern.test(code), `the link code has an unexpected shape: ${code}`);
  assert(!page.url().includes(code) && !page.url().includes(code.replace(/-/g, '')),
    'the link code leaked into the address bar');
  assert(
    (await page.locator('#mycarlos-code-label').innerText()).trim() === t('mycarlos_code_label'),
    'the link code has no label'
  );
  assert(await page.locator('.mycarlos-code code').getAttribute('aria-labelledby')
    === 'mycarlos-code-label', 'the link code is not tied to its label');
  await page.getByRole('heading', { name: t('mycarlos_qr_label'), exact: true }).waitFor();
  const qr = page.locator('img.mycarlos-link-qr');
  assert(await qr.getAttribute('alt') === t('mycarlos_qr_alt'), 'the QR image has the wrong alt');
  const qrState = await qr.evaluate((image) => new Promise((resolve) => {
    const report = () => resolve({
      naturalHeight: image.naturalHeight,
      naturalWidth: image.naturalWidth,
      src: image.getAttribute('src') || '',
    });
    if (image.complete) {
      report();
    } else {
      image.addEventListener('load', report, { once: true });
      image.addEventListener('error', report, { once: true });
    }
  }));
  assert(qrState.naturalWidth > 0 && qrState.naturalHeight > 0,
    'the QR image did not load (is it blocked by the page CSP?)');
  assert(qrState.src.startsWith('data:image/png;base64,'), 'the QR image is not rendered inline');
  await page.getByText(t('mycarlos_lifetime'), { exact: true }).waitFor();
  assert(await createCodeButton(page, 'mycarlos_another').count() === 1
    && await createCodeButton(page, 'mycarlos_create').count() === 0,
  'after a code the button should offer another code');
  return code;
}

async function assertNoCodeShown(page, surface) {
  assert(await page.locator('.mycarlos-code, img.mycarlos-link-qr').count() === 0,
    `${surface} must not show a link code`);
}

function proofCookie(context) {
  return context.cookies().then((cookies) => (
    cookies.find((cookie) => cookie.name === settings.proofCookieName)
  ));
}

// ---- Step 2, first half: create codes while the sign-in's MFA proof is present ----
async function checkLinkCodes(page, context) {
  const proof = await proofCookie(context);
  assert(proof, 'a verified email sign-in in development should carry the myCarlos MFA proof');
  assert(proof.httpOnly && proof.sameSite === 'Strict'
    && proof.path === portalPathname('/portal') && proof.value.startsWith('email.'),
  'the myCarlos MFA proof cookie has the wrong flags or scope');

  await open(page, '/portal');
  const tile = page.locator('a.module-tile', {
    has: page.getByRole('heading', { name: t('mycarlos_link'), exact: true }),
  });
  assert(await tile.count() === 1, 'the dashboard should offer Link myCarlos');
  assert((await tile.innerText()).includes(t('mycarlos_approval')),
    'the Link myCarlos tile should say devices need approval');
  const [pageResponse] = await Promise.all([
    page.waitForResponse((response) => response.request().method() === 'GET'
      && new URL(response.url()).pathname === portalPathname('/portal/mycarlos')),
    tile.click(),
  ]);
  await page.waitForURL((url) => url.pathname === portalPathname('/portal/mycarlos'));
  assert(pageResponse.headers()['cache-control'] === 'no-store',
    'the linking page must not be cached');
  await page.getByRole('heading', { name: t('mycarlos_link'), exact: true, level: 1 }).waitFor();
  assert((await page.locator('.module-nav a[aria-current="page"]').innerText()).trim()
    === t('mycarlos_link'), 'the navigation does not mark Link myCarlos as current');
  await page.getByRole('heading', { name: t('mycarlos_portal_address'), exact: true }).waitFor();
  assert((await page.locator('.mycarlos-portal-address code').innerText()).trim()
    === settings.publicBaseUrl, 'the linking page shows the wrong portal address');
  // Opening the page never makes a code (README: a GET never creates one).
  await assertNoCodeShown(page, 'the linking page before Create');
  assert(await createCodeButton(page, 'mycarlos_create').count() === 1,
    'the linking page should offer Create a code');
  await page.getByText(t('mycarlos_approval'), { exact: true }).waitFor();
  await assertAccessiblePage(page, 'Link myCarlos page');

  const firstCode = await createLinkCode(page, 'mycarlos_create');
  await assertAccessiblePage(page, 'Link myCarlos page with a code');
  await page.setViewportSize({ width: 390, height: 844 });
  await assertNoHorizontalOverflow(page, 'mobile Link myCarlos page with a code');
  await page.setViewportSize({ width: 1280, height: 900 });

  // A code is shown once: opening the page again shows none.
  const reopened = await open(page, '/portal/mycarlos');
  assert(reopened && reopened.status() === 200, 'the linking page did not reopen');
  await assertNoCodeShown(page, 'the reopened linking page');
  assert(await createCodeButton(page, 'mycarlos_create').count() === 1,
    'the reopened linking page should offer Create a code again');
  await page.screenshot({ path: screenshotPath('patient-portal-account-mycarlos'), fullPage: true });

  const secondCode = await createLinkCode(page, 'mycarlos_create');
  assert(secondCode !== firstCode
    && secondCode.split('-')[0] !== firstCode.split('-')[0],
  'a second code must be a new link, not the first one again');
}

// ---- Step 2, second half: without the MFA proof no code is made ----
async function checkMfaProofGate(page, context) {
  await open(page, '/portal/mycarlos');
  assert(await createCodeButton(page, 'mycarlos_create').count() === 1,
    'the linking page should offer Create a code while the proof is present');
  // As if the proof had lapsed while this page was open.
  await context.clearCookies({ name: settings.proofCookieName });
  assert(!(await proofCookie(context)), 'the MFA proof cookie could not be cleared');

  const verifyButton = page.getByRole('button', { name: t('mycarlos_verify'), exact: true });
  const mfaForm = page.locator(`form[action$="${portalPathname('/portal/mycarlos/mfa')}"]`);
  expectHttpError(403, portalPathname('/portal/mycarlos/code'));
  const refused = await submit(page, createCodeButton(page, 'mycarlos_create'), {
    pathname: portalPathname('/portal/mycarlos/code'),
  });
  assert(refused.status() === 403, `a code without the MFA proof returned ${refused.status()}`);
  await page.getByRole('alert').filter({ hasText: t('mycarlos_mfa_required') }).waitFor();
  await assertNoCodeShown(page, 'a refused code request');
  assert(await createCodeButton(page, 'mycarlos_create').count() === 0
    && await mfaForm.count() === 1 && await verifyButton.count() === 1,
  'without the proof the page should offer Verify sign-in instead of Create');

  await open(page, '/portal/mycarlos');
  assert(await page.locator('.module-workspace [role="alert"]').count() === 0,
    'opening the linking page should not show an error');
  await page.getByText(t('mycarlos_mfa_required'), { exact: true }).waitFor();
  assert(await createCodeButton(page, 'mycarlos_create').count() === 0
    && await verifyButton.count() === 1,
  'the reopened page should still ask for verification');

  if (!settings.stepUpEmailAvailable) {
    // No mail server: the step-up has no way to send a code and must say linking is unavailable
    // rather than show a code page it cannot back (routes/mycarlos_portal.py start_step_up).
    expectHttpError(409, portalPathname('/portal/mycarlos/mfa'));
    const unavailable = await submit(page, verifyButton, {
      pathname: portalPathname('/portal/mycarlos/mfa'),
    });
    assert(unavailable.status() === 409,
      `the step-up without a mail server returned ${unavailable.status()}`);
    await page.getByRole('alert').filter({ hasText: t('mycarlos_unavailable') }).waitFor();
    assert(await page.getByRole('heading', { name: t('mfa_heading'), exact: true }).count() === 0,
      'the step-up showed a code page although no code could be sent');
    await assertNoCodeShown(page, 'an unavailable step-up');
    return;
  }

  // A mail server is configured: complete the step-up, then the gate opens again.
  await waitForMfaCooldown(linkAccount);
  if (!useDevelopmentMfaCode) {
    runMailCommand('clear');
  }
  const stepUp = await submit(page, verifyButton, {
    pathname: portalPathname('/portal/mycarlos/mfa'),
  });
  assert(stepUp.status() === 200, `the step-up returned ${stepUp.status()}`);
  await page.getByRole('heading', { name: t('mfa_heading'), exact: true }).waitFor();
  await enterMfaCode(page, linkAccount, linkAccount.email);
  assert(await proofCookie(context), 'the completed step-up did not restore the MFA proof');
  await open(page, '/portal/mycarlos');
  await createLinkCode(page, 'mycarlos_create');
}

// ---- Step 2, recovery without a mail server: a fresh sign-in restores the proof ----
async function checkProofRestoredBySignIn(page, context) {
  await signIn(page, linkAccount);
  assert(await proofCookie(context), 'a fresh sign-in did not restore the MFA proof');
  await open(page, '/portal/mycarlos');
  assert(await page.getByRole('button', { name: t('mycarlos_verify'), exact: true }).count() === 0,
    'the linking page still asks for verification after a fresh sign-in');
  await createLinkCode(page, 'mycarlos_create');
}

// ---- Step 5: "None of these work" on offered appointment times ----
async function checkDeclineOfferedTimes(page) {
  const decline = linkAccount.decline;
  await openModule(page, 'messages', '/portal/messages');
  const row = page.locator('.message-row').filter({ hasText: decline.title });
  assert(await row.count() === 1, 'the seeded offer is not in the message list');
  assert(await row.locator('.message-badge').count() === 1, 'the unopened offer should be new');
  await row.click();
  await page.waitForURL((url) => url.pathname.startsWith(portalPathname('/portal/messages/')));
  const messagePathname = new URL(page.url()).pathname;
  await page.getByRole('heading', { name: decline.title, exact: true }).waitFor();
  const times = page.getByRole('group', { name: t('booking_slots_legend') }).getByRole('radio');
  assert(await times.count() === decline.slotCount,
    `the offer should list ${decline.slotCount} times`);
  assert(await page.getByRole('button', { name: t('booking_choose'), exact: true }).count() === 1,
    'the offer should let the patient choose a time');
  const choiceAction = await page.locator('form.booking-choice-form').getAttribute('action');
  const offeredSlot = await page.locator('input[name="slot"]').first().getAttribute('value');
  assert(choiceAction && offeredSlot, 'the offer form is incomplete');
  await assertAccessiblePage(page, 'offered times');

  const declined = await submit(
    page,
    page.getByRole('button', { name: t('booking_decline'), exact: true }),
    { pathname: `${messagePathname}/decline` },
  );
  assert(declined.status() === 303, `declining the offer returned ${declined.status()}`);
  assert(atPath(page, messagePathname), 'declining did not return to the message');

  async function assertDeclinedPage(surface) {
    assert((await page.locator('.message-detail .message-contact').innerText()).trim()
      === decline.contactText, `${surface} should tell the patient to contact the clinic`);
    assert(await page.locator('.message-detail form, input[name="slot"]').count() === 0,
      `${surface} must offer nothing more to pick or decline`);
  }

  await assertDeclinedPage('a declined offer');
  assert(await page.getByRole('alert').count() === 0, 'declining showed an error');
  await page.screenshot({ path: screenshotPath('patient-portal-account-declined'), fullPage: true });

  // Revisited from the list, the offer stays closed and is no longer new.
  await page.getByRole('link', { name: t('message_back'), exact: true }).click();
  await page.waitForURL((url) => url.pathname === portalPathname('/portal/messages'));
  assert(await row.locator('.message-badge').count() === 0, 'a declined offer is still new');
  await row.click();
  await page.waitForURL((url) => url.pathname === messagePathname);
  await assertDeclinedPage('a revisited declined offer');

  // The server refuses a time from the closed offer. A second tab opened before declining would
  // be refused one step earlier (its CSRF token no longer matches the cookie, which every portal
  // page render rotates), so the old form's fields are posted with this page's current token to
  // reach the offer's own check.
  expectHttpError(409, `${messagePathname}/choice`);
  const staleResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === `${messagePathname}/choice`
  ));
  const staleNavigation = page.waitForEvent('framenavigated', {
    predicate: (frame) => frame === page.mainFrame(),
  });
  staleResponsePromise.catch(() => {});
  staleNavigation.catch(() => {});
  await page.evaluate(({ action, slot }) => {
    const csrfToken = document.querySelector('.logout-form input[name="csrf_token"]').value;
    const form = document.createElement('form');
    form.method = 'post';
    form.action = action;
    for (const [name, value] of [['csrf_token', csrfToken], ['slot', slot]]) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.append(input);
    }
    document.body.append(form);
    form.submit();
  }, { action: choiceAction, slot: offeredSlot });
  const stale = await staleResponsePromise;
  await staleNavigation;
  await page.waitForLoadState('load');
  assert(stale.status() === 409, `a time from a declined offer returned ${stale.status()}`);
  await page.getByRole('alert').filter({ hasText: t('booking_choice_error') }).waitFor();
  await assertDeclinedPage('a refused pick on a declined offer');
}

(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(chromePath ? { executablePath: chromePath } : {}),
  });
  const contexts = [];

  async function newPage(label) {
    // One context per patient, as separate devices: no cookie is shared between them.
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    contexts.push(context);
    watchContext(context, label);
    const page = await context.newPage();
    watchPage(page, label);
    return { context, page };
  }

  async function closeBrowser() {
    for (const context of contexts) {
      await context.close().catch(() => {});
    }
    await browser.close().catch(() => {});
  }

  // Nothing here can be put back the way the main check restores its password: the fixtures are
  // single-use by design. An interrupted run only needs its browser closed and a fresh database.
  let signalHandled = false;
  for (const [signal, exitCode] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    process.once(signal, () => {
      if (signalHandled) {
        return;
      }
      signalHandled = true;
      console.error(`${signal}: stopping. Recreate the database and reseed before the next run.`);
      void (async () => {
        await closeBrowser();
        process.exit(exitCode);
      })();
    });
  }

  try {
    if (!useDevelopmentMfaCode) {
      runMailCommand('clear');
    }
    const lock = await newPage('lock');
    await checkWrongPasswordsAndLockout(lock.page, lock.context);

    const email = await newPage('email-change');
    const otherDevice = await newPage('email-confirm');
    await checkEmailChangeConfirmation(email.page, email.context, otherDevice.page);

    const link = await newPage('mycarlos');
    await signIn(link.page, linkAccount);
    // Removal needs the MFA proof too, so devices come before the proof is cleared.
    await checkLinkedDevices(link.page);
    await checkLinkCodes(link.page, link.context);
    await checkDeclineOfferedTimes(link.page);
    await checkMfaProofGate(link.page, link.context);
    await signOut(link.page, link.context);

    // Second sign-ins wait out each account's MFA email cooldown, so they come last.
    await checkEmailChangeApplied(email.page, email.context);
    if (!settings.stepUpEmailAvailable) {
      await checkProofRestoredBySignIn(link.page, link.context);
      await signOut(link.page, link.context);
    }

    const unmet = expectedErrors.filter((expected) => !expected.seen);
    assert(unmet.length === 0,
      `expected HTTP errors were not observed: ${JSON.stringify(unmet)}`);
    assert(badResponses.length === 0, `unexpected HTTP errors: ${JSON.stringify(badResponses)}`);
    assert(browserIssues.length === 0, `browser errors: ${JSON.stringify(browserIssues)}`);
    console.log('Patient portal account Playwright checks passed');
    for (const name of [
      'patient-portal-account-locked',
      'patient-portal-account-email-confirmed',
      'patient-portal-account-device-removed',
      'patient-portal-account-mycarlos',
      'patient-portal-account-declined',
    ]) {
      console.log(`Screenshot: ${screenshotPath(name)}`);
    }
  } finally {
    await closeBrowser();
  }
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
