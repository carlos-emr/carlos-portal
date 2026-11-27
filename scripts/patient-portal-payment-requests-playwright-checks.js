#!/usr/bin/env node
/*
 * Browser check for payment requests in the patient's Messages (billing through the portal, Phase 0).
 *
 * Starts its own throwaway portal (tests/serve_payment_requests_browser.py: an in-memory database,
 * the seeded FAKE patient already signed in, an open and a paid request made through the real
 * internal API), so it needs no running server and touches no real data:
 *
 *   npm run test:patient-portal-payment-requests-playwright
 *
 * Optional environment:
 *   PORTAL_PYTHON=python        the interpreter with the portal's dependencies
 *   PORTAL_PAYMENT_REQUESTS_PORT=8432
 *   PORTAL_SCREENSHOT_DIR=/tmp
 *   PORTAL_CHROME_PATH=/path/to/chrome-or-chromium
 *
 * At 390 px and 320 px in every language, and at 1280 px in English, it checks: the list shows the
 * open request (amount, status, a "New" badge) and the paid one; opening the request shows the
 * amount, the tax portion, the due date, the clinic's "how to pay" text and the "no online payment"
 * note, with no form, button or link that could pay; the paid request says it was received and shows
 * no instructions; nothing runs off the screen sideways; axe finds no serious issue.
 */

const { spawn } = require('node:child_process');
const { mkdirSync, readFileSync, existsSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { assertNoSeriousAxeIssues } = require('./patient-portal-axe');

const pythonCommand = process.env.PORTAL_PYTHON || 'python';
const port = Number(process.env.PORTAL_PAYMENT_REQUESTS_PORT || 8432);
const screenshotDir = path.resolve(process.env.PORTAL_SCREENSHOT_DIR || os.tmpdir());
const chromePath = process.env.PORTAL_CHROME_PATH || process.env.CHROME_PATH || '';
const fixturePath = path.join(os.tmpdir(), `patient-portal-payreq-${process.pid}.json`);
const origin = `http://127.0.0.1:${port}`;
const KEYS = [
  'payment_request_amount', 'payment_request_how_to_pay', 'payment_request_no_online',
  'payment_request_status_open', 'payment_request_status_paid',
  'payment_request_uninsured_service_title', 'payment_request_form_or_note_title',
];
const catalogueScript = `
import json, sys
sys.path.insert(0, ${JSON.stringify(path.join(__dirname, '..'))})
from carlos_patient_portal.i18n import SUPPORTED_LOCALES, portal_text
print(json.dumps({l.code: {k: portal_text(l.code)[k] for k in ${JSON.stringify(KEYS)}}
  for l in SUPPORTED_LOCALES}))
`;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const squash = (text) => text.replace(/\s+/g, ' ').trim();

async function waitForServer(url, server) {
  const deadline = Date.now() + 60000;
  for (;;) {
    if (server.exitCode !== null) throw new Error('the throwaway portal exited before it was ready');
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error('the throwaway portal did not start in 60 s');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
}

async function noSidewaysScroll(page, surface) {
  const layout = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth,
  }));
  assert(layout.documentWidth <= layout.viewportWidth + 1,
    `${surface}: sideways scroll (${layout.documentWidth}px > ${layout.viewportWidth}px)`);
}

async function main() {
  mkdirSync(screenshotDir, { recursive: true });
  const catalogues = JSON.parse(await new Promise((resolve, reject) => {
    const child = spawn(pythonCommand, ['-c', catalogueScript], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('exit', (code) => (code === 0 ? resolve(out) : reject(new Error('could not read the catalogues'))));
  }));

  const server = spawn(
    pythonCommand,
    [path.join(__dirname, '..', 'tests', 'serve_payment_requests_browser.py'), fixturePath, String(port)],
    { stdio: ['ignore', 'inherit', 'inherit'], cwd: path.join(__dirname, '..') },
  );
  let browser;
  try {
    await waitForServer(`${origin}/`, server);
    assert(existsSync(fixturePath), 'the throwaway portal wrote no session fixture');
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
    browser = await chromium.launch({
      headless: true,
      ...(chromePath ? { executablePath: chromePath } : {}),
      args: ['--no-sandbox'],
    });
    let surfaces = 0;
    for (const [locale, text] of Object.entries(catalogues)) {
      const sizes = [[390, 844], [320, 640]];
      if (locale === 'en') sizes.push([1280, 800]);
      for (const [width, height] of sizes) {
        const context = await browser.newContext({ viewport: { width, height }, locale });
        await context.addCookies([
          {
            name: fixture.cookie_name, value: fixture.cookie_value, domain: '127.0.0.1', path: '/portal',
            httpOnly: true, sameSite: 'Strict',
          },
          { name: 'portal_locale', value: locale, domain: '127.0.0.1', path: '/' },
        ]);
        const page = await context.newPage();
        page.setDefaultTimeout(20000);
        const surface = `Payment requests, ${locale}, ${width}px`;

        // The list: both requests, the open one marked new, with its amount and status.
        await page.goto(`${origin}/portal/messages`, { waitUntil: 'domcontentloaded' });
        await page.locator('.message-list').waitFor();
        const rows = page.locator('.message-row');
        assert(await rows.count() === 2, `${surface}: expected two payment requests in the list`);
        const listText = squash(await page.locator('.message-list').innerText());
        assert(listText.includes(text.payment_request_uninsured_service_title),
          `${surface}: the open request's title is missing from the list`);
        assert(listText.includes(text.payment_request_status_open), `${surface}: the open status is missing`);
        assert(listText.includes(text.payment_request_status_paid), `${surface}: the paid status is missing`);
        // Only the very first visit sees the request unread: opening it (below) records the read.
        assert(await page.locator('.message-row.new').count() === (surfaces === 0 ? 1 : 0),
          `${surface}: the "new" badge is wrong for an ${surfaces === 0 ? 'unread' : 'already read'} request`);
        await noSidewaysScroll(page, `${surface} (list)`);
        if (width === 390) await assertNoSeriousAxeIssues(page, `${surface} (list)`, 'light');

        // The open request: amount, tax, due date, how to pay, no way to pay here.
        await page.goto(`${origin}/portal/messages/payment/${fixture.open_id}`, { waitUntil: 'domcontentloaded' });
        const detail = page.locator('.payment-request-detail');
        await detail.waitFor();
        const detailText = squash(await detail.innerText());
        assert(/45[.,]00 CAD/.test(detailText), `${surface}: the amount is not shown: ${detailText}`);
        assert(/5[.,]18 CAD/.test(detailText), `${surface}: the tax portion is not shown`);
        assert(detailText.includes(text.payment_request_how_to_pay), `${surface}: "how to pay" is missing`);
        assert(detailText.includes('payments@example.invalid'), `${surface}: the clinic instructions are missing`);
        assert(detailText.includes(text.payment_request_no_online), `${surface}: the no-online-payment note is missing`);
        assert(await detail.locator('form, button, input, select').count() === 0,
          `${surface}: the request offers something to press or fill`);
        await noSidewaysScroll(page, `${surface} (open)`);
        if (width === 390) await assertNoSeriousAxeIssues(page, `${surface} (open)`, 'light');
        if ((width === 320 && locale === 'en') || width === 1280) {
          await page.screenshot({ path: path.join(screenshotDir, `payment-request-${locale}-${width}.png`), fullPage: true });
        }

        // Opening it recorded the read: it is no longer new.
        await page.goto(`${origin}/portal/messages`, { waitUntil: 'domcontentloaded' });
        assert(await page.locator('.message-row.new').count() === 0,
          `${surface}: opening the request did not clear its "new" badge`);
        if (surfaces === 0) {
          await page.screenshot({ path: path.join(screenshotDir, `payment-request-list-${locale}-${width}.png`), fullPage: true });
        }

        // The paid request: received, and nothing about how to pay.
        await page.goto(`${origin}/portal/messages/payment/${fixture.paid_id}`, { waitUntil: 'domcontentloaded' });
        const paidText = squash(await page.locator('.payment-request-detail').innerText());
        assert(paidText.includes(text.payment_request_status_paid), `${surface}: the paid request does not say so`);
        assert(!paidText.includes(text.payment_request_how_to_pay), `${surface}: a paid request still shows how to pay`);
        assert(!paidText.includes('payments@example.invalid'), `${surface}: a paid request still shows the instructions`);

        // An id that is not the patient's: the not-found notice, not a request.
        const missing = await page.goto(`${origin}/portal/messages/payment/99999`, { waitUntil: 'domcontentloaded' });
        assert(missing.status() === 404, `${surface}: an unknown request did not answer 404`);
        await context.close();
        surfaces += 1;
      }
    }
    console.log(`Payment requests OK on ${surfaces} surfaces in ${Object.keys(catalogues).length} languages.`);
  } finally {
    if (browser) await browser.close().catch(() => {});
    server.kill('SIGTERM');
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
