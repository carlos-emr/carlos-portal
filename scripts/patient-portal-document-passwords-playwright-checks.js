#!/usr/bin/env node
/*
 * Browser check for the empty "Document passwords" section at phone width.
 *
 * Starts its own throwaway portal (tests/serve_document_passwords_browser.py: an in-memory
 * database, the seeded FAKE patient already signed in), so it needs no running server and
 * touches no real data:
 *
 *   npm run test:patient-portal-document-passwords-playwright
 *
 * Optional environment:
 *   PORTAL_PYTHON=python        the interpreter with the portal's dependencies
 *   PORTAL_DOCUMENT_PASSWORDS_PORT=8431
 *   PORTAL_SCREENSHOT_DIR=/tmp
 *   PORTAL_CHROME_PATH=/path/to/chrome-or-chromium
 *
 * It checks, at 390 px and at 320 px, in every language: the section heading stays, the empty
 * state is the explanation (not the bare "No document passwords" line), the text is inside the
 * screen with no sideways scroll, a search that finds nothing keeps its own short line, and axe
 * finds no serious accessibility issue.
 */

const { spawn } = require('node:child_process');
const { mkdirSync, readFileSync, existsSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { assertNoSeriousAxeIssues } = require('./patient-portal-axe');

const pythonCommand = process.env.PORTAL_PYTHON || 'python';
const port = Number(process.env.PORTAL_DOCUMENT_PASSWORDS_PORT || 8431);
const screenshotDir = path.resolve(process.env.PORTAL_SCREENSHOT_DIR || os.tmpdir());
const chromePath = process.env.PORTAL_CHROME_PATH || process.env.CHROME_PATH || '';
const fixturePath = path.join(os.tmpdir(), `patient-portal-docpw-${process.pid}.json`);
const origin = `http://127.0.0.1:${port}`;
const catalogueScript = `
import json, sys
sys.path.insert(0, ${JSON.stringify(path.join(__dirname, '..'))})
from carlos_patient_portal.i18n import SUPPORTED_LOCALES, portal_text
print(json.dumps({l.code: {k: portal_text(l.code)[k] for k in
  ('no_email_passwords', 'no_matching_email_passwords', 'email_passwords')} for l in SUPPORTED_LOCALES}))
`;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

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
    [path.join(__dirname, '..', 'tests', 'serve_document_passwords_browser.py'), fixturePath, String(port)],
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
    for (const [locale, text] of Object.entries(catalogues)) {
      for (const [width, height] of [[390, 844], [320, 640]]) {
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
        await page.goto(`${origin}/portal/email-passwords`, { waitUntil: 'domcontentloaded' });
        const surface = `Document passwords, empty, ${locale}, ${width}px`;
        await page.locator('.empty-state').first().waitFor();
        const shown = (await page.locator('.empty-state').first().innerText()).replace(/\s+/g, ' ').trim();
        assert(shown === text.no_email_passwords.replace(/\s+/g, ' ').trim(),
          `${surface}: the empty state is not the explanation: ${JSON.stringify(shown)}`);
        assert(await page.getByRole('heading', { name: text.email_passwords }).count() > 0,
          `${surface}: the section heading is gone`);
        const layout = await page.evaluate(() => {
          const cell = document.querySelector('.empty-state');
          const box = cell.getBoundingClientRect();
          return {
            documentWidth: document.documentElement.scrollWidth,
            viewportWidth: window.innerWidth,
            left: box.left, right: box.right,
            cellOverflow: cell.scrollWidth - cell.clientWidth,
          };
        });
        assert(layout.documentWidth <= layout.viewportWidth + 1,
          `${surface}: sideways scroll (${layout.documentWidth}px > ${layout.viewportWidth}px)`);
        assert(layout.left >= -1 && layout.right <= layout.viewportWidth + 1,
          `${surface}: the note is outside the screen (${layout.left} to ${layout.right})`);
        assert(layout.cellOverflow <= 1, `${surface}: the note overflows its own box`);
        if (width === 390) await assertNoSeriousAxeIssues(page, surface, 'light');
        if (width === 320 && locale === 'en') {
          await page.screenshot({ path: path.join(screenshotDir, `document-passwords-empty-${locale}-${width}.png`), fullPage: true });
        }
        // A search that finds nothing: its own short line, not the explanation.
        await page.goto(`${origin}/portal/email-passwords?q=missing`, { waitUntil: 'domcontentloaded' });
        const searched = (await page.locator('.empty-state').first().innerText()).replace(/\s+/g, ' ').trim();
        assert(searched === text.no_matching_email_passwords.replace(/\s+/g, ' ').trim(),
          `${surface}: a search that finds nothing shows ${JSON.stringify(searched)}`);
        await context.close();
      }
    }
    console.log(`Document passwords empty state OK in ${Object.keys(catalogues).length} languages at 390 and 320 px.`);
  } finally {
    if (browser) await browser.close().catch(() => {});
    server.kill('SIGTERM');
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
