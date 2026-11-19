/*
 * The automatic accessibility check (carlos-emr/carlos-portal#57): axe-core runs on the page that
 * is open and the check fails on any serious or critical issue under WCAG 2.0/2.1/2.2 A and AA,
 * colour contrast included. Shared by the three browser check scripts, which call it from their
 * own accessible-page helper.
 *
 * It runs twice, in the light and then in the dark colour scheme (the device's setting, emulated),
 * and then makes a smoke check with forced colours (a Windows contrast theme, emulated): the page
 * still shows its heading and the skip link, when it has the focus, still has a visible outline.
 * Emulation is switched off again, so the caller's own steps see the page as before.
 *
 * The brand blue is #4065b2 (4.54:1 on the page background, 5.64:1 on white); the dark palette
 * and these ratios are pinned from the stylesheet in tests/test_accessibility_basics.py.
 */
const { AxeBuilder } = require('@axe-core/playwright');

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const FAILING_IMPACTS = new Set(['serious', 'critical']);

async function assertNoSeriousIssues(page, surface, scheme) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  const serious = results.violations.filter((violation) => FAILING_IMPACTS.has(violation.impact));
  if (serious.length > 0) {
    const summary = serious.map((violation) => (
      `${violation.id} (${violation.impact}, ${violation.nodes.length} element(s)): `
      + `${violation.nodes.slice(0, 3).map((node) => node.target.join(' ')).join('; ')}`
    )).join('\n  ');
    throw new Error(`${surface} has serious accessibility issues (axe, ${scheme} colours):\n  ${summary}`);
  }
}

async function assertForcedColoursSmoke(page, surface) {
  await page.emulateMedia({ forcedColors: 'active' });
  const state = await page.evaluate(() => {
    const heading = document.querySelector('h1');
    const skipLink = document.querySelector('.skip-link');
    if (skipLink instanceof HTMLElement) {
      skipLink.focus();
    }
    const outline = skipLink ? getComputedStyle(skipLink) : null;
    return {
      headingVisible: Boolean(heading && heading.getClientRects().length > 0),
      skipLinkOutline: outline
        ? { style: outline.outlineStyle, width: parseFloat(outline.outlineWidth) }
        : null,
    };
  });
  if (!state.headingVisible) {
    throw new Error(`${surface} shows no heading with forced colours`);
  }
  if (!state.skipLinkOutline || state.skipLinkOutline.style === 'none' || !(state.skipLinkOutline.width >= 2)) {
    throw new Error(`${surface}: the skip link has no visible focus outline with forced colours`);
  }
}

async function assertNoSeriousAxeIssues(page, surface) {
  await assertNoSeriousIssues(page, surface, 'light');
  try {
    await page.emulateMedia({ colorScheme: 'dark' });
    await assertNoSeriousIssues(page, surface, 'dark');
    await page.emulateMedia({ colorScheme: null });
    await assertForcedColoursSmoke(page, surface);
  } finally {
    await page.emulateMedia({ colorScheme: null, forcedColors: null });
  }
}

module.exports = { assertNoSeriousAxeIssues };
