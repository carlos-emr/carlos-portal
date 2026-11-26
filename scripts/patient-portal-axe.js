/*
 * The automatic accessibility check (carlos-emr/carlos-portal#57): axe-core runs on the page that
 * is open and the check fails on any serious or critical issue under WCAG 2.0/2.1/2.2 A and AA,
 * colour contrast included. Shared by the three browser check scripts, which call it from their
 * own accessible-page helper.
 *
 * It runs twice, in the light and then in the dark colour scheme (the device's setting, emulated),
 * then again with the patient's own choice from Preferences (data-theme Dark and Light, and
 * data-contrast More, set on <html> as the server does), and then makes a smoke check with forced
 * colours (a Windows contrast theme, emulated): the page
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
    const selected = document.querySelector('.text-tab.selected, .module-link.selected');
    const selectedStyle = selected ? getComputedStyle(selected) : null;
    let focusOutline = null;
    if (skipLink instanceof HTMLElement) {
      skipLink.focus();
      const outline = getComputedStyle(skipLink);
      focusOutline = { style: outline.outlineStyle, width: parseFloat(outline.outlineWidth) };
      // Back to where the page was: later steps and screenshots must not see this focus.
      skipLink.blur();
    }
    return {
      headingVisible: Boolean(heading && heading.getClientRects().length > 0),
      focusOutline,
      selected: selectedStyle
        ? {
          underlined: selectedStyle.textDecorationLine.includes('underline'),
          borderWidth: parseFloat(selectedStyle.borderTopWidth),
        }
        : null,
    };
  });
  if (!state.headingVisible) {
    throw new Error(`${surface} shows no heading with forced colours`);
  }
  if (!state.focusOutline || state.focusOutline.style === 'none' || !(state.focusOutline.width >= 2)) {
    throw new Error(`${surface}: the skip link has no visible focus outline with forced colours`);
  }
  // Only the stylesheet's forced-colors block gives a selected tab an underline and a 2px border
  // (outside it the selected state is a fill colour, which forced colours removes), so this fails
  // if that block is deleted or stops matching. Pages without a selected tab are not checked.
  if (state.selected && !(state.selected.underlined && state.selected.borderWidth >= 2)) {
    throw new Error(
      `${surface}: the selected tab is not drawn by shape (underline, 2px border) with forced colours`
    );
  }
}

// The patient's own choice in Preferences: the server puts data-theme and data-contrast on <html>.
// They are set here the same way, on the open page, and put back as they were: Dark chosen while
// the device is light (and Light chosen while it is dark), and High contrast on top of each.
async function assertNoSeriousIssuesWithChosenAppearance(page, surface) {
  const previous = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute('data-theme'),
    contrast: document.documentElement.getAttribute('data-contrast'),
  }));
  const setAppearance = (theme, contrast) => page.evaluate(([chosenTheme, chosenContrast]) => {
    const root = document.documentElement;
    if (chosenTheme) root.setAttribute('data-theme', chosenTheme); else root.removeAttribute('data-theme');
    if (chosenContrast) root.setAttribute('data-contrast', chosenContrast); else root.removeAttribute('data-contrast');
  }, [theme, contrast]);
  try {
    await setAppearance('dark', null);
    await assertNoSeriousIssues(page, surface, 'chosen dark');
    await setAppearance('dark', 'more');
    await assertNoSeriousIssues(page, surface, 'chosen dark, high contrast');
    await setAppearance('light', 'more');
    await assertNoSeriousIssues(page, surface, 'chosen light, high contrast');
    // Chosen Light on a device that is dark must stay light: the device's palette is scoped out.
    await page.emulateMedia({ colorScheme: 'dark' });
    await setAppearance('light', null);
    await assertNoSeriousIssues(page, surface, 'chosen light on a dark device');
  } finally {
    await page.emulateMedia({ colorScheme: null });
    await setAppearance(previous.theme, previous.contrast);
  }
}

async function assertNoSeriousAxeIssues(page, surface) {
  await assertNoSeriousIssues(page, surface, 'light');
  try {
    await page.emulateMedia({ colorScheme: 'dark' });
    await assertNoSeriousIssues(page, surface, 'dark');
    await page.emulateMedia({ colorScheme: null });
    await assertNoSeriousIssuesWithChosenAppearance(page, surface);
    await assertForcedColoursSmoke(page, surface);
  } finally {
    await page.emulateMedia({ colorScheme: null, forcedColors: null });
  }
}

module.exports = { assertNoSeriousAxeIssues };
