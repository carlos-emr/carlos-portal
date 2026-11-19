/*
 * The automatic accessibility check (carlos-emr/carlos-portal#57): axe-core runs on the page that
 * is open and the check fails on any serious or critical issue under WCAG 2.0/2.1/2.2 A and AA.
 * Shared by the three browser check scripts, which call it from their own accessible-page helper.
 *
 * Colour contrast is on. The brand blue was 3.99:1 on the page's pale blue background; it is now
 * #4065b2 (4.54:1 there, 5.64:1 on white), and tests/test_accessibility_basics.py pins those
 * ratios from the stylesheet.
 */
const { AxeBuilder } = require('@axe-core/playwright');

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const FAILING_IMPACTS = new Set(['serious', 'critical']);

async function assertNoSeriousAxeIssues(page, surface) {
  const results = await new AxeBuilder({ page })
    .withTags(WCAG_TAGS)
    .analyze();
  const serious = results.violations.filter((violation) => FAILING_IMPACTS.has(violation.impact));
  if (serious.length > 0) {
    const summary = serious.map((violation) => (
      `${violation.id} (${violation.impact}, ${violation.nodes.length} element(s)): `
      + `${violation.nodes.slice(0, 3).map((node) => node.target.join(' ')).join('; ')}`
    )).join('\n  ');
    throw new Error(`${surface} has serious accessibility issues (axe):\n  ${summary}`);
  }
}

module.exports = { assertNoSeriousAxeIssues };
