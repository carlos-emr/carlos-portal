/*
 * The automatic accessibility check (carlos-emr/carlos-portal#57): axe-core runs on the page that
 * is open and the check fails on any serious or critical issue under WCAG 2.0/2.1/2.2 A and AA.
 * Shared by the three browser check scripts, which call it from their own accessible-page helper.
 *
 * Colour contrast is left out for now: the page background makes the brand blue text 3.99:1, a
 * design decision recorded as finding S6 of the audit (the issue's follow-up), not something this
 * check should decide. Everything else axe can check in a real browser is on.
 */
const { AxeBuilder } = require('@axe-core/playwright');

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const FAILING_IMPACTS = new Set(['serious', 'critical']);

async function assertNoSeriousAxeIssues(page, surface) {
  const results = await new AxeBuilder({ page })
    .withTags(WCAG_TAGS)
    .disableRules(['color-contrast'])
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
