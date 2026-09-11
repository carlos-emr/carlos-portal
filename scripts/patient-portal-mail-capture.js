'use strict';

const DEFAULT_MFA_EMAIL_SUBJECT = 'Your CARLOS Patient Portal verification code';

function readCapturedMfaCode({
  expectedRecipient,
  readLatest,
  wait,
  maxAttempts = 40,
  pollIntervalMs = 250,
  expectedSubject = DEFAULT_MFA_EMAIL_SUBJECT,
}) {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const message = readLatest();
      const codeMatch = message.match(/(?:^|\r?\n)(\d{6})(?:\r?\n|$)/);
      const recipientMatch = message.match(/^Envelope-To:\s*(\S+)\s*$/m);
      const subjectMatch = message.match(/^Subject:\s*(.+)\s*$/m);
      if (
        codeMatch
        && recipientMatch?.[1] === expectedRecipient
        && subjectMatch?.[1] === expectedSubject
      ) {
        return codeMatch[1];
      }
    } catch (error) {
      if (attempt === maxAttempts - 1) {
        throw error;
      }
    }
    if (attempt < maxAttempts - 1) {
      wait(pollIntervalMs);
    }
  }
  throw new Error('Expected captured MFA email did not arrive before the polling limit');
}

module.exports = { readCapturedMfaCode };
