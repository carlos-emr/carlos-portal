'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_MFA_EMAIL_SUBJECT = 'Your CARLOS Patient Portal verification code';

function readCapturedMfaCode({
  expectedRecipient,
  readLatest,
  wait,
  maxAttempts = 40,
  pollIntervalMs = 250,
  expectedSubject = DEFAULT_MFA_EMAIL_SUBJECT,
}) {
  const normalizedExpectedRecipient = expectedRecipient.trim().toLowerCase();
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const message = readLatest();
      const codeMatch = message.match(/(?:^|\r?\n)(\d{6})(?:\r?\n|$)/);
      const recipientMatch = message.match(/^Envelope-To:\s*(\S+)\s*$/m);
      const subjectMatch = message.match(/^Subject:\s*(.+)\s*$/m);
      if (
        codeMatch
        && recipientMatch?.[1].toLowerCase() === normalizedExpectedRecipient
        && subjectMatch?.[1].trim() === expectedSubject
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

/* The development mail outbox (#135): a development portal with no SMTP host writes each outgoing
 * email as one JSON line to this file (see DevelopmentOutboxEmailSender), because it prints and
 * returns no code. The browser checks read the sign-in code from it when no mail command (the
 * devcontainer's /scripts/mail, a test inbox) is available. */
function defaultOutboxFile() {
  return process.env.PORTAL_DEVELOPMENT_MAIL_OUTBOX
    || path.join(os.tmpdir(), 'patient-portal-development-mail.jsonl');
}

/* The newest outbox message as the text the mail command prints (`Envelope-To`, `Subject`, then
 * the body), so `readCapturedMfaCode` reads both the same way. Only the sign-in code and the reset
 * link are put in a body. */
function latestOutboxMessage(file) {
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter((line) => line.trim() !== '');
  if (lines.length === 0) throw new Error('the development mail outbox is empty');
  const record = JSON.parse(lines[lines.length - 1]);
  const subject = record.kind === 'mfa_code'
    ? DEFAULT_MFA_EMAIL_SUBJECT
    : `CARLOS Patient Portal ${record.kind}`;
  const body = record.kind === 'mfa_code' ? record.code
    : record.kind === 'password_reset' ? record.reset_url : '';
  return `Envelope-To: ${record.recipient}\nSubject: ${subject}\n\n${body}\n`;
}

/* Forgets what is in the outbox (the file keeps its private mode). */
function clearOutbox(file) {
  if (fs.existsSync(file)) fs.writeFileSync(file, '');
}

/* The `runMailCommand(...args)` the browser checks call: `clear` and `read latest`. With a mail
 * command (PORTAL_MAIL_COMMAND set, or the default one present) it runs that; without one it reads
 * the development outbox file instead. */
function mailRunner({
  mailCommand,
  execFileSync,
  outboxFile = defaultOutboxFile(),
  useCommand = process.env.PORTAL_MAIL_COMMAND !== undefined || fs.existsSync(mailCommand),
}) {
  return (...args) => {
    if (useCommand) {
      return execFileSync(mailCommand, args, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
    }
    if (args[0] === 'clear' && args.length === 1) {
      clearOutbox(outboxFile);
      return '';
    }
    if (args[0] === 'read' && args[1] === 'latest' && args.length === 2) {
      return latestOutboxMessage(outboxFile);
    }
    throw new Error(`the development mail outbox does not support: ${args.join(' ')}`);
  };
}

module.exports = {
  clearOutbox, defaultOutboxFile, latestOutboxMessage, mailRunner, readCapturedMfaCode,
};
