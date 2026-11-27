'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { readCapturedMfaCode } = require('../scripts/patient-portal-mail-capture');

const expectedSubject = 'Your CARLOS Patient Portal verification code';

function capturedMessage(recipient, code, subject = expectedSubject) {
  return `Envelope-To: ${recipient}\nSubject: ${subject}\n\n${code}\n`;
}

test('waits for MFA mail addressed to the expected account', () => {
  const messages = [
    capturedMessage('previous.patient@example.com', '111111'),
    capturedMessage('expected.patient@example.com', '222222'),
  ];
  let reads = 0;
  let waits = 0;

  const code = readCapturedMfaCode({
    expectedRecipient: 'expected.patient@example.com',
    readLatest: () => messages[Math.min(reads++, messages.length - 1)],
    wait: () => { waits += 1; },
    maxAttempts: 3,
    pollIntervalMs: 0,
  });

  assert.equal(code, '222222');
  assert.equal(reads, 2);
  assert.equal(waits, 1);
});

test('waits for the patient portal MFA subject', () => {
  const messages = [
    capturedMessage('expected.patient@example.com', '111111', 'Password reset requested'),
    capturedMessage('expected.patient@example.com', '222222'),
  ];
  let reads = 0;

  const code = readCapturedMfaCode({
    expectedRecipient: 'expected.patient@example.com',
    readLatest: () => messages[Math.min(reads++, messages.length - 1)],
    wait: () => {},
    maxAttempts: 3,
    pollIntervalMs: 0,
  });

  assert.equal(code, '222222');
  assert.equal(reads, 2);
});

test('accepts CRLF line endings in captured MFA mail', () => {
  const message = capturedMessage('expected.patient@example.com', '222222')
    .replaceAll('\n', '\r\n');

  const code = readCapturedMfaCode({
    expectedRecipient: 'expected.patient@example.com',
    readLatest: () => message,
    wait: () => {},
    maxAttempts: 1,
    pollIntervalMs: 0,
  });

  assert.equal(code, '222222');
});

test('matches recipients using portal email normalization', () => {
  const code = readCapturedMfaCode({
    expectedRecipient: '  Expected.Patient@Example.COM  ',
    readLatest: () => capturedMessage('expected.patient@example.com', '222222'),
    wait: () => {},
    maxAttempts: 1,
    pollIntervalMs: 0,
  });

  assert.equal(code, '222222');
});

test('fails when no matching MFA mail arrives', () => {
  let reads = 0;
  let waits = 0;

  assert.throws(
    () => readCapturedMfaCode({
      expectedRecipient: 'expected.patient@example.com',
      readLatest: () => {
        reads += 1;
        return capturedMessage('previous.patient@example.com', '111111');
      },
      wait: () => { waits += 1; },
      maxAttempts: 3,
      pollIntervalMs: 0,
    }),
    /Expected captured MFA email did not arrive before the polling limit/
  );
  assert.equal(reads, 3);
  assert.equal(waits, 2);
});

// ---- the development mail outbox (#135): a portal prints no code, it writes its email to a file ----

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { clearOutbox, latestOutboxMessage, mailRunner } = require('../scripts/patient-portal-mail-capture');

function outboxFile() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-outbox-test-'));
  return path.join(directory, 'outbox.jsonl');
}

function line(record) {
  return `${JSON.stringify({ at: '2026-11-27T00:00:00+00:00', ...record })}\n`;
}

test('the newest outbox message reads like captured mail, so the same reader finds the code', () => {
  const file = outboxFile();
  fs.writeFileSync(file, line({ kind: 'mfa_code', recipient: 'old@example.com', code: '111111' })
    + line({ kind: 'mfa_code', recipient: 'expected.patient@example.com', code: '222222' }));
  const message = latestOutboxMessage(file);
  assert.match(message, /^Envelope-To: expected\.patient@example\.com$/m);
  assert.equal(readCapturedMfaCode({
    expectedRecipient: 'Expected.Patient@example.com',
    readLatest: () => latestOutboxMessage(file),
    wait: () => {},
    maxAttempts: 1,
  }), '222222');
});

test('a message of another kind is never mistaken for a sign-in code', () => {
  const file = outboxFile();
  fs.writeFileSync(file, line({ kind: 'mfa_code', recipient: 'a@example.com', code: '111111' })
    + line({ kind: 'password_reset', recipient: 'a@example.com', reset_url: 'https://p/r#token=Z' })
    + line({ kind: 'contact_change_notice', recipient: 'a@example.com' }));
  const message = latestOutboxMessage(file);
  assert.match(message, /^Subject: CARLOS Patient Portal contact_change_notice$/m);
  assert.throws(() => readCapturedMfaCode({
    expectedRecipient: 'a@example.com', readLatest: () => message, wait: () => {}, maxAttempts: 2, pollIntervalMs: 0,
  }), /did not arrive/);
  fs.appendFileSync(file, line({ kind: 'password_reset', recipient: 'a@example.com', reset_url: 'https://p/r#token=Z' }));
  assert.match(latestOutboxMessage(file), /\nhttps:\/\/p\/r#token=Z\n$/);
});

test('the default outbox file is in the temp directory, which TMPDIR moves, as the portal reads it', () => {
  const { defaultOutboxFile } = require('../scripts/patient-portal-mail-capture');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-outbox-tmpdir-'));
  const before = { TMPDIR: process.env.TMPDIR, outbox: process.env.PORTAL_DEVELOPMENT_MAIL_OUTBOX };
  try {
    delete process.env.PORTAL_DEVELOPMENT_MAIL_OUTBOX;
    process.env.TMPDIR = directory;
    assert.equal(defaultOutboxFile(), path.join(directory, 'patient-portal-development-mail.jsonl'));
    process.env.PORTAL_DEVELOPMENT_MAIL_OUTBOX = '/elsewhere/outbox.jsonl';
    assert.equal(defaultOutboxFile(), '/elsewhere/outbox.jsonl');
  } finally {
    for (const [name, value] of [['TMPDIR', before.TMPDIR], ['PORTAL_DEVELOPMENT_MAIL_OUTBOX', before.outbox]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});

test('an empty or missing outbox is an error, and clearing it empties it', () => {
  const file = outboxFile();
  assert.throws(() => latestOutboxMessage(file), /ENOENT/);
  fs.writeFileSync(file, line({ kind: 'mfa_code', recipient: 'a@example.com', code: '111111' }));
  clearOutbox(file);
  assert.equal(fs.readFileSync(file, 'utf8'), '');
  assert.throws(() => latestOutboxMessage(file), /empty/);
  clearOutbox(path.join(path.dirname(file), 'never-written.jsonl'));
});

test('the runner uses the mail command when there is one and the outbox file when there is not', () => {
  const file = outboxFile();
  const calls = [];
  const withCommand = mailRunner({
    mailCommand: '/scripts/mail', outboxFile: file, useCommand: true,
    execFileSync: (...call) => { calls.push(call.slice(0, 2)); return 'from the command'; },
  });
  assert.equal(withCommand('read', 'latest'), 'from the command');
  assert.deepEqual(calls, [['/scripts/mail', ['read', 'latest']]]);

  const noCommand = mailRunner({
    mailCommand: '/scripts/mail', outboxFile: file, useCommand: false,
    execFileSync: () => { throw new Error('must not run a command'); },
  });
  fs.writeFileSync(file, line({ kind: 'mfa_code', recipient: 'a@example.com', code: '333333' }));
  assert.match(noCommand('read', 'latest'), /\n333333\n$/);
  assert.equal(noCommand('clear'), '');
  assert.equal(fs.readFileSync(file, 'utf8'), '');
  assert.throws(() => noCommand('send', 'x'), /does not support/);
});
