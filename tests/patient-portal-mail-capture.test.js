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
