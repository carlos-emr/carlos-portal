'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.join(__dirname, '../carlos_patient_portal/static/portal.js'),
  'utf8',
);

function revealPage() {
  class Element {
    constructor(selector) {
      this.selector = selector;
      this.dataset = {};
      this.textContent = '';
      this.hidden = false;
      this.disabled = false;
    }
    closest(selector) {
      return selector === this.selector ? this : null;
    }
  }
  class HTMLElement extends Element {
    focus() {
      this.focused = true;
    }
  }
  class HTMLButtonElement extends HTMLElement {
    getAttribute(name) {
      return this.attributes?.[name] ?? null;
    }
  }
  class HTMLInputElement extends HTMLElement {}
  class HTMLFormElement extends HTMLElement {}
  class HTMLSelectElement extends HTMLElement {}

  const password = new HTMLInputElement();
  password.type = 'password';
  password.value = '';
  const toggle = new HTMLButtonElement('[data-password-toggle]');
  toggle.attributes = { 'aria-controls': 'password' };
  toggle.dataset = { showLabel: 'FAKE show', hideLabel: 'FAKE hide' };
  toggle.hidden = true;
  const reveal = new HTMLButtonElement('[data-reveal-url][data-reveal-target]');
  reveal.dataset = {
    revealUrl: '/portal/email-passwords/123/reveal',
    revealTarget: 'secret',
    csrfToken: 'FAKE-csrf-token',
    revealLabel: 'FAKE reveal',
    revealingLabel: 'FAKE revealing',
    revealFailedLabel: 'FAKE failed',
  };
  const copy = new HTMLButtonElement('[data-copy-target]');
  copy.hidden = true;
  const secret = new HTMLElement();
  secret.textContent = 'Not revealed';
  secret.parentElement = { querySelector: () => copy };
  const elements = { password, secret };
  const listeners = [];
  const timers = [];
  const requests = [];
  let finishFetch;
  const pendingFetch = new Promise((resolve) => {
    finishFetch = resolve;
  });
  const document = {
    addEventListener: (type, callback) => {
      if (type === 'click') listeners.push(callback);
    },
    getElementById: (id) => elements[id] ?? null,
    querySelector: (selector) =>
      selector === '[data-reveal-password]' ? password : null,
    querySelectorAll: (selector) =>
      selector === '[data-password-toggle]' ? [toggle] : [],
  };
  const window = {
    addEventListener: () => {},
    setTimeout: (callback, milliseconds) => {
      timers.push({ callback, milliseconds });
    },
  };
  vm.runInNewContext(
    source,
    {
      document,
      window,
      navigator: {},
      URLSearchParams,
      Element,
      HTMLElement,
      HTMLButtonElement,
      HTMLInputElement,
      HTMLFormElement,
      HTMLSelectElement,
      fetch: (url, options) => {
        requests.push({
          url,
          options,
          inputValue: password.value,
          inputType: password.type,
        });
        return pendingFetch;
      },
    },
    { filename: 'portal.js' },
  );
  const click = (target) => {
    for (const listener of listeners)
      listener({ target, preventDefault: () => {} });
  };
  return {
    password,
    toggle,
    reveal,
    copy,
    secret,
    timers,
    requests,
    click,
    finishFetch,
  };
}

for (const succeeds of [true, false]) {
  test(`clears and hides the step-up password before a pending ${succeeds ? 'successful' : 'refused'} reveal`, async () => {
    const page = revealPage();
    try {
      const typedPassword = 'FAKE current password +<&';
      page.password.value = typedPassword;
      page.click(page.toggle);
      assert.equal(page.password.type, 'text');
      assert.equal(page.toggle.textContent, 'FAKE hide');

      page.click(page.reveal);
      assert.equal(page.requests.length, 1);
      const request = page.requests[0];
      assert.equal(request.url, '/portal/email-passwords/123/reveal');
      assert.equal(request.options.method, 'POST');
      assert.equal(request.options.credentials, 'same-origin');
      const body = new URLSearchParams(request.options.body);
      assert.equal(body.get('current_password'), typedPassword);
      assert.equal(body.get('csrf_token'), 'FAKE-csrf-token');
      // These observations are captured inside fetch, before its promise settles.
      assert.equal(request.inputValue, '');
      assert.equal(request.inputType, 'password');
      assert.equal(page.password.value, '');
      assert.equal(page.toggle.textContent, 'FAKE show');
      assert.equal(page.reveal.disabled, true);
      assert.equal(page.secret.textContent, 'Not revealed');
      assert.equal(page.copy.hidden, true);

      let jsonReads = 0;
      const disclosed = 'FAKE revealed <&> value';
      page.finishFetch({
        ok: succeeds,
        status: succeeds ? 200 : 503,
        json: async () => {
          jsonReads += 1;
          return { passphrase: disclosed };
        },
      });
      // Drain the real promise chain without a wall-clock retry delay.
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(page.password.value, '');
      assert.equal(page.password.type, 'password');
      if (succeeds) {
        assert.equal(jsonReads, 1);
        assert.equal(page.secret.textContent, disclosed);
        assert.equal(page.secret.focused, true);
        assert.equal(page.copy.hidden, false);
        assert.equal(page.reveal.hidden, true);
        assert.equal(page.timers.length, 0);
      } else {
        assert.equal(jsonReads, 0);
        assert.equal(page.secret.textContent, 'Not revealed');
        assert.equal(page.copy.hidden, true);
        assert.equal(page.reveal.textContent, 'FAKE failed');
        assert.equal(page.timers.length, 1);
        page.timers[0].callback();
        assert.equal(page.reveal.textContent, 'FAKE reveal');
        assert.equal(page.reveal.disabled, false);
        assert.equal(page.password.value, '');
      }
    } finally {
      page.finishFetch({ ok: false, status: 503 });
      await new Promise((resolve) => setImmediate(resolve));
    }
  });
}

// Relative times on the linked-device cards: whole units rounded down, and "now" for the future or under
// a minute ago (a device clock ahead of the portal's must never read "in 3 minutes").
function relativePage(lang, nowMs, moments) {
  const time = (iso) => {
    const element = {
      dataset: {},
      textContent: 'written date',
      appended: [],
      getAttribute: (name) => (name === 'datetime' ? iso : null),
      append(child) {
        this.appended.push(child);
      },
    };
    return element;
  };
  const elements = moments.map(time);
  const document = {
    addEventListener: () => {},
    getElementById: () => null,
    querySelector: () => null,
    documentElement: { lang },
    createElement: () => ({ className: '', textContent: '' }),
    querySelectorAll: (selector) => (selector === 'time[data-relative]' ? elements : []),
  };
  class FixedDate extends Date {
    static now() {
      return nowMs;
    }
  }
  vm.runInNewContext(
    source,
    {
      document,
      window: { addEventListener: () => {}, setTimeout: () => {} },
      navigator: {},
      URLSearchParams,
      Date: FixedDate,
      Element: class {},
      HTMLElement: class {},
      HTMLButtonElement: class {},
      HTMLInputElement: class {},
      HTMLFormElement: class {},
      HTMLSelectElement: class {},
    },
    { filename: 'portal.js' },
  );
  return elements;
}

test('relative times round down and never read as the future', () => {
  const now = Date.parse('2026-11-20T12:00:00Z');
  const ago = (ms) => new Date(now - ms).toISOString();
  const day = 24 * 60 * 60 * 1000;
  const cases = [
    [ago(30 * 1000), 'now'],
    [new Date(now + 5 * 60 * 1000).toISOString(), 'now'],
    [new Date(now + 3 * day).toISOString(), 'now'],
    [ago(61 * 1000), '1 minute ago'],
    [ago(2 * 60 * 60 * 1000), '2 hours ago'],
    [ago(3 * day), '3 days ago'],
    [ago(45 * day), 'last month'],
    [ago(59 * day), 'last month'],
    [ago(60 * day), '2 months ago'],
    [ago(364 * day), '12 months ago'],
    [ago(400 * day), 'last year'],
  ];
  const elements = relativePage('en', now, cases.map(([iso]) => iso));
  cases.forEach(([, expected], index) => {
    assert.equal(elements[index].textContent, expected, `case ${index}`);
    // The written date stays, after the relative one, for a screen reader.
    assert.equal(elements[index].appended[0].textContent, ' (written date)');
  });
});

test('relative times are written in the page language and leave an invalid date alone', () => {
  const now = Date.parse('2026-11-20T12:00:00Z');
  const elements = relativePage('fr', now, [new Date(now - 3 * 24 * 60 * 60 * 1000).toISOString(), 'not a date']);
  assert.match(elements[0].textContent, /^il y a 3 jours$/);
  assert.equal(elements[1].textContent, 'written date');
  assert.equal(elements[1].appended.length, 0);
});
