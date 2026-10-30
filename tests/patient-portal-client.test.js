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
