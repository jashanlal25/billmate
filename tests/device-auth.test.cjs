const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../frontend/static/js/device-auth.js'), 'utf8');

function setup(options = {}) {
  const elements = Object.fromEntries(['enableFingerprint', 'fingerprintSetup', 'fingerprintUnlock', 'fingerprintForget', 'fingerprintError', 'l_user']
    .map(id => [id, {hidden: true, disabled: false, checked: false, value: '', textContent: ''}]));
  const messages = [], requests = [], redirects = [], alerts = [];
  const bridge = {postMessage(raw) {
    const message = JSON.parse(raw); messages.push(message);
    const answer = options.native?.(message) || (message.action === 'status'
      ? {available: true, saved: true, username: 'first'}
      : message.action === 'unlock' ? {token: 'secret-device-token'} : {success: true});
    queueMicrotask(() => bridge.onmessage({data: JSON.stringify({id: message.id, ...answer})}));
  }};
  const window = options.browser ? {} : {BillMateNativeAuth: bridge};
  const context = {window, document: {getElementById: id => elements[id]},
    setTimeout, clearTimeout, URL, URLSearchParams, alert: message => alerts.push(message), confirm: () => true,
    location: {origin: 'https://billmate-med.vercel.app', search: options.search || '', assign: target => redirects.push(target)},
    fetch: async (url, body) => { requests.push({url, ...body}); return {ok: options.ok !== false, json: async () => options.result || {success: true, redirect: '/billing'}}; }};
  vm.runInNewContext(source, context);
  return {auth: window.BillMateDeviceAuth, elements, messages, requests, redirects, alerts};
}

test('opening login shows remembered username without authenticating automatically', async () => {
  const s = setup(); await s.auth.init('login');
  assert.equal(s.elements.l_user.value, 'first');
  assert.deepEqual(s.messages.map(m => m.action), ['status']);
  assert.equal(s.requests.length, 0); assert.equal(s.redirects.length, 0);
  await s.auth.unlock();
  assert.equal(JSON.parse(s.requests[0].body).token, 'secret-device-token');
  assert.deepEqual(s.redirects, ['/billing']);
});
test('password-only browsers keep fingerprint controls hidden', async () => {
  const s = setup({browser: true}); await s.auth.init('login');
  assert.equal(s.elements.fingerprintSetup.hidden, true);
  assert.equal(s.auth.enrollRequested(), false);
});
test('another typed account cannot use remembered fingerprint', async () => {
  const s = setup(); await s.auth.init('login'); s.elements.l_user.value = 'second';
  await s.auth.unlock(); assert.equal(s.requests.length, 0);
  assert.match(s.elements.fingerprintError.textContent, /another account/);
});
test('expired enrollment is removed, network failure is not treated as logout', async () => {
  const s = setup({ok: false, result: {forget: true, error: 'Expired'}});
  await s.auth.init('admin', 'first'); await s.auth.unlock();
  assert.equal(JSON.parse(s.requests[0].body).kind, 'admin');
  assert.ok(s.messages.some(m => m.action === 'forget'));
  assert.equal(s.redirects.length, 0);
  assert.equal(s.elements.fingerprintUnlock.disabled, false);
});
test('external next redirects are rejected and cancellation preserves password login', async () => {
  const s = setup({search: '?next=https%3A%2F%2Fexample.com'});
  await s.auth.init('login'); await s.auth.unlock(); assert.deepEqual(s.redirects, ['/billing']);
  const cancelled = setup({native: m => m.action === 'status' ? {available: true, saved: false} : {error: 'Cancelled'}});
  await cancelled.auth.init('login');
  await cancelled.auth.save({device_token: 'new-token', username: 'first'});
  assert.match(cancelled.alerts[0], /Login succeeded/);
});
