const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const script = fs.readFileSync(require('node:path').join(__dirname, '../app/src/main/assets/billing-keyboard.js'), 'utf8');

function setup() {
  const events = {};
  const document = {body: {}, documentElement: {}, querySelector: () => null,
    addEventListener(name, callback) { events[name] = callback; }};
  const field = {id: 'itemSearch', isConnected: true, value: 'panad',
    selectionStart: 3, selectionEnd: 3, selectionDirection: 'none',
    getClientRects: () => [{}], focus() { document.activeElement = this; },
    setSelectionRange(start, end, direction) { this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction; },
    scrollIntoView() { this.scrolled = true; }};
  document.activeElement = field;
  const window = {};
  vm.runInNewContext(script, {window, document});
  events.focusin({target: field});
  return {document, field, events, api: window.BillMateBillingKeyboard};
}

test('app return restores the same unfinished text and exact caret, without selecting all', () => {
  const {api, document, field} = setup();
  api.capture();
  document.activeElement = document.body;
  field.selectionStart = field.selectionEnd = 0;
  assert.equal(api.restore(), true);
  assert.equal(document.activeElement, field);
  assert.equal(field.value, 'panad');
  assert.equal(field.selectionStart, 3);
  assert.equal(field.selectionEnd, 3);
  assert.equal(field.scrolled, true);
  assert.equal(api.restore(), false, 'restore is consumed once');
});

test('repeated app switches preserve an updated query and a selected range', () => {
  const {api, field, events} = setup();
  for (let i = 0; i < 5; i++) {
    field.value += 'x';
    field.selectionStart = 1; field.selectionEnd = 4; field.selectionDirection = 'backward';
    events.input(); api.capture();
    assert.equal(api.restore(), true);
    assert.equal(field.selectionStart, 1); assert.equal(field.selectionEnd, 4);
    assert.equal(field.selectionDirection, 'backward');
  }
});

for (const scenario of ['another field', 'removed', 'hidden', 'readonly', 'changed query', 'dialog', 'new touch']) {
  test('does not reopen the item field after ' + scenario, () => {
    const {api, field, document, events} = setup();
    api.capture();
    if (scenario === 'another field') document.activeElement = {id: 'customer'};
    if (scenario === 'removed') field.isConnected = false;
    if (scenario === 'hidden') field.getClientRects = () => [];
    if (scenario === 'readonly') field.readOnly = true;
    if (scenario === 'changed query') field.value = '';
    if (scenario === 'dialog') document.querySelector = () => ({});
    if (scenario === 'new touch') events.pointerdown();
    assert.equal(api.restore(), false);
  });
}

test('leaving from another field does not remember the old search', () => {
  const {api, events, document} = setup();
  document.activeElement = {id: 'customer'};
  events.focusin({target: document.activeElement});
  api.capture();
  document.activeElement = document.body;
  assert.equal(api.restore(), false);
});
