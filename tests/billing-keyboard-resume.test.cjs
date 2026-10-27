const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../frontend/static/js/billing-keyboard-resume.js'), 'utf8');

function setup(pathname = '/billing') {
  const handlers = new Map();
  function events(target) {
    target.addEventListener = (name, callback) => {
      const key = target.tag + name;
      handlers.set(key, [...(handlers.get(key) || []), callback]);
    };
    target.emit = (name, event = {}) => (handlers.get(target.tag + name) || []).forEach(fn => fn(event));
    return target;
  }
  let focused = true, clock = 0, nextTimer = 0;
  const timers = new Map();
  const document = events({tag: 'document', hidden: false, body: {}, documentElement: {},
    hasFocus: () => focused, querySelector: () => null});
  const viewport = events({tag: 'viewport', height: 800, width: 400, scale: 1});
  const window = events({tag: 'window', document, visualViewport: viewport, location: {pathname},
    setTimeout(fn, delay) { timers.set(++nextTimer, {fn, at: clock + delay}); return nextTimer; },
    clearTimeout(id) { timers.delete(id); }});
  const field = {id: 'itemSearch', value: 'panad', isConnected: true,
    selectionStart: 3, selectionEnd: 3, selectionDirection: 'none',
    getClientRects: () => [{}],
    blur() { document.activeElement = document.body; this.blurs = (this.blurs || 0) + 1; },
    focus() { document.activeElement = this; this.focuses = (this.focuses || 0) + 1; document.emit('focusin', {target: this}); },
    setSelectionRange(start, end, direction) { this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction; },
    scrollIntoView() { this.scrolled = true; }};
  vm.runInNewContext(source, {window});
  field.focus();
  function tick(ms = 250) {
    clock += ms;
    for (const [id, timer] of [...timers]) if (timer.at <= clock) { timers.delete(id); timer.fn(); }
  }
  function leave() { focused = false; window.emit('blur'); document.hidden = true; document.emit('visibilitychange'); }
  function back() { document.hidden = false; document.emit('visibilitychange'); focused = true; window.emit('focus'); tick(); }
  function resize(height) { viewport.height = height; viewport.emit('resize'); }
  return {window, document, viewport, field, tick, leave, back, resize, handlers};
}

test('other pages attach no keyboard, visibility, resize, or focus handlers', () => {
  for (const page of ['/', '/items', '/demand-search', '/purchase', '/payments', '/customers', '/admin/sales']) {
    const s = setup(page);
    assert.equal(s.handlers.size, 0, page);
    s.leave(); s.back();
    assert.equal(s.field.focuses, 1, page);
  }
});

test('Billing customer and quantity fields do not trigger keyboard restoration', () => {
  for (const id of ['custSearch', 'custPhone', 'billLineSearch', 'quantity']) {
    const s = setup();
    s.field.id = id;
    s.field.focus();
    const initial = s.field.focuses;
    s.leave(); s.back();
    assert.equal(s.field.focuses, initial, id);
  }
});

test('WhatsApp round trip restores typing and caret without changing unfinished text', () => {
  const s = setup(); s.resize(450); s.leave(); s.resize(800); s.back();
  assert.equal(s.field.value, 'panad');
  assert.equal(s.field.selectionStart, 3);
  assert.equal(s.field.selectionEnd, 3);
  assert.equal(s.field.focuses, 2);
  assert.equal(s.field.blurs, 1, 'reacquires even an already-focused Android input');
  assert.equal(s.field.scrolled, true);
});

test('repeated switches retain edits and a selected text range', () => {
  const s = setup();
  for (let i = 0; i < 4; i++) {
    s.field.value += 'x'; s.field.selectionStart = 1; s.field.selectionEnd = 4;
    s.field.selectionDirection = 'backward'; s.document.emit('input');
    s.leave(); s.back();
    assert.equal(s.field.selectionStart, 1); assert.equal(s.field.selectionEnd, 4);
    assert.equal(s.field.selectionDirection, 'backward');
  }
  assert.equal(s.field.focuses, 5);
});

test('hiding keyboard while staying on Billing is respected', () => {
  const s = setup(); s.resize(450); s.resize(800); s.tick(); s.leave(); s.back();
  assert.equal(s.field.focuses, 1);
});

test('keyboard closing just before app suspension is not treated as manual dismissal', () => {
  const s = setup(); s.resize(450); s.resize(800); s.leave(); s.tick(); s.back();
  assert.equal(s.field.focuses, 2);
});

test('tapping search again enables restore after deliberate keyboard dismissal', () => {
  const s = setup(); s.resize(450); s.resize(800); s.tick();
  s.document.emit('pointerdown', {target: s.field}); s.leave(); s.back();
  assert.equal(s.field.focuses, 2);
});

for (const scenario of ['other field', 'dialog', 'new touch', 'removed field', 'changed text', 'hidden field', 'readonly']) {
  test('does not steal focus after ' + scenario, () => {
    const s = setup(); s.leave();
    if (scenario === 'other field') s.document.activeElement = {id: 'custSearch'};
    if (scenario === 'dialog') s.document.querySelector = () => ({});
    if (scenario === 'new touch') s.document.emit('pointerdown', {target: {id: 'other'}});
    if (scenario === 'removed field') s.field.isConnected = false;
    if (scenario === 'changed text') s.field.value = '';
    if (scenario === 'hidden field') s.field.getClientRects = () => [];
    if (scenario === 'readonly') s.field.readOnly = true;
    s.back(); assert.equal(s.field.focuses, 1);
  });
}

test('a return signal while still hidden cannot reopen the field', () => {
  const s = setup(); s.leave(); s.window.emit('focus'); s.tick();
  assert.equal(s.field.focuses, 1);
});

test('normal page focus without an app switch does not open search', () => {
  const s = setup(); s.window.emit('focus'); s.window.emit('pageshow'); s.tick();
  assert.equal(s.field.focuses, 1);
});

test('APK return requests the native keyboard only after restoring the item editor', () => {
  const s = setup(); const calls = [];
  s.window.BillMateNativeKeyboard = {postMessage(action) {
    calls.push(action);
    assert.equal(s.document.activeElement, s.field);
    assert.equal(s.field.selectionStart, 3);
  }};
  s.window.emit('billmate:app-pause');
  s.window.emit('billmate:app-resume'); s.tick();
  assert.deepEqual(calls, ['show']);
  assert.equal(s.field.value, 'panad');
});

test('APK Back dismissal prevents a native keyboard request on return', () => {
  const s = setup(); const calls = [];
  s.window.BillMateNativeKeyboard = {postMessage: action => calls.push(action)};
  s.window.emit('billmate:keyboard-dismissed');
  s.leave(); s.back();
  assert.deepEqual(calls, []);
});

test('native bridge is never called on Demand Search even if accidentally included', () => {
  const s = setup('/demand-search'); const calls = [];
  s.window.BillMateNativeKeyboard = {postMessage: action => calls.push(action)};
  s.window.emit('billmate:app-pause'); s.window.emit('billmate:app-resume'); s.tick();
  assert.deepEqual(calls, []);
});

test('APK return does not reopen the keyboard when a dialog covers Billing', () => {
  const s = setup(); const calls = [];
  s.window.BillMateNativeKeyboard = {postMessage: action => calls.push(action)};
  s.window.emit('billmate:app-pause');
  s.document.querySelector = () => ({});
  s.window.emit('billmate:app-resume'); s.tick();
  assert.deepEqual(calls, []);
});
