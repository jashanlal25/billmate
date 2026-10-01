const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const script = fs.readFileSync(path.join(__dirname, '../frontend/static/js/contact-picker.js'), 'utf8');
function setup(select) {
  const nodes = new Map();
  const input = id => ({id, value: '', events: [], dispatchEvent(event) { this.events.push(event.type); }});
  for (const id of ['phone', 'wa', 'name']) nodes.set(id, input(id));
  class Element {
    constructor(tag) { this.tag = tag; this.style = {}; this.children = []; this.value = ''; this.files = []; }
    append(...children) { this.children.push(...children); }
    replaceChildren() { this.children = []; }
    get childElementCount() { return this.children.length; }
    remove() { this.removed = true; }
  }
  const body = new Element('body');
  const context = {
    navigator: {contacts: {select, getProperties: async () => ['tel', 'name']}},
    document: {readyState: 'complete', body, getElementById: id => nodes.get(id),
      createElement: tag => new Element(tag), querySelectorAll: () => []},
    Event: class { constructor(type) { this.type = type; } },
    window: {}
  };
  vm.createContext(context);
  vm.runInContext(script, context);
  return {picker: context.window.BillMateContacts, nodes, body};
}

test('direct contact selection fills phone, WhatsApp and empty name', async () => {
  const {picker, nodes, body} = setup(async () => [{tel: ['+92 (300) 123-4567'], name: ['Ali']}]);
  await picker.pick({phoneId: 'phone', whatsappId: 'wa', nameId: 'name'});
  assert.equal(nodes.get('phone').value, '+923001234567');
  assert.equal(nodes.get('wa').value, '+923001234567');
  assert.equal(nodes.get('name').value, 'Ali');
  assert.equal(body.children.length, 0);
});

test('rejected WebView picker offers a local vCard contact list', async () => {
  const {picker, nodes, body} = setup(async () => { throw new Error('Picker unavailable in WebView'); });
  await picker.pick({phoneId: 'phone'});
  const panel = body.children[0].children[0];
  const file = panel.children[2];
  file.files = [{text: async () => 'BEGIN:VCARD\nFN:Ali\nitem1.TEL;TYPE=CELL:+92 300 1234567\nEND:VCARD'}];
  await file.onchange();
  panel.children[4].children[0].onclick();
  assert.equal(nodes.get('phone').value, '+923001234567');
  assert.equal(body.children[0].removed, true);
});
