const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '../frontend/templates/billing.html'), 'utf8');
// Match the HTML parser's script boundaries, not the JavaScript function
// boundaries. A literal closing script tag inside a JS string ends the script.
const scripts = [...template.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
const inline = scripts.filter(match => !/\bsrc\s*=/.test(match[1]));
function rendered(source) {
  return source.replace(/\{\{\s*'true' if is_guest else 'false'\s*\}\}/g, 'false')
    .replace(/\{\{\s*session\.username or (?:'guest'|"guest")\s*\}\}/g, 'test-user');
}

test('all Billing inline scripts parse using actual HTML script boundaries', () => {
  assert.equal(inline.length, 2);
  for (const [index, match] of inline.entries()) {
    const source = rendered(match[2]);
    assert.doesNotMatch(source, /\{\{/);
    assert.doesNotThrow(() => new vm.Script(source, {filename: `billing-inline-${index}.js`}));
  }
});

test('item search and invoice history stay inside the executable Billing script', () => {
  const main = inline.find(match => match[2].includes('function searchItem('));
  assert.ok(main);
  for (const name of ['loadHistory', '_showRateSourcePref', 'loadIntoBuilder', 'renderLines']) {
    assert.match(main[2], new RegExp(`function ${name}\\(`));
  }
  const helper = scripts.filter(match => /billing-keyboard-resume\.js/.test(match[1]));
  assert.equal(helper.length, 1, 'load the keyboard helper once, outside the print template');
  assert.ok(helper[0].index > main.index + main[0].length);
});

test('generated customer invoice has no keyboard script or other executable script', () => {
  const start = template.indexOf('function buildInvoicePrintHtml(');
  const end = template.indexOf('function _showRateSourcePref', start);
  const context = {settings: {shop_name: 'Test Shop'}, esc: String, statusLabel: () => 'Invoiced'};
  vm.createContext(context);
  vm.runInContext(template.slice(start, end), context);
  const invoice = {invoice_number: 'TEST-1', status: 'posted', invoice_date: '2026-10-23',
    customer_name: 'Test customer', lines: [], subtotal: 0, tax_amount: 0, total: 0};
  for (const pdf of [false, true]) {
    const printed = context.buildInvoicePrintHtml(invoice, pdf, false, false, false, false);
    assert.doesNotMatch(printed, /<script\b/i);
    assert.doesNotMatch(printed, /billing-keyboard-resume/);
  }
});


test('regression: a helper inside the print string breaks the HTML script boundary', () => {
  const broken = template.replace('</body></html>`;', '<script src="/keyboard-test.js"></script>\n</body></html>`;');
  const blocks = [...broken.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  const main = blocks.find(match => match[2].includes('function searchItem('));
  assert.throws(() => new vm.Script(rendered(main[2])), SyntaxError);
});
