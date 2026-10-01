const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('function invoiceEditMismatch('),html.indexOf('function loadIntoBuilder('));
const context={};vm.createContext(context);vm.runInContext(source,context);
test('consistent saved bill has no discrepancy notice',()=>{
 assert.equal(context.invoiceEditMismatch({total:199,discount_amount:5,lines:[{line_net:180,qty:2,tax_pct:12}]}),'');
});
test('old stored totals are reported without changing the saved invoice',()=>{
 const invoice={total:43744.53,discount_amount:0,lines:[{line_net:43388.13,qty:1,tax_pct:646.30}]};
 const before=JSON.stringify(invoice);
 assert.match(context.invoiceEditMismatch(invoice),/43744\.53.*44034\.43/);
 assert.equal(JSON.stringify(invoice),before);
});
