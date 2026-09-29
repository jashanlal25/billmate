const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'../frontend/templates');
const esc=s=>String(s);
const invoice={invoice_number:'SSD-001',status:'posted',invoice_date:'2026-09-30',
  lines:[{item_name:'MED A',tp:100,discount_pct:10,tax_pct:5,qty:2,line_net:180},
    {item_name:'MED B',tp:80,discount_pct:5,tax_pct:0,qty:1,line_net:76}],
  subtotal:180,tax_amount:10,total:190};
const purchase={purchase_number:'PUR-001',purchase_date:'2026-09-30',supplier_name:'GH',
  lines:[{item_name:'MED A',tp:100,retail:120,disc_pct:10,qty:2,line_total:180},
    {item_name:'MED B',tp:80,retail:100,disc_pct:5,qty:1,line_total:76}],total_cost:256};

for(const [file,fn,next,data] of [
  ['billing.html','buildInvoicePrintHtml','function _showRateSourcePref',invoice],
  ['admin/sales.html','buildInvoicePrintHtml','function printInvoice',invoice],
  ['purchase.html','buildPurchasePrintHtml','function viewPurchaseBill',purchase],
  ['admin/purchase.html','buildPurchasePrintHtml','function viewPurchase',purchase],
]){
  test(`${file}: Print uses black ink; PDF keeps color without row shading`,()=>{
    const html=fs.readFileSync(path.join(root,file),'utf8');
    const start=html.indexOf(`function ${fn}(`);
    assert.ok(start>=0);
    const end=html.indexOf(next,start);
    assert.ok(end>start);
    const context={settings:{shop_name:'SSD MEDICOS'},shopSettings:{shop_name:'SSD MEDICOS'},
      purShopSettings:{shop_name:'SSD MEDICOS'},esc,statusLabel:()=> 'Invoiced'};
    vm.createContext(context);
    vm.runInContext(html.slice(start,end),context);
    const printed=context[fn](data,false);
    const pdf=context[fn](data,true);
    assert.match(printed,/color:#000!important/);
    assert.doesNotMatch(pdf,/color:#000!important/);
    assert.match(pdf,/color:#4f46e5/);
    assert.doesNotMatch(pdf,/background:#f8f8ff/);
  });
}

test('Android print uses monochrome while Android PDF keeps color',async()=>{
  const html=fs.readFileSync(path.join(root,'billing.html'),'utf8');
  const printStart=html.indexOf('function buildInvoicePrintHtml(');
  const bridgeStart=html.indexOf('function _sendNativeInvoice(');
  const bridgeEnd=html.indexOf('function checkNativeUpdate(',bridgeStart);
  const messages=[];
  const context={settings:{shop_name:'SSD MEDICOS'},esc,statusLabel:()=> 'Invoiced',
    _isBillMateNative:()=>true,
    window:{BillMateNativeShare:{postMessage(msg){messages.push(JSON.parse(msg));}}}};
  vm.createContext(context);
  vm.runInContext(html.slice(printStart,html.indexOf('function _showRateSourcePref',printStart)),context);
  vm.runInContext(html.slice(bridgeStart,bridgeEnd),context);
  await context._sendPdfToNative('print_pdf',invoice,false,false,false,false);
  await context._sendPdfToNative('share_pdf',invoice,false,false,false,false);
  assert.match(messages[0].html,/color:#000!important/);
  assert.doesNotMatch(messages[1].html,/color:#000!important/);
  assert.match(messages[1].html,/color:#4f46e5/);
});
