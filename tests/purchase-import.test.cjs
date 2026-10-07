const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/purchase.html'),'utf8');
test('purchase startup loads saved invoices with the shared header',async()=>{
  const header=fs.readFileSync(path.join(__dirname,'../frontend/templates/_header.html'),'utf8');
  assert.match(header,/class="theme-btn"/);
  const nodes=Object.fromEntries([...html.matchAll(/\bid="([^"]+)"/g)].map(m=>[m[1],{style:{},innerHTML:'',textContent:'',value:''}]));
  const themeButton={textContent:''};
  const requests=[];
  const context={URLSearchParams,location:{search:''},
    localStorage:{getItem:()=>null,setItem(){}},
    window:{addEventListener(){}},
    document:{documentElement:{setAttribute(){}},addEventListener(){},
      getElementById:id=>nodes[id]||null,
      querySelector:selector=>selector==='.nav .theme-btn'?themeButton:null},
    fetch:async url=>{requests.push(url);return {ok:true,json:async()=>url.startsWith('/api/invoices')
      ?{items:[{id:42,invoice_number:'SSD-0042',customer_name:'Test customer',lines:[{vendor:'DOSANI'}]}]}:[]};}
  };
  vm.createContext(context);
  const script=[...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)].find(m=>m[2].includes('function loadBillingInvoices('))[2];
  vm.runInContext(script,context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.ok(requests.includes('/api/invoices?offset=0&limit=100'));
  assert.match(nodes.billingInvoicePicker.innerHTML,/SSD-0042/);
  assert.equal(themeButton.textContent,'☀️');
});

test('purchase inline scripts remain valid at HTML script boundaries',()=>{
  const scripts=[...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  const inline=scripts.filter(m=>! /\bsrc\s*=/.test(m[1]));
  assert.ok(inline.length>0);
  for(const script of inline)assert.doesNotThrow(()=>new vm.Script(script[2]));
  const main=inline.find(m=>m[2].includes('function loadBillingInvoices('));
  assert.ok(main[2].includes('function viewPurchaseBill('));
  assert.ok(scripts.some(m=>m[1].includes('/static/js/account-dialog.js')));
});

const source=html.slice(html.indexOf('let lines=[], supplier=null'),html.indexOf('// Supplier search'))
  +html.slice(html.indexOf('function clearAll(){'),html.indexOf("document.addEventListener('click'",html.indexOf('function clearAll(){')));

test('customer invoice prepares separate supplier bills with supplier discounts',async()=>{
  const nodes={};
  const invoice={invoice_number:'SSD-0042',lines:[
    {item_id:1,item_name:'MED A',vendor:'DOSANI',vendor_name:'MED A DOSANI',vendor_code:'A1',qty:2,tp:100,discount_pct:5,bonus_text:'Customer bonus',vendor_discount_pct:18},
    {item_id:2,item_name:'MED B',vendor:'SKR',qty:3,tp:200,discount_pct:10,bonus_text:'Customer bonus',vendor_discount_pct:25},
    {item_id:null,item_name:'Unknown',qty:1}
  ]};
  const items=[
    {id:1,vendor:'DOSANI',tp:80,retail_price:120,tax_pct:3,qty:10,bonus_text:'10+1',vendor_discount_pct:18},
    {id:2,vendor:'SKR',tp:150,retail_price:220,tax_pct:0,qty:4,bonus_text:'',vendor_discount_pct:25}
  ];
  const context={
    URLSearchParams,location:{search:'?invoice=42'},window:{location:{href:''},addEventListener(){}},
    document:{getElementById(id){return nodes[id] ||= {style:{},innerHTML:'',textContent:''};}},
    fetch:async(url)=>({ok:true,json:async()=>url.includes('/api/invoices/')?invoice:url.startsWith('/api/items')?items:[]}),
    esc:x=>String(x),clearSupplier(){context.supplier=null;},selectSupplier(id,name){context.supplier={id,name};},
    renderLines(){},toast(){},console
  };
  vm.createContext(context);vm.runInContext(source,context);
  await vm.runInContext('importCustomerInvoice()',context);
  const prepared=vm.runInContext('invoiceGroups.map(g=>({vendor:g.vendor,lines:g.lines}))',context);
  assert.equal(prepared.length,2);
  assert.equal(prepared[0].vendor,'DOSANI');
  assert.equal(prepared[0].lines[0].qty,2);
  assert.equal(prepared[0].lines[0].tp,80);
  assert.equal(prepared[0].lines[0].disc,18);
  assert.equal(prepared[0].lines[0].supplierBonus,'10+1');
  assert.equal(prepared[0].lines[0].vendorCode,'A1');
  assert.equal(prepared[0].lines[0].bonus,undefined);
  assert.equal(prepared[1].vendor,'SKR');
  assert.equal(prepared[1].lines[0].disc,25);
  assert.equal(nodes.invoiceImport.style.display,'block');
  vm.runInContext('lines=[]; invoiceGroups[0].lines=lines; clearAll()',context);
  assert.equal(vm.runInContext('lines.length',context),1);
  assert.equal(vm.runInContext('invoiceGroups[0].lines[0].vendorCode',context),'A1');
  assert.equal(nodes.purchaseClear.textContent,'↻ Reset items from Billing');
  vm.runInContext('lines=[]; cancelPurchaseDraft()',context);
  assert.equal(vm.runInContext('invoiceGroups[0].lines.length',context),1);
  assert.equal(context.window.location.href,'/billing');
  context.sessionStorage={getItem:()=>JSON.stringify({invoiceNumber:'SSD-0042',groups:[
    {vendor:'DOSANI',lines:[],supplier:null,invoiceNumber:'SSD-0042'},
    {vendor:'SKR',lines:[prepared[1].lines[0]],supplier:null,invoiceNumber:'SSD-0042'}
  ]}),setItem(){}};
  await vm.runInContext('importCustomerInvoice()',context);
  assert.equal(vm.runInContext('invoiceGroups[0].lines.length',context),1);
  assert.equal(vm.runInContext('invoiceGroups[1].lines.length',context),1);
});
