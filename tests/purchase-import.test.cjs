const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/purchase.html'),'utf8');
const source=html.slice(html.indexOf('let lines=[], supplier=null'),html.indexOf('// Supplier search'));

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
    URLSearchParams,location:{search:'?invoice=42'},
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
});
