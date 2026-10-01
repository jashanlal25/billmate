const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const search=html.slice(html.indexOf('function _stockFirst('),html.indexOf('function _renderItemDropdown('));
const add=html.slice(html.indexOf('function addLine(item){'),html.indexOf('function calcLine('));

test('previous bill suggestion is selectable without replacing another manual line',async()=>{
  const previous={id:null,name:'FAMOSPIN 20',code:'F20',tp:350,retail_price:0,
    discount_pct:11,tax_pct:4,qty:0,historical:true,vendor:'OLD VENDOR',previous_invoice:'SSD-0002'};
  const manual={item_id:null,item_name:'OTHER MANUAL ITEM',vendor:'',qty:1};
  const searchInput={value:'Famospin 20'};
  const dropdown={classList:{remove(){}}};
  const context={IS_GUEST:false,lines:[manual],itemTimer:0,lastQuery:'',
    fetch:async url=>({ok:true,json:async()=>url.includes('/history?')?[previous]:[]}),
    document:{getElementById:id=>id==='itemSearch'?searchInput:dropdown},
    clearTimeout(){},setTimeout(){},calcLine(l){l.lineNet=l.qty*l.tp*(1-l.disc/100);},
    renderLines(){},recalc(){},_focusCartField(){}};
  vm.createContext(context);
  vm.runInContext(search+add,context);
  const found=await context._fetchItems('Famospin 20');
  assert.equal(found.length,1);
  assert.equal(found[0].historical,true);
  context.addLine(found[0]);
  assert.equal(context.lines.length,2);
  assert.equal(manual.qty,1);
  assert.equal(context.lines[1].item_name,'FAMOSPIN 20');
  assert.equal(context.lines[1].disc,11);
  assert.equal(context.lines[1].tax,4);
});
