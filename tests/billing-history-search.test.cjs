const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const search=html.slice(html.indexOf('function _stockFirst('),html.indexOf('function _renderItemDropdown('));
const add=html.slice(html.indexOf('function addLine(item){'),html.indexOf('function calcLine('));

test('previous bills are separated by one non-selectable divider after all current offers',()=>{
  const render=html.slice(html.indexOf('function _renderItemDropdown('),html.indexOf('async function searchItem('));
  const dropdown={innerHTML:'',classList:{add(){}}};
  const context={document:{getElementById(){return dropdown;}},toTitleCase:s=>s,esc:s=>s};
  vm.createContext(context);vm.runInContext(search+render,context);
  const current=[{name:'Zeegap SKR',tp:100,qty:0,discount_pct:4},{name:'Zeegap JANGDA',tp:100,qty:0,discount_pct:3}];
  const history=[{name:'Old Zeegap',tp:100,historical:true,discount_pct:90,previous_invoice:'SSD-0013'},{name:'Older Zeegap',tp:100,historical:true,discount_pct:80}];
  context._renderItemDropdown(context._stockFirst([...history,...current]),'zeegap');
  const content=dropdown.innerHTML;
  assert(content.indexOf('Zeegap JANGDA')<content.indexOf('role="separator"'));
  assert(content.indexOf('role="separator"')<content.indexOf('Previous bill SSD-0013'));
  assert.equal((content.match(/role="separator"/g)||[]).length,1);
  assert.equal((content.match(/class="dd-item"/g)||[]).length,5,'Only offers and the manual-add action participate in keyboard navigation');
  context._renderItemDropdown(current,'zeegap');
  assert.doesNotMatch(dropdown.innerHTML,/role="separator"/);
});

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
