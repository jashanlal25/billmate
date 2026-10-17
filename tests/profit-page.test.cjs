const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync('frontend/static/js/profit.js', 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
function mount(responses) {
  const elements = {};
  for (const id of ['profitStart','profitEnd','profitGroup','profitSearch','profitFilters','profitRefresh','profitSummary','profitWarning','profitRows','profitStatus','profitTitle']) {
    elements[id] = {value:id==='profitGroup'?'customer':'', hidden:false, listeners:{},
      addEventListener(name, fn){this.listeners[name]=fn;}, reportValidity(){return true;}, replaceChildren(){this.innerHTML='';}};
  }
  const requests=[];
  vm.runInNewContext(code, {Intl, Date, Object, String, Number, URLSearchParams, AbortController,
    document:{getElementById:id=>elements[id], querySelectorAll:()=>[], addEventListener(){}},
    window:{addEventListener(){}}, esc:value=>String(value).replaceAll('<','&lt;').replaceAll('>','&gt;'),
    fetch:async url=>{requests.push(url);const response=responses.shift();return {ok:!response.error,json:async()=>response};}});
  return {elements,requests};
}
function report(complete=true) {
  return {start:'2026-10-01',end:'2026-10-16',group_by:'customer',
    summary:{sales:300,matched_sales:complete?300:150,cost:80,profit:70,purchases:800,missing_qty:complete?0:1,margin:46.67,complete},
    rows:[{label:'<Customer>',sales:300,cost:80,profit:70,qty:2,missing_qty:complete?0:1,margin:46.67,complete}]};
}
test('profit renders saved amounts, escapes names, and changes breakdown request',async()=>{
  const second=report();second.group_by='item';second.rows=[];
  const {elements:e,requests}=mount([report(false),second]);await tick();
  assert.equal(e.profitSummary.hidden,false);
  assert.match(e.profitSummary.innerHTML,/Known gross profit/);
  assert.match(e.profitSummary.innerHTML,/800\.00/);
  assert.match(e.profitRows.innerHTML,/&lt;Customer&gt;/);
  assert.equal(e.profitWarning.hidden,false);
  assert.match(e.profitWarning.textContent,/costs are missing for 1/);
  e.profitGroup.value='item';e.profitSearch.value='old search';
  e.profitGroup.listeners.change();await tick();
  assert.match(requests[1],/group_by=item/);
  assert.equal(e.profitSearch.value,'');
  assert.equal(e.profitWarning.hidden,true);
  assert.match(e.profitRows.innerHTML,/No saved sales/);
});
test('API failure is shown and report values stay hidden',async()=>{
  const {elements:e}=mount([{error:'Please complete shop setup first'}]);await tick();
  assert.equal(e.profitStatus.textContent,'Please complete shop setup first');
  assert.equal(e.profitSummary.hidden,true);
  assert.equal(e.profitRefresh.disabled,false);
});
