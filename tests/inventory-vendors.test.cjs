const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('frontend/templates/items.html','utf8');
function setup(){
  const elements={}; const calls=[];
  const context={IS_GUEST:false,CAN_DELETE_GLOBAL:false,URLSearchParams,
    esc:s=>String(s??''),toast(){},setTimeout,clearTimeout,
    document:{getElementById:id=>elements[id]??=( {value:'',innerHTML:'',textContent:''})},
    fetch:async url=>{calls.push(url);return {ok:true,json:async()=>url==='/api/items/count'
      ?{private:3,global:0,vendors:[{name:'DOSANI',count:2},{name:'JANGDA',count:1}]}
      :new URLSearchParams(url.split('?')[1]).get('q')?[]:[{id:1,name:'Medicine',vendor:'DOSANI',qty:0,tp:10,retail_price:12}]};}};
  vm.createContext(context);
  vm.runInContext('let allItems=[];'+html.slice(html.indexOf('function _applyLoadedItems('),html.indexOf('function toggleVendorPanel(')),context);
  return {context,elements,calls,run:s=>vm.runInContext(s,context)};
}
test('summary loads without fetching items; vendor selection fetches only that vendor; empty search retains choices',async()=>{
  const {context,elements,calls,run}=setup();
  await context.loadItems('');
  assert.deepEqual(calls,['/api/items/count']);
  assert.match(elements.vendorPanel.innerHTML,/DOSANI/);assert.match(elements.vendorPanel.innerHTML,/2 items/);
  assert.match(elements.itemsBody.innerHTML,/Select a vendor/);
  run("selectedVendors.add('DOSANI')");await context.loadItems('');
  assert.equal(calls.at(-1),'/api/items?q=&vendor=DOSANI');
  assert.match(elements.itemsBody.innerHTML,/Medicine/);
  elements.searchBox.value='missing';await context.loadItems('missing');
  assert.match(elements.itemsBody.innerHTML,/No items match/);
  assert.match(elements.vendorPanel.innerHTML,/JANGDA/);
  assert.equal(run('selectedVendors.has("DOSANI")'),true);
  run('selectedVendors.clear()');calls.length=0;await context.loadItems('missing');
  assert.deepEqual(calls,['/api/items/count']);
});
test('late item response cannot overwrite cleared selection',async()=>{
  const {context,elements,run}=setup();await context.loadItems('');
  const original=context.fetch;let finish;
  context.fetch=url=>url==='/api/items/count'?original(url):new Promise(resolve=>finish=resolve);
  run("selectedVendors.add('DOSANI')");const pending=context.loadItems('');
  await new Promise(resolve=>setImmediate(resolve));
  run('selectedVendors.clear()');await context.loadItems('');
  finish({ok:true,json:async()=>[{id:1,name:'STALE',vendor:'DOSANI'}]});await pending;
  assert.match(elements.itemsBody.innerHTML,/Select a vendor/);assert.doesNotMatch(elements.itemsBody.innerHTML,/STALE/);
});
