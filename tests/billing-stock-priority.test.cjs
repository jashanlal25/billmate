const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('function _stockFirst('),html.indexOf('function _renderItemDropdown('));

test('stocked match survives the cached search limit and is the first Enter result',async()=>{
  const catalog=Array.from({length:60},(_,n)=>({id:n+1,name:`Indrop ${String(n).padStart(2,'0')}`,code:String(n),qty:0}));
  catalog.push({id:61,name:'Indrop Z',code:'Z',qty:2});
  catalog.push({id:62,name:'Indrop ZZ',code:'ZZ',qty:1});
  const context={IS_GUEST:false,_cacheGet:()=>catalog,fetch:async()=>({json:async()=>catalog})};
  vm.createContext(context);
  vm.runInContext(source,context);
  const cached=context._searchCache('indrop');
  assert.equal(cached.length,50);
  assert.deepEqual(Array.from(cached.slice(0,2),i=>i.id),[61,62]);
  assert.equal(cached[2].id,1);
  const fresh=await context._fetchItems('indrop');
  assert.deepEqual(Array.from(fresh.slice(0,2),i=>i.id),[61,62]);
  assert.equal(fresh[2].id,1);
  assert.equal(context._searchCache('absent').length,0);
});
