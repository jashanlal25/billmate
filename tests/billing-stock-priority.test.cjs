const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('function _stockFirst('),html.indexOf('function _renderItemDropdown('));

test('previously billed offers stay after every current vendor even with higher discount or old stock',async()=>{
  const catalog=[{id:1,name:'Zeegap SKR',qty:0,discount_pct:4},{id:2,name:'Zeegap JANGDA',qty:0,discount_pct:3},{id:3,name:'Zeegap stock',qty:2,discount_pct:1}];
  const history=[{id:null,name:'Zeegap old bill',qty:10,discount_pct:90,historical:true}];
  const context={IS_GUEST:false,fetch:async url=>({ok:true,json:async()=>url.includes('/history')?history:catalog})};
  vm.createContext(context);vm.runInContext(source,context);
  const results=await context._fetchItems('zeegap');
  assert.deepEqual(Array.from(results,i=>i.name),['Zeegap stock','Zeegap SKR','Zeegap JANGDA','Zeegap old bill']);
  assert.equal(results.at(-1),history[0]);
});

test('cached and refreshed offers rank by discount after stock, preserving ties',async()=>{
  const catalog=[
    {id:1,name:'Betnovate JANGDA',qty:0,discount_pct:'14',bonus_text:'CTN 99%'},
    {id:2,name:'Betnovate SKR',qty:0,discount_pct:13},
    {id:3,name:'Betnovate DOSANI',qty:0,discount_pct:15},
    {id:4,name:'Betnovate G.H',qty:0,discount_pct:12},
    {id:5,name:'Betnovate stock',qty:29,discount_pct:1},
    {id:6,name:'Betnovate POS',qty:2,discount_pct:20},
    {id:7,name:'Betnovate equal offer',qty:0,discount_pct:14},
    {id:8,name:'Betnovate missing discount',qty:0},
    {id:9,name:'Betnovate invalid discount',qty:0,discount_pct:'invalid'}
  ];
  const context={IS_GUEST:false,_cacheGet:()=>catalog,
    fetch:async url=>({json:async()=>url.includes('/history')?[]:catalog})};
  vm.createContext(context);
  vm.runInContext(source,context);
  const expected=[5,6,3,1,7,2,4,8,9];
  assert.deepEqual(Array.from(context._searchCache('betnovate'),i=>i.id),expected);
  assert.deepEqual(Array.from(await context._fetchItems('betnovate'),i=>i.id),expected);
  assert.deepEqual(catalog.map(i=>i.id),[1,2,3,4,5,6,7,8,9]);
});

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
