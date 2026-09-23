const {test}=require('node:test');
const assert=require('node:assert/strict');
const m=require('../frontend/static/js/demand-matcher.js');
const offer=(name,vendor)=>({name,vendor,tp:200,discount_pct:10});
test('every compatible vendor offer appears; syrup never matches tablets',()=>{
 const inventory=m.prepare([offer('PANADOL SYP','A'),offer('PANADOL TAB','A'),offer('PANADOL SYRUP','B')]);
 const syrup=m.match({name:'PANDOL SYP'},inventory);
 assert.deepEqual(syrup.offers.map(o=>o.item.vendor),['A','B']);
 assert(syrup.offers.every(o=>o.status==='review'));
 const tabs=m.match({name:'PANADOL TAB'},inventory);
 assert.deepEqual(tabs.offers.map(o=>o.item.vendor),['A']);assert.equal(tabs.status,'match');
});
test('strength and pack conflicts excluded; missing details flagged',()=>{
 const inventory=m.prepare(['PANADOL 500 MG TABLETS','PANADOL 250MG TAB','PANADOL 500MG TAB 100','PANADOL TAB'].map(n=>offer(n,'A')));
 const result=m.match({name:'PANADOL TAB 500MG'},inventory);
 assert.equal(result.offers.length,3);
 assert.equal(result.offers[0].status,'match');
 assert.equal(result.offers[1].status,'review');assert.equal(result.offers[2].status,'review');
 assert.equal(m.compare(m.profile('PANADOL 500MG TAB 20'),m.profile('PANADOL 500MG TAB 100')),null);
 assert.equal(m.compare(m.profile('MED 120MG/5ML SYP'),m.profile('MED 250MG/5ML SYP')),null);
});
test('unspecified form offers are choices; shelf stripping is opt-in',()=>{
 const result=m.match({name:'PANADOL'},m.prepare([offer('PANADOL TAB','A'),offer('PANADOL SYP','B')]));
 assert.equal(result.offers.length,2);assert(result.offers.every(o=>o.status==='review'));
 assert.equal(m.profile('ANAGROW SHAMPOO C-55',true).key,m.profile('ANAGROW SHAMPOO').key);
 assert.notEqual(m.profile('ANAGROW SHAMPOO C-55').key,m.profile('ANAGROW SHAMPOO').key);
});
test('unknown products do not acquire unrelated offers; no inventory mutations',()=>{
 const source=[offer('PANADOL TAB','A')],before=JSON.stringify(source);
 assert.equal(m.match({name:'AMOXIL CAP'},m.prepare(source)).status,'missing');
 assert.equal(JSON.stringify(source),before);assert.equal(m.price(source[0]),180);
 assert.equal(m.price({tp:null}),null);assert.equal(m.price({tp:200,discount_pct:110}),null);
});
