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
test('real demand and vendor naming: shelf code, omitted mg unit and variant differences',()=>{
 const stock=m.prepare([offer('TERBISIL 250MG TAB','C'),offer('TERBISIL 125MG TAB','C'),offer('GEN-M 30 INJ','A'),offer('GEN-M 60 INJ','A'),offer('CHEWCAL TAB.','B'),offer('ALDACTONE 100 TAB +','C')],true);
 assert.deepEqual(m.match({name:'TERBISIL 250MG TAB A-16'},stock,true).offers.map(o=>o.item.name),['TERBISIL 250MG TAB']);
 assert.equal(m.match({name:'GEN-M 120MG INJ H-43'},stock,true).offers.length,0);
 assert.equal(m.match({name:'GEN-M 60MG INJ'},stock,true).offers[0].status,'review');
 assert.equal(m.match({name:'CHEWCAL TAB A-52'},stock,true).offers[0].status,'match');
 const plus=m.match({name:'ALDACTONE TAB 100 A-35'},stock,true).offers;
 assert.equal(plus.length,1);assert.equal(plus[0].status,'review');
});
test('unspecified form offers are choices; shelf stripping is opt-in',()=>{
 const result=m.match({name:'PANADOL'},m.prepare([offer('PANADOL TAB','A'),offer('PANADOL SYP','B')]));
 assert.equal(result.offers.length,2);assert(result.offers.every(o=>o.status==='review'));
 assert.equal(m.profile('ANAGROW SHAMPOO C-55',true).key,m.profile('ANAGROW SHAMPOO').key);
 assert.notEqual(m.profile('ANAGROW SHAMPOO C-55').key,m.profile('ANAGROW SHAMPOO').key);
});
test('Sp. syrup shorthand matches syrup and never tablet',()=>{
 const stock=m.prepare([offer('RAPICORT SYP','A'),offer('RAPICORT TAB','B')]);
 assert.deepEqual(m.match({name:'Sp. Rapicort',qty:'2'},stock).offers.map(o=>o.item.vendor),['A']);
});
test('one strength cannot suggest a two-strength combination',()=>{
 assert.equal(m.compare(m.profile('SOFVASC 5'),m.profile('SOFVASC 5/80')),null);
 assert.equal(m.compare(m.profile('EXTOR 5/160'),m.profile('EXTOR 5/160 MG TAB')).status,'review');
});
test('unknown products do not acquire unrelated offers; no inventory mutations',()=>{
 const source=[offer('PANADOL TAB','A')],before=JSON.stringify(source);
 assert.equal(m.match({name:'AMOXIL CAP'},m.prepare(source)).status,'missing');
 assert.equal(JSON.stringify(source),before);assert.equal(m.price(source[0]),180);
 assert.equal(m.price({tp:null}),null);assert.equal(m.price({tp:200,discount_pct:110}),null);
});
test('Estar vendor annotations retain all three offers without admitting 5mg',()=>{
 const names=['ESTAR 10 MG TAB 389 RETAIL','ESTAR 10 TAB (PHARMEVO)','ESTAR 10 TAB.','ESTAR 5MG TAB.'];
 const result=m.match({name:'Tab estar 10mg'},m.prepare(names.map((n,i)=>offer(n,String(i)))));
 assert.deepEqual(result.offers.map(o=>o.item.vendor),['0','1','2']);
 assert(result.offers.every(o=>o.status==='review'));
});
test('Nuberol NEW annotation is a review offer, variants and unknown parentheses stay protected',()=>{
 const names=['NUBEROL FORTE NEW','NUBEROL FORTE TAB','NUBEROL FORTE TAB.','NUBEROL TAB','NUBEROL FORTE (PLUS)'];
 const result=m.match({name:'Tab nubrol forte'},m.prepare(names.map((n,i)=>offer(n,String(i)))));
 assert.deepEqual(result.offers.map(o=>o.item.vendor),['0','1','2']);
 assert(result.offers.every(o=>o.status==='review'));
 assert.equal(m.compare(m.profile('ESTAR 10MG TAB'),m.profile('ESTAR 5MG TAB 389 RETAIL')),null);
});
test('Sup is an ambiguous liquid request and cannot match tablets or drops',()=>{
 const names=['ONSET SYP','ONSET SUSP','ONSET TAB','ONSET DROPS'];
 const result=m.match({name:'Sup onset'},m.prepare(names.map(n=>offer(n,'A'))));
 assert.deepEqual(result.offers.map(o=>o.item.name),names.slice(0,2));
 assert(result.offers.every(o=>o.status==='review'));
});
test('common form spellings match but strengths and short brand names stay strict',()=>{
 for(const [a,b] of [['Calcee sache','Calcee sachet'],['Doctor shampo','Doctor shampoo'],['Voltral emulgel','Voltral gel']]){
  assert(m.compare(m.profile(a),m.profile(b)));
 }
 assert.equal(m.compare(m.profile('ESTAR 10 TAB'),m.profile('EXTOR 10 TAB')),null);
 assert.equal(m.compare(m.profile('EXTOR 5/80'),m.profile('EXTOR 5/160')),null);
});
