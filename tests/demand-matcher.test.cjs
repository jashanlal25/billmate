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

test('screenshot: Neoprox 500 retains K.K manufacturer suffix and excludes 250',()=>{
 const items=[offer('NEOPROX 500 TAB MERCK','K.K TRADERS'),offer('NEOPROX 250 TAB MERCK','K.K TRADERS')];
 const result=m.match({name:'Tab neoprox 500mg'},m.prepare(items));
 assert.deepEqual(result.offers.map(o=>o.item.name),['NEOPROX 500 TAB MERCK']);
 assert.equal(result.offers[0].status,'review');
 assert.match(result.offers[0].reason,/annotation/);
});
test('screenshot: DOSANI malformed injection is a review candidate with unknown strength',()=>{
 const items=[offer('ONSET INJECTIONNNNN','DOSANI MEDICOS'),offer('ONSET INJ.','JANGDA MEDICOS AHSAN'),offer('ONSET SYP','A'),offer('ONSET INJECTIONNNNN 4MG','B')];
 const result=m.match({name:'Inj onset 8mg'},m.prepare(items));
 assert.deepEqual(result.offers.map(o=>o.item.vendor),['DOSANI MEDICOS','JANGDA MEDICOS AHSAN']);
 assert.equal(result.offers[0].status,'review');
 assert.match(result.offers[0].reason,/Form spelling corrected/);
 assert.match(result.offers[0].reason,/strength/);
});
test('screenshot: Panadol STOCK drops remain separate from Extra',()=>{
 const items=[{...offer('PANADOL DROP. NEWW','STOCK'),qty:23,tp:79.56,discount_pct:30},offer('PANADOL DROP DROP','K.K TRADERS'),offer('PANADOL EXTRA','G.H MEDICAL'),offer('PANADOL-(EXTRA).','NOMAN IMPEX'),offer('PANADOL EXTRA DROP NEWW','A'),offer('PANADOL TAB NEWW','B')];
 const before=JSON.stringify(items);
 const result=m.match({name:'Panadol drop'},m.prepare(items));
 assert.deepEqual(result.offers.map(o=>o.item.vendor),['STOCK','K.K TRADERS']);
 assert.equal(result.offers[0].status,'review');
 assert.equal(result.offers[0].item.qty,23);
 assert.equal(result.offers[0].item.discount_pct,30);
 assert.equal(JSON.stringify(items),before);
});

test('missing pack labels appear for review alongside exact supplier offers',()=>{
 const inventory=m.prepare([
   offer('CALPOL SYP LARGE','S.K.R'),
   {...offer('CALPOL SYP.','Jangda'),discount_pct:13},
   offer('CALPOL SYP SMALL','Different pack'),
   offer('CALPOL TAB','Different form'),
   offer('CALPOL 6 PLUS SYP','Different variant')
 ]);
 const result=m.match({name:'CALPOL SYP LARGE'},inventory);
 assert.equal(result.status,'match');
 assert.deepEqual(result.offers.map(o=>[o.item.vendor,o.status]),[['S.K.R','match'],['Jangda','review']]);
 assert.equal(result.offers[1].reason,'Verify pack size');
 assert.equal(result.offers[1].item.discount_pct,13);
 assert.equal(m.compare(m.profile('ONSET SYP'),m.profile('ONSET SYP MEDIUM')).status,'review');
 assert.equal(m.compare(m.profile('CALPOL SYP LARGE 120MG'),m.profile('CALPOL SYP 250MG')),null);
});

test('reported demand lines distinguish Synalgo, Azomax liquids, Augmentin 625 and Flagyl OLD',()=>{
 const {parse}=require('../frontend/static/js/demand-text-parser.js');
 const rows=parse('Synalgo........1\nAzomax syp.......2\nAugmentin 625.......2\nFlagyl tab........1');
 const names=[
  'Synalar Cream','Synalgo Tab',
  'Azomax Suspension','Azomax 500 Tab','Azomax Drops','Azomax Syp',
  'Augmentin 625mg Tab','Augmentin 375mg Tab','Augmentin DS 457mg Suspension',
  'Flagyl Tab Old','Flagyl Tab','Flagyl Tab New'
 ];
 const stock=m.prepare(names.map(name=>offer(name,'A')));
 const search=row=>m.match(row,stock).offers.map(o=>[o.item.name,o.status]);
 assert.deepEqual(rows.map(row=>row.qty),['1','2','2','1']);
 assert.deepEqual(search(rows[0]),[['Synalgo Tab','review']]);
 assert.deepEqual(search(rows[1]),[['Azomax Suspension','review'],['Azomax Syp','match']]);
 assert.deepEqual(search(rows[2]),[['Augmentin 625mg Tab','review']]);
 assert.deepEqual(search(rows[3]),[['Flagyl Tab Old','review'],['Flagyl Tab','match'],['Flagyl Tab New','review']]);
 assert.deepEqual(search({name:'Flagyl Tab Old'}),[['Flagyl Tab Old','review'],['Flagyl Tab','review']]);
 assert.deepEqual(search({name:'flaygyl tab old'}),[['Flagyl Tab Old','review'],['Flagyl Tab','review']]);
 assert.equal(m.compare(m.profile('Azomax 100mg Syp'),m.profile('Azomax 200mg Suspension')),null);
 assert.equal(m.compare(m.profile('Azomax Syp'),m.profile('Azmax Suspension')),null);
});

test('Augmentin 625 finds both STOCK pack labels when demand omits the form',()=>{
 const items=[
  {...offer('AUGMENTIN 625 TAB LARGE','STOCK'),code:'7992',qty:-1},
  {...offer('AUGMENTIN 625 TAB LARGE NEW','STOCK'),code:'465',qty:13},
  offer('AUGMENTIN 375 TAB LARGE','A'),
  offer('AUGMENTIN SYP LARGE','B')
 ];
 const inventory=m.prepare(items);
 const result=m.match({name:'Augmentin 625'},inventory);
 assert.deepEqual(result.offers.map(o=>[o.item.code,o.status]),[['7992','review'],['465','review']]);
 assert(result.offers.every(o=>/Verify pack size.*verify form/.test(o.reason)));
 assert.equal(m.match({name:'Augmentin 625 Small'},inventory).status,'missing');
});
