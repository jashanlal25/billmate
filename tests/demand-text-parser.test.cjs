const {test}=require('node:test');
const assert=require('node:assert/strict');
const {parse}=require('../frontend/static/js/demand-text-parser.js');
const matcher=require('../frontend/static/js/demand-matcher.js');

test('paste list keeps strength and form in name, quantity separate, and lazmi visible',()=>{
 const rows=parse('Methachlor drop (10)\nExtor 5/160 (3)\nTruva 10 (2)lazmi\nSelsun blue small (2) lazmi\nSp. Rapicort (2)\n');
 assert.deepEqual(rows.map(r=>[r.name,r.qty,r.required]),[
  ['Methachlor drop','10',false],['Extor 5/160','3',false],
  ['Truva 10','2',true],['Selsun blue small','2',true],['Sp. Rapicort','2',false]
 ]);
 const stock=matcher.prepare([{name:'EXTOR 5/160',vendor:'A'},{name:'EXTOR 5/80',vendor:'B'}]);
 assert.deepEqual(matcher.match(rows[1],stock).offers.map(o=>o.item.vendor),['A']);
});
test('text without quantities stays searchable and empty lists fail',()=>{
 assert.deepEqual(parse('1. Nexum 40\n- Nuberol tab')[0].name,'Nexum 40');
 assert.equal(parse('Nuberol tab')[0].qty,'');
 assert.throws(()=>parse('  \n  '),/at least one/);
});

test('pasted supplier order reads ITM blocks and ignores message framing',()=>{
 const message=`*Customer* :
*List No* : 000231
====================
*Code* : 4
*QTY*  : 2
*Disc* : 31%.
*Bonus*:
*ITM*  : Acireg 20mg Cap.
--------------------
*Code* : 400
*QTY*  : 5
*Disc* : 3%.
*Bonus*: 5%
*ITM*  : Minoxin Plus 5 % Solution
--------------------
*Code* : 683
*QTY*  : 2
*Disc* : 13%,
*Bonus*:
*ITM*  : Vocinti 10 Mg Tab 476 Retail
*Items* : 3
*Net* : 111077.72
====================`;
 const rows=parse(message);
 assert.deepEqual(rows.map(r=>[r.code,r.name,r.qty,r.discount_pct,r.bonus]),[
  ['4','Acireg 20mg Cap.','2',31,''],
  ['400','Minoxin Plus 5 % Solution','5',3,'5%'],
  ['683','Vocinti 10 Mg Tab 476 Retail','2',13,'']
 ]);
 assert.equal(rows.every(r=>r.required===false),true);
});

test('large order message retains one row per ITM entry',()=>{
 const text=Array.from({length:64},(_,i)=>`*Code* : ${i+1}\n*QTY* : ${i%7+1}\n*Disc* : 4%'\n*Bonus*:\n*ITM* : Medicine ${i+1}\n--------------------`).join('\n')+'\n*Items* : 64';
 const rows=parse(text);
 assert.equal(rows.length,64);
 assert.deepEqual([rows[63].code,rows[63].qty,rows[63].name],['64','1','Medicine 64']);
});

test('quantity-first demand keeps all 19 names, quantities and duplicate lines',()=>{
 const input="1 feldene 20mg\n1 bynevol 2.5mg\n2 diabold 4mg\n4 acne soft bar\n3 fonaz cap\n3 calcee plus sachet\n1 barizold 600mg\n2 bifomyk cream\n2 bynevol 2.5mg\n1 calamox syp\n2 cefim sp\n2 kinz 20mg inj\n1 leflox 250mg\n4 nubral fort\n10 panadol drops\n6 rigix syp\n2 sofvasc 5mg\n1 talopex 5mg\n2 tobracin d drop";
 const rows=parse(input);
 assert.equal(rows.length,19);
 const expected=input.split('\n').map(line=>{const split=line.indexOf(' ');return [line.slice(split+1),line.slice(0,split)];});
 assert.deepEqual(rows.map(r=>[r.name,r.qty]),expected);
 assert.deepEqual(rows.filter(r=>r.name==='bynevol 2.5mg').map(r=>r.qty),['1','2']);
 const inventory=matcher.prepare(expected.map(([name],i)=>({id:i,name,vendor:'TEST'})));
 for(const row of rows)assert(matcher.match(row,inventory).offers.some(o=>o.item.name===row.name),row.name);
 const stock=matcher.prepare([{name:'FELDENE 20MG',vendor:'correct'},{name:'FELDENE 10MG',vendor:'wrong'}]);
 assert.deepEqual(matcher.match(rows[0],stock).offers.map(o=>o.item.vendor),['correct']);
});
test('prefix quantities coexist with bullets, numbering, lazmi and strength-first names',()=>{
 assert.deepEqual(parse('1. 2 Bynevol 2.5mg\n- 6 Rigix syp lazmi').map(r=>[r.name,r.qty,r.required]),[['Bynevol 2.5mg','2',false],['Rigix syp','6',true]]);
 assert.deepEqual(parse('20 mg Medicine\n5 ml Solution\n5 Fluorouracil (2)').map(r=>[r.name,r.qty]),[['20 mg Medicine',''],['5 ml Solution',''],['5 Fluorouracil','2']]);
});
