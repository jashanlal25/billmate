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
