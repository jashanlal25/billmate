const {test}=require('node:test');const assert=require('node:assert/strict');
const {prepare}=require('../frontend/static/js/pos-purchases.js');
const h={INO:'001',SCODE:'5',IDATE:'20261001',AMOUNT:'855.00',CAN:''};
const item={CODE:'9',MODE:'I',NAME:'Medicine',PKQTY:'10',RETAIL:'100'};
const supplier={MODE:'S',CODE:'5',NAME:'Supplier'};
const line={...h,ICODE:'9',PR:'1',FULL:'1',PCS:'5',BFULL:'1',BPCS:'0',NET:'855',DISC:'5',PRICE:'600',TAX:'0'};
test('purchase packing, paid and supplier bonus quantities are preserved separately',()=>{
 const d=prepare([h],[line],[item],[supplier]);const b=d.bills[0],l=b.lines[0];
 assert.equal(b.supplier_name,'Supplier');assert.equal(b.total_cost,855);
 assert.equal(l.qty,2.5);assert.equal(l.paid_qty,1.5);assert.equal(l.bonus_qty,1);
 assert.equal(l.line_total,855);assert.equal(b.purchase_date,'2026-10-01');
});
test('returns and cancelled bills remain distinguishable',()=>{
 const d=prepare([{...h,AMOUNT:'-90'}],[{...line,FULL:'-1',PCS:'0',BFULL:'0',NET:'-90'}],[item],[supplier]);
 assert.equal(d.bills[0].lines[0].qty,-1);assert.equal(d.bills[0].total_cost,-90);
 assert.deepEqual(prepare([{...h,CAN:'C'}],[line],[item],[supplier]).bills[0].lines,[]);
});
test('a missing historical name is flagged, but loose pieces without packing are rejected',()=>{
 const d=prepare([h],[{...line,PCS:'0',BFULL:'0'}],[],[supplier]);
 assert.equal(d.unresolved,1);assert.equal(d.bills[0].lines[0].unresolved,true);
 assert.throws(()=>prepare([h],[line],[],[supplier]),/Packing quantity/);
});
test('blank counter supplier codes match blank source line codes',()=>{
 const d=prepare([{...h,SCODE:''}],[{...line,SCODE:''}],[item],[]);
 assert.equal(d.bills[0].supplier_code,'COUNTER');assert.equal(d.bills[0].lines.length,1);
});

test('leading-zero supplier codes remain distinct POS accounts',()=>{
 const a={...h,SCODE:'00'},b={...h,SCODE:'0'};
 const result=prepare([a,b],[{...line,SCODE:'00',PCS:'0'},{...line,SCODE:'0',PCS:'0'}],[item],[]);
 assert.notEqual(result.bills[0].supplier_code,result.bills[1].supplier_code);
 assert.equal(result.bills[0].lines.length,1);assert.equal(result.bills[1].lines.length,1);
});
