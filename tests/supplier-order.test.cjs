const {test}=require('node:test');
const assert=require('node:assert/strict');
const {format}=require('../frontend/static/js/supplier-order.js');
const item={vendor:'DOSANI',vendor_list_no:'000051',vendor_code:'1680',vendor_name:'CIPROXIN 500 NEWWW RETAIL',qty:1,discount_pct:4,vendor_discount_pct:8,bonus_text:''};
test('exact supplier message including blank bonus and separators',()=>{
 assert.equal(format('',[item]),'*Customer* : \n*List No* : 000051\n====================\n*Code* : 1680\n*QTY*  : 1\n*Disc* : 8%\n*Bonus*: \n*ITM*  : CIPROXIN 500 NEWWW RETAIL\n--------------------\n*Items* : 1\n====================');
});
test('preserves codes, supplier names, bonus and fractional quantities',()=>{
 const msg=format('SSD MEDICOS',[{...item,vendor_code:'+021',vendor_name:'EXACT  NAME.',qty:1.5,bonus_text:'10+1'}, {...item,vendor_code:'0296'}]);
 assert.ok(msg.includes('*Code* : +021\n*QTY*  : 1.5'));
 assert.ok(msg.includes('*Bonus*: 10+1\n*ITM*  : EXACT  NAME.'));
 assert.ok(msg.includes('*Code* : 0296'));assert.ok(msg.includes('*Items* : 2'));
});
test('does not substitute internal codes or mix lists',()=>{
 assert.throws(()=>format('',[{...item,vendor_code:'',item_code:'ITM0001'}]),/Re-import/);
 assert.throws(()=>format('',[item,{...item,vendor_list_no:'000052'}]),/one supplier/);
 assert.throws(()=>format('',[item,{...item,vendor:'other'}]),/one supplier/);
});

test('customer discount never leaks into supplier order, including zero',()=>{
 const msg=format('SSD MEDICOS',[
  {...item,vendor_code:'2825',vendor_discount_pct:6,discount_pct:4},
  {...item,vendor_code:'2983',vendor_discount_pct:2,discount_pct:0},
  {...item,vendor_discount_pct:0,discount_pct:15}
 ]);
 assert.deepEqual([...msg.matchAll(/\*Disc\* : (.*?)%/g)].map(m=>m[1]),['6','2','0']);
 assert.throws(()=>format('',[{...item,vendor_discount_pct:null}]),/Supplier discount is missing/);
});
test('own stock message uses its stock code and rate without requiring a supplier list number',()=>{
 const msg=format('SSD MEDICOS',[{vendor:'STOCK',vendor_list_no:'',vendor_code:'58',
  vendor_name:'ACNE SOFT SOAP',vendor_discount_pct:11,discount_pct:4,qty:2}]);
 assert.ok(msg.includes('*List No* : Own Stock'));
 assert.ok(msg.includes('*Code* : 58\n*QTY*  : 2\n*Disc* : 11%'));
 assert.ok(msg.includes('*ITM*  : ACNE SOFT SOAP'));
});
