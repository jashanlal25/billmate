const {test}=require('node:test');
const assert=require('node:assert/strict');
const {format}=require('../frontend/static/js/supplier-order.js');
const item={vendor:'DOSANI',vendor_list_no:'000051',vendor_code:'1680',vendor_name:'CIPROXIN 500 NEWWW RETAIL',qty:1,discount_pct:8,bonus_text:''};
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
