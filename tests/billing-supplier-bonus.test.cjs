const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync(require('node:path').join(__dirname,'../frontend/templates/billing.html'),'utf8');
const SupplierOrder=require('../frontend/static/js/supplier-order.js');
const opener=html.slice(html.indexOf('async function openVendorMessage(inv)'),html.indexOf('function closeVendorMessage()'));
const reorder=html.slice(html.indexOf('function _vendorReorderUrl('),html.indexOf('function _prefetchVendorSuppliers('));
for(const customerBonus of ['', '2+1'])test(`supplier refresh preserves customer bonus ${JSON.stringify(customerBonus)}`,async()=>{
 const line={item_id:363,item_name:'ARINAC FORTE TAB.',vendor:'JANGDA',vendor_code:'363',vendor_name:'ARINAC FORTE TAB.',vendor_list_no:'67',vendor_discount_pct:9,qty:1,bonus_text:customerBonus};
 const inv={lines:[line]};
 const context={IS_GUEST:false,lastSavedInv:null,_activeVendorInv:null,_vendorInv(){return inv;},
  async _fetchItems(){return [{id:363,name:line.item_name,vendor:line.vendor,vendor_code:'363',vendor_name:line.vendor_name,vendor_list_no:'67',vendor_discount_pct:9,bonus_text:'10PCS 10%'}];},
  _vendorGroups(){return {JANGDA:[line]};},_renderVendorMsgList(){},_prefetchVendorSuppliers(){},
  document:{getElementById(){return {classList:{add(){}}};}},settings:{shop_name:'SSD'},SupplierOrder,_vendorPhone(){return '';}};
 vm.createContext(context);vm.runInContext(opener+'\n'+reorder,context);
 await context.openVendorMessage(inv);
 assert.equal(line.bonus_text,customerBonus);
 assert.equal(line.supplierBonus,'10PCS 10%');
 const snapshot=JSON.stringify(inv);
 const msg=decodeURIComponent(context._vendorReorderUrl('',inv.lines).split('?text=')[1]);
 assert.match(msg,/\*Bonus\*: 10PCS 10%/);
 assert.equal(JSON.stringify(inv),snapshot);
 await context.openVendorMessage(inv);
 assert.equal(line.bonus_text,customerBonus);
});
test('supplier message never substitutes customer bonus for a missing supplier bonus',()=>{
 const context={settings:{shop_name:'SSD'},SupplierOrder,_vendorPhone(){return '';}};
 vm.createContext(context);vm.runInContext(reorder,context);
 const msg=decodeURIComponent(context._vendorReorderUrl('',[{vendor:'JANGDA',vendor_code:'363',vendor_name:'ARINAC',vendor_list_no:'67',vendor_discount_pct:9,qty:1,bonus_text:'CUSTOMER ONLY',bonus:'CUSTOMER ONLY'}]).split('?text=')[1]);
 assert.ok(!msg.includes('CUSTOMER ONLY'));
 assert.match(msg,/\*Bonus\*: \n/);
});
