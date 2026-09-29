/* Shared by desktop browsers and the Android WebView. */
(function(root){
  'use strict';
  function format(customer, items){
    if(!items || !items.length) throw new Error('No items selected');
    const first = items[0];
    const ownStock = (first.vendor||'').trim().toLowerCase()==='stock' && !first.vendor_list_no;
    if(ownStock){
      if(items.some(l=>(l.vendor||'').trim().toLowerCase()!=='stock' || l.vendor_list_no))
        throw new Error('Choose one stock list per message.');
      let msg = `*Customer* : ${customer}\n*List No* : Own Stock\n====================\n`;
      items.forEach(l=>{
        msg += `*Code* : ${l.vendor_code||l.item_code||''}\n*QTY*  : ${Number(l.qty)}\n*Disc* : ${Number(l.vendor_discount_pct??l.discount_pct??l.disc??0)}%\n*Bonus*: \n*ITM*  : ${l.vendor_name||l.item_name||''}\n--------------------\n`;
      });
      return msg + `*Items* : ${items.length}\n====================`;
    }
    if(items.some(l=>!l.vendor_code || !l.vendor_name || !l.vendor_list_no)){
      throw new Error('Supplier details are missing. Re-import the vendor list and add its items to a new bill.');
    }
    if(items.some(l=>l.vendor_discount_pct == null || !Number.isFinite(Number(l.vendor_discount_pct)))){
      throw new Error('Supplier discount is missing. Reload the saved invoice or re-import the vendor list.');
    }
    if(items.some(l=>l.vendor!==first.vendor || l.vendor_list_no!==first.vendor_list_no)){
      throw new Error('Choose one supplier list per message.');
    }
    let msg = `*Customer* : ${customer}\n*List No* : ${first.vendor_list_no}\n====================\n`;
    items.forEach(l=>{
      msg += `*Code* : ${l.vendor_code}\n*QTY*  : ${Number(l.qty)}\n*Disc* : ${Number(l.vendor_discount_pct)}%\n*Bonus*: ${l.bonus_text ?? l.bonus ?? ''}\n*ITM*  : ${l.vendor_name}\n--------------------\n`;
    });
    return msg + `*Items* : ${items.length}\n====================`;
  }
  const api = {format};
  if(typeof module==='object' && module.exports) module.exports=api;
  else root.SupplierOrder=api;
})(typeof globalThis!=='undefined'?globalThis:this);
