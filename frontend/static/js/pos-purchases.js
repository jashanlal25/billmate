/* Shared POS purchase normalization: historical bills never add stock twice. */
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.POSPurchases=api;})(typeof window==='object'?window:globalThis,()=>{
 const key=v=>String(v??'').trim();
 const num=v=>{const n=Number(String(v??'').replace(/,/g,'').trim()||0);if(!Number.isFinite(n))throw Error('Invalid number in POS purchase');return n;};
 function prepare(headers,details,items,master){
  const catalog=new Map(),suppliers=new Map();
  for(const r of [...master,...items])if(!r.MODE||r.MODE==='I')catalog.set(key(r.CODE),r);
  for(const r of master)if(r.MODE==='S')suppliers.set(key(r.CODE),String(r.NAME||'').trim());
  const billKey=r=>[String(r.IDATE||'').trim(),key(r.SCODE)||'COUNTER',String(r.INO||'').trim()].join('|');
  const grouped=new Map();
  for(const r of details){if(String(r.CAN||'').trim()==='C')continue;const k=billKey(r);if(!grouped.has(k))grouped.set(k,[]);grouped.get(k).push(r);}
  let unresolved=0,zeroRows=0;
  const bills=headers.map(h=>{
   const date=String(h.IDATE||'').trim(),invoice=String(h.INO||'').trim(),supplier=key(h.SCODE)||'COUNTER';
   if(!/^\d{8}$/.test(date)||!invoice||!supplier)throw Error('Invalid purchase invoice identity in PUR1.DBF');
   const cancelled=String(h.CAN||'').trim()==='C';
   const lines=cancelled?[]:(grouped.get(billKey(h))||[]).flatMap(r=>{
    if(String(r.PR||'').trim()!=='1')throw Error('Unsupported purchase row on bill '+invoice);
    const code=key(r.ICODE),item=catalog.get(code),pack=item?num(item.PKQTY):0;
    const full=num(r.FULL),pcs=num(r.PCS),bfull=num(r.BFULL),bpcs=num(r.BPCS);
    // Without packing, loose pieces cannot be converted safely.
    if((pcs||bpcs)&&pack<=0)throw Error('Packing quantity is missing for POS item '+code+' on bill '+invoice);
    const paid=full+(pcs?pcs/pack:0),bonus=bfull+(bpcs?bpcs/pack:0),qty=paid+bonus,amount=num(r.NET);
    if(!qty&&!amount){zeroRows++;return [];}
    if(!qty)throw Error('Purchase has an amount without a quantity: '+invoice);
    const missing=!item||!String(item.NAME||'').trim();if(missing)unresolved++;
    return [{pos_item_code:code,item_name:missing?'POS item '+code:String(item.NAME).trim(),
      unresolved:missing,qty,paid_qty:paid,bonus_qty:bonus,pack_qty:pack||1,tp:num(r.PRICE),
      retail:item?num(item.RETAIL):0,disc_pct:num(r.DISC),tax:num(r.TAX),line_total:amount,
      batch:String(r.BATCH||'').trim(),expiry:String(r.IEXPIRY||'').trim()}];
   });
   return {pos_invoice_number:invoice,purchase_date:`${date.slice(0,4)}-${date.slice(4,6)}-${date.slice(6)}`,
    supplier_code:supplier,supplier_name:suppliers.get(supplier)||(supplier==='COUNTER'?'Counter':'POS supplier '+supplier),
    total_cost:num(h.AMOUNT),cancelled,lines};
  });
  return {bills,unresolved,zero_rows:zeroRows};
 }
 async function sync(bills,status){
  const request=async(path,options)=>{const response=await fetch(path,{...options,headers:{'Content-Type':'application/json','Accept':'application/json'}});const data=await response.json().catch(()=>({}));if(!response.ok)throw Error(data.error||'Purchase sync failed (HTTP '+response.status+')');return data;};
  const totals={created:0,updated:0,unchanged:0,cancelled:0};
  // Small sequential transactions can safely be retried after interruption.
  for(let i=0;i<bills.length;){
   const batch=[];let lines=0;
   while(i<bills.length&&batch.length<100&&(lines+bills[i].lines.length<=1500||!batch.length)){lines+=bills[i].lines.length;batch.push(bills[i++]);}
   status('Synchronizing purchase bills… '+i+' / '+bills.length);
   const result=await request('/api/pos-backup/purchases',{method:'POST',body:JSON.stringify({bills:batch})});
   for(const k of Object.keys(totals))totals[k]+=Number(result[k]||0);
  }
  return totals;
 }
 return {prepare,sync};
});
