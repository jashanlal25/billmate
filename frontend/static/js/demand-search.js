(function(){
  'use strict';
  const $=id=>document.getElementById(id);
  let demands=[],results=[],currentFile=null,currentPasted=false,version=0,busy=false;
  let copyOffers=[];
  const selectedOffers=new Map(),vendorPhones=new Map();
  let suppliers=[];
  const billingTransferKey='billmate-demand-billing-selection';
  const demandOwner=document.querySelector('main.demand').dataset.owner;
  const status=text=>{$('demandStatus').textContent=text;};
  function controls(){
    $('runDemand').disabled=busy||!demands.length;
    $('inventoryInstead').disabled=busy||!currentFile||!/\.html?$/i.test(currentFile.name);
    $('clearDemand').disabled=busy||(!demands.length&&!currentFile&&!$('pastedDemand').value.trim());
    $('demandFile').disabled=busy;
    $('pastedDemand').disabled=busy;
    $('loadTextDemand').disabled=busy||!$('pastedDemand').value.trim();
    $('ignoreShelf').disabled=busy;
  }
  function parseHtml(text){
    // Detached document: uploaded scripts and styles never enter the app.
    const doc=new DOMParser().parseFromString(text,'text/html');
    const rows=[];
    for(const table of doc.querySelectorAll('table')){
      let columns=null;
      for(const tr of table.querySelectorAll('tr')){
        if(tr.closest('table')!==table) continue;
        const cells=Array.from(tr.children).filter(c=>/^(TD|TH)$/.test(c.tagName));
        const values=cells.map(c=>c.textContent.replace(/\s+/g,' ').trim());
        const headers=values.map(v=>v.toLowerCase());
        const name=headers.findIndex(v=>/^(item\s*name|product\s*name|description|item|product)$/.test(v));
        if(name>=0){columns={name,code:headers.indexOf('code'),box:headers.indexOf('box'),pcs:headers.indexOf('pcs')};continue;}
        if(!columns||!cells.length||cells.some(c=>c.querySelector('table'))) continue;
        const item=values[columns.name];
        if(!item||!/[a-z]/i.test(item)||cells.length<=columns.name||/^(total|grand total|sub total)\b/i.test(item)) continue;
        if(cells.some(c=>c.querySelector('input,button,select'))) continue;
        rows.push({name:item,code:values[columns.code]||'',box:values[columns.box]||'',pcs:values[columns.pcs]||''});
      }
    }
    if(!rows.length) throw Error('No demand items found. Use an HTML table with an Item Name column.');
    if(rows.length>2000) throw Error('Please split this demand into files of no more than 2,000 items.');
    return rows;
  }
  async function load(file,pasted=false,restored=false){
    const ticket=++version;
    demands=[];results=[];currentFile=file||null;currentPasted=pasted;
    selectedOffers.clear();updateSelectionPanel();
    $('selectedDemandFile').hidden=!file;
    $('selectedDemandFile').textContent=file?(pasted?'Pasted text demand':`Attached demand file: ${file.name} (${(file.size/1024).toFixed(1)} KB)`):'';
    $('demandResults').hidden=true;$('demandPreview').hidden=true;controls();
    if(!file){status('No demand loaded.');return;}
    try{
      if(!/\.(?:html?|txt)$/i.test(file.name)) throw Error('Choose an HTM, HTML, or TXT demand file.');
      if(file.size>4*1024*1024) throw Error('Maximum file size is 4 MB.');
      status('Reading demand…');
      const content=await file.text();
      const parsed=/\.txt$/i.test(file.name)?DemandTextParser.parse(content):parseHtml(content);
      if(ticket!==version) return;
      demands=parsed;
      let saved=true;
      if(!restored){
        try{await ShareStore.saveDemand(file,demandOwner);}
        catch(e){saved=false;}
      }
      if(ticket!==version)return;
      if(pasted)$('pastedDemand').value=content;
      $('previewRows').innerHTML=demands.map(d=>`<tr><td>${esc(d.code)}</td><td>${esc(d.name)}</td><td>${esc(d.qty?`${d.qty}${d.required?' · Lazmi':''}`:'')}</td><td>${esc(d.box)}</td><td>${esc(d.pcs)}</td></tr>`).join('');
      $('demandPreview').hidden=false;
      status(`${pasted?'Pasted demand':file.name} — ${demands.length} demand items ready. Tap Run Search.${saved?'':' This device could not save the demand for later.'}`);
    }catch(e){if(ticket===version) status(e.message);}
    controls();
  }
  $('demandFile').addEventListener('change',async e=>{
    if(!e.target.files.length)return;
    await ShareStore.clearPendingSharedFile();
    await load(e.target.files[0]);
  });
  $('pastedDemand').addEventListener('input',controls);
  $('loadTextDemand').addEventListener('click',async()=>{
    const text=$('pastedDemand').value;
    if(!text.trim()||busy)return;
    await ShareStore.clearPendingSharedFile();
    $('demandFile').value='';
    await load(new File([text],'Pasted demand.txt',{type:'text/plain'}),true);
  });
  $('ignoreShelf').addEventListener('change',()=>{
    results=[];$('demandResults').hidden=true;
    if(demands.length) status('Matching option changed. Tap Run Search to update results.');
  });
  $('clearDemand').addEventListener('click',async()=>{
    await load(null);
    $('demandFile').value='';$('pastedDemand').value='';
    try{await Promise.all([ShareStore.clearPendingSharedFile(),ShareStore.clearDemand()]);}
    catch(e){status('Demand cleared here, but could not be removed from device storage. Please try Clear again.');}
    controls();
  });
  $('inventoryInstead').addEventListener('click',async()=>{
    if(!currentFile)return;
    busy=true;controls();
    try{await ShareStore.savePendingSharedFile(currentFile);location.assign('/items?shared=1&destination=inventory');}
    catch(e){status('Could not transfer the file. Please open Items and select Import File.');busy=false;controls();}
  });
  $('runDemand').addEventListener('click',async()=>{
    if(busy||!demands.length)return;
    busy=true;controls();results=[];$('demandResults').hidden=true;
    selectedOffers.clear();updateSelectionPanel();
    status('Loading all vendor inventory…');
    try{
      const response=await fetch('/api/items',{cache:'no-store',headers:{Accept:'application/json'}});
      if(!response.ok||response.redirected) throw Error('Could not load inventory. Sign in again if your session expired, then retry.');
      let inventory=await response.json();
      if(!Array.isArray(inventory))throw Error('Could not read inventory. Please retry.');
      if(document.querySelector('main.demand').dataset.guest==='true'){
        const local=JSON.parse(localStorage.getItem('g_items')||'[]');
        inventory=[...local,...inventory.filter(s=>!local.some(l=>l.name.toLowerCase()===s.name.toLowerCase()&&String(l.vendor||'').toLowerCase()===String(s.vendor||'').toLowerCase()))];
      }
      const ignore=$('ignoreShelf').checked;
      const prepared=DemandMatcher.prepare(inventory,ignore);
      for(let i=0;i<demands.length;i++){
        results.push(DemandMatcher.match(demands[i],prepared,ignore));
        if(i%10===0){status(`Searching ${i+1} of ${demands.length} demand items…`);await new Promise(resolve=>setTimeout(resolve,0));}
      }
      $('demandPreview').open=false;$('demandResults').hidden=false;
      status(`Search complete across ${inventory.length} inventory entries. No inventory was changed.`);
      $('resultFilter').value=results.some(r=>r.offers.length)?'found':'missing';
      render();
      requestAnimationFrame(()=>$('demandResults').scrollIntoView({block:'start',behavior:'smooth'}));
    }catch(e){results=[];status(e.message||'Search failed. Please retry.');}
    finally{busy=false;controls();}
  });
  const money=v=>v==null||!Number.isFinite(Number(v))?'—':Number(v).toFixed(2);
  const tpValue=v=>v==null||v===''||!Number.isFinite(Number(v))?Infinity:Number(v);
  const demandQty=d=>[d.qty,d.box&&`${d.box} box`,d.pcs&&`${d.pcs} pcs`,d.required&&'Lazmi'].filter(Boolean).join(' · ')||'—';
  const discountForCopy=v=>v==null||v===''||!Number.isFinite(Number(v))?'Discount not specified':`${Number(v)}%`;
  function offerLetter(index){
    let letters='';
    for(let n=index+1;n>0;n=Math.floor((n-1)/26))letters=String.fromCharCode(97+(n-1)%26)+letters;
    return letters;
  }
  function render(){
    const counts={match:0,review:0,missing:0};
    results.forEach(r=>counts[r.status]++);
    const found=results.filter(r=>r.offers.length).length;
    const offers=results.reduce((total,r)=>total+r.offers.length,0);
    const matchItems=results.filter(r=>r.offers.some(o=>o.status==='match')).length;
    const reviewItems=results.filter(r=>r.offers.some(o=>o.status==='review')).length;
    $('resultSummary').textContent=`${results.length} demand items · ${found} found (${offers} vendor offers) · ${counts.missing} not found`;
    for(const [value,label,count] of [['found','Found offers',found],['all','All demand items',results.length],['match','Matching offers',matchItems],['review','Needs review',reviewItems],['missing','Not found',counts.missing]]){
      $('resultFilter').querySelector(`option[value="${value}"]`).textContent=`${label} (${count})`;
    }
    const filter=$('resultFilter').value,sort=$('resultSort').value;
    const rows=[];
    $('copyFeedback').textContent='';
    copyOffers=[];
    let visibleItems=0,visibleOffers=0;
    for(const [dIndex,result] of results.entries()){
      let offers=result.offers.slice();
      if(filter==='found'&&!offers.length)continue;
      if(filter==='missing'&&offers.length)continue;
      if(filter==='match'||filter==='review') offers=offers.filter(o=>o.status===filter);
      if(!offers.length&&filter!=='all'&&!(filter==='missing'&&result.status==='missing'))continue;
      visibleItems++;visibleOffers+=offers.length;
      offers.sort((a,b)=>{
        if(sort==='vendor')return String(a.item.vendor||'').localeCompare(String(b.item.vendor||''));
        if(sort==='discount')return Number(b.item.discount_pct||0)-Number(a.item.discount_pct||0);
        return tpValue(a.item.tp)-tpValue(b.item.tp);
      });
      if(!offers.length){rows.push(`<tr class="group-start"><td class="mark-col"></td><td>${visibleItems}</td><td class="names">${esc(result.demand.name)}</td><td colspan="4">Not found — no compatible inventory entry</td><td>${esc(demandQty(result.demand))}</td><td></td></tr>`);continue;}
      offers.forEach((o,i)=>{
        const copyIndex=copyOffers.push(`${String(o.item.name||'').trim()}-----${discountForCopy(o.item.discount_pct)}`)-1;
        const key=`${dIndex}:${result.offers.indexOf(o)}`;
        rows.push(`<tr class="${i===0?'group-start':''}"><td class="mark-col"><input class="mark-offer" type="checkbox" data-offer-key="${key}" aria-label="Mark ${esc(o.item.name)} from ${esc(o.item.vendor||'unspecified vendor')}" ${selectedOffers.has(key)?'checked':''}></td><td>${visibleItems}.${offerLetter(i)}</td><td class="names">${esc(result.demand.name)}</td><td class="names">${esc(o.item.name)}<button type="button" class="copy-offer" data-copy-offer="${copyIndex}" aria-label="Copy ${esc(o.item.name)} and discount">Copy</button></td><td>${esc(o.item.vendor||'Not specified')}</td><td>${money(o.item.discount_pct)}</td><td>${money(o.item.tp)}</td><td>${esc(demandQty(result.demand))}</td><td><div class="${o.status==='review'?'review':''}"><strong>${o.status==='review'?'Needs review':'Matching details'}</strong><p class="note">${esc(o.reason)}</p>${o.item.bonus_text?`<p class="note">Bonus: ${esc(o.item.bonus_text)}</p>`:''}</div></td></tr>`);
      });
    }
    $('visibleResultCount').textContent=`Showing ${visibleItems} demand item${visibleItems===1?'':'s'}${visibleOffers?` and ${visibleOffers} vendor offer${visibleOffers===1?'':'s'}`:''} below.`;
    $('resultRows').innerHTML=rows.join('')||'<tr><td colspan="9">No results in this view.</td></tr>';
  }
  const validQty=value=>value!==''&&Number.isFinite(Number(value))&&Number(value)>0&&Number(value)<=10000;
  function initialQty(d){
    // Box and Pcs together need an explicit unit choice before billing.
    if(d.box&&d.pcs)return '';
    return String(d.qty||d.box||d.pcs||'');
  }
  function updateSelectionPanel(){
    const enabled=$('enableDemandMarks').checked;
    document.querySelector('main.demand').classList.toggle('selecting',enabled);
    $('selectedOffersPanel').hidden=!enabled;
    $('jumpToMarked').hidden=!enabled;
    if(!enabled)return;
    const entries=[...selectedOffers.entries()];
    $('selectedOffersCount').textContent=entries.length
      ?`${entries.length} vendor offer${entries.length===1?'':'s'} marked. Check each quantity and any “Needs review” match before proceeding.`
      :'Mark the vendor offers you want. Unmatched items cannot be marked.';
    $('reviewInBilling').disabled=!entries.length||entries.some(([,s])=>!validQty(s.qty));
    $('selectedOffersList').innerHTML=entries.map(([key,s])=>`<div class="selected-row"><span>${esc(s.demand.name)} → <strong>${esc(s.offer.item.name)}</strong> · ${esc(s.offer.item.vendor||'Vendor missing')}${s.offer.status==='review'?' · Needs review':''}${s.demand.required?' · Lazmi':''}</span><label>Qty <input type="number" min="0.01" max="10000" step="any" inputmode="decimal" data-selected-qty="${key}" value="${esc(s.qty)}" aria-label="Quantity for ${esc(s.offer.item.name)}"></label></div>`).join('');
    const groups=new Map();
    for(const [,s] of entries){
      const vendor=String(s.offer.item.vendor||'').trim();
      if(vendor){if(!groups.has(vendor))groups.set(vendor,[]);groups.get(vendor).push(s);}
    }
    $('selectedVendorList').innerHTML=[...groups].map(([vendor,list])=>`<div class="vendor-send"><strong>${esc(vendor)} · ${list.length} item${list.length===1?'':'s'}</strong><p class="muted note">WhatsApp message will include these items and their selected quantities.</p><div class="controls"><label>Vendor phone (optional) <input type="tel" inputmode="tel" placeholder="Country code + number" data-vendor-phone="${esc(vendor)}" value="${esc(vendorPhones.get(vendor)||'')}"></label><button type="button" class="btn btn-outline" data-copy-vendor="${esc(vendor)}" ${list.some(s=>!validQty(s.qty))?'disabled':''}>Copy order text</button><button type="button" class="btn btn-outline" data-send-vendor="${esc(vendor)}" ${list.some(s=>!validQty(s.qty))?'disabled':''}>WhatsApp this vendor</button></div></div>`).join('');
  }
  $('enableDemandMarks').addEventListener('change',()=>{
    if(!$('enableDemandMarks').checked)selectedOffers.clear();
    updateSelectionPanel();render();
    if($('enableDemandMarks').checked){
      fetch('/api/suppliers').then(r=>r.ok?r.json():[]).then(list=>{
        suppliers=list;
        for(const selected of selectedOffers.values()){
          const vendor=String(selected.offer.item.vendor||'').trim();
          const supplier=list.find(s=>String(s.name||'').trim().toLowerCase()===vendor.toLowerCase());
          if(vendor&&supplier&&!vendorPhones.has(vendor))vendorPhones.set(vendor,String(supplier.phone||''));
        }
        for(const input of $('selectedVendorList').querySelectorAll('input[data-vendor-phone]')){
          if(!input.value)input.value=vendorPhones.get(input.dataset.vendorPhone)||'';
        }
      }).catch(()=>{});
    }
  });
  $('resultRows').addEventListener('change',e=>{
    const mark=e.target.closest('input[data-offer-key]');
    if(!mark)return;
    const key=mark.dataset.offerKey;
    const [dIndex,oIndex]=key.split(':').map(Number);
    const result=results[dIndex],offer=result&&result.offers[oIndex];
    if(!offer)return;
    if(mark.checked){
      selectedOffers.set(key,{demand:result.demand,offer,qty:initialQty(result.demand)});
      const vendor=String(offer.item.vendor||'').trim();
      if(vendor&&!vendorPhones.has(vendor)){
        const supplier=suppliers.find(s=>String(s.name||'').trim().toLowerCase()===vendor.toLowerCase());
        if(supplier)vendorPhones.set(vendor,String(supplier.phone||''));
      }
    }
    else selectedOffers.delete(key);
    updateSelectionPanel();
  });
  $('selectedOffersList').addEventListener('input',e=>{
    const input=e.target.closest('input[data-selected-qty]');
    if(!input)return;
    const selected=selectedOffers.get(input.dataset.selectedQty);
    if(!selected)return;
    selected.qty=input.value;
    const invalid=[...selectedOffers.values()].some(s=>!validQty(s.qty));
    $('reviewInBilling').disabled=invalid;
    for(const button of $('selectedVendorList').querySelectorAll('button[data-send-vendor],button[data-copy-vendor]')){
      const vendor=button.dataset.sendVendor||button.dataset.copyVendor;
      button.disabled=[...selectedOffers.values()].some(s=>String(s.offer.item.vendor||'').trim()===vendor&&!validQty(s.qty));
    }
  });
  $('selectedVendorList').addEventListener('change',e=>{
    const input=e.target.closest('input[data-vendor-phone]');
    if(input)vendorPhones.set(input.dataset.vendorPhone,input.value.trim());
  });
  function vendorOrder(vendor){
    const entries=[...selectedOffers.values()].filter(s=>String(s.offer.item.vendor||'').trim()===vendor);
    if(!entries.length||entries.some(s=>!validQty(s.qty)))return null;
    return [`Order request for ${vendor}`, '',...entries.map((s,i)=>`${i+1}. ${s.offer.item.name} ×${s.qty}${s.demand.required?' (lazmi)':''}${s.offer.status==='review'?` — check against ${s.demand.name}`:''}`)].join('\n');
  }
  $('selectedVendorList').addEventListener('click',async e=>{
    const button=e.target.closest('button[data-send-vendor],button[data-copy-vendor]');
    if(!button)return;
    const vendor=button.dataset.sendVendor||button.dataset.copyVendor;
    const message=vendorOrder(vendor);
    if(!message)return;
    if(button.dataset.copyVendor){
      try{
        if(!await copyText(message))throw Error('Copy failed');
        button.textContent='Copied!';
        setTimeout(()=>{if(button.isConnected)button.textContent='Copy order text';},2000);
      }catch(error){$('selectedOffersCount').textContent='Could not copy the vendor order. Please try WhatsApp instead.';}
      return;
    }
    let phone=String(vendorPhones.get(vendor)||'').replace(/\D/g,'');
    if(/^03\d{9}$/.test(phone))phone='92'+phone.slice(1);
    if(phone&&!/^\d{8,15}$/.test(phone)){
      $('selectedOffersCount').textContent='Enter a valid vendor phone with country code, or leave it blank to choose a WhatsApp contact.';
      return;
    }
    const url=`https://wa.me/${phone}?text=${encodeURIComponent(message)}`;
    const chat=window.open(url,'_blank');
    if(chat)chat.opener=null;
    else{
      $('selectedOffersCount').textContent='WhatsApp could not open. Allow pop-ups or use Copy order text.';
    }
  });
  $('reviewInBilling').addEventListener('click',()=>{
    const entries=[...selectedOffers.values()];
    if(!entries.length||entries.some(s=>!validQty(s.qty)))return;
    try{
      sessionStorage.setItem(billingTransferKey,JSON.stringify(entries.map(s=>({item:s.offer.item,qty:Number(s.qty),demandName:s.demand.name,required:!!s.demand.required,review:s.offer.status==='review'}))));
      location.assign('/billing?demand_selection=1');
    }catch(e){$('selectedOffersCount').textContent='Could not prepare Billing on this device. Please try again.';}
  });
  async function copyText(value){
    if(navigator.clipboard && window.isSecureContext){
      try{await navigator.clipboard.writeText(value);return true;}catch(e){/* Android WebViews may need the fallback below. */}
    }
    const input=document.createElement('textarea');
    input.value=value;input.setAttribute('readonly','');
    input.style.cssText='position:fixed;left:-9999px;top:0';
    document.body.appendChild(input);input.select();
    try{return document.execCommand('copy');}finally{input.remove();}
  }
  $('resultRows').addEventListener('click',async e=>{
    const button=e.target.closest('button[data-copy-offer]');
    if(!button)return;
    const value=copyOffers[Number(button.dataset.copyOffer)];
    if(!value)return;
    try{
      if(!await copyText(value))throw Error('Copy failed');
      button.textContent='Copied!';
      $('copyFeedback').textContent=`Copied: ${value}`;
      setTimeout(()=>{if(button.isConnected)button.textContent='Copy';},2000);
    }catch(e){$('copyFeedback').textContent='Could not copy. Please select the vendor item name and discount manually.';}
  });
  $('resultFilter').addEventListener('change',render);$('resultSort').addEventListener('change',render);
  (async()=>{
    try{
      await ShareStore.pruneStale();
      const file=await ShareStore.takePendingSharedFile();
      if(file){
        // The shared file belongs to this page now. Leaving for Items must
        // not send the user straight back here with the same pending file.
        await ShareStore.clearPendingSharedFile();
        if(!currentFile)await load(file);
      }else{
        const saved=await ShareStore.getDemand(demandOwner);
        if(saved&&!currentFile)await load(saved,/^Pasted demand\.txt$/.test(saved.name),true);
      }
    }
    catch(e){status('Could not restore the shared file. Use Upload Demand to select it.');}
  })();
})();
