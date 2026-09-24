(function(){
  'use strict';
  const $=id=>document.getElementById(id);
  let demands=[],results=[],currentFile=null,version=0,busy=false;
  let copyOffers=[];
  const status=text=>{$('demandStatus').textContent=text;};
  function controls(){
    $('runDemand').disabled=busy||!demands.length;
    $('inventoryInstead').disabled=busy||!currentFile;
    $('clearDemand').disabled=busy||!currentFile;
    $('demandFile').disabled=busy;
    $('ignoreShelf').disabled=busy;
  }
  function parse(text){
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
  async function load(file){
    const ticket=++version;
    demands=[];results=[];currentFile=file||null;
    $('selectedDemandFile').hidden=!file;
    $('selectedDemandFile').textContent=file?`Attached demand file: ${file.name} (${(file.size/1024).toFixed(1)} KB)` : '';
    $('demandResults').hidden=true;$('demandPreview').hidden=true;controls();
    if(!file){status('No demand loaded.');return;}
    try{
      if(!/\.html?$/i.test(file.name)) throw Error('Choose an HTM or HTML demand file.');
      if(file.size>4*1024*1024) throw Error('Maximum file size is 4 MB.');
      status('Reading demand…');
      const parsed=parse(await file.text());
      if(ticket!==version) return;
      demands=parsed;
      $('previewRows').innerHTML=demands.map(d=>`<tr><td>${esc(d.code)}</td><td>${esc(d.name)}</td><td>${esc(d.box)}</td><td>${esc(d.pcs)}</td></tr>`).join('');
      $('demandPreview').hidden=false;
      status(`${file.name} — ${demands.length} demand items ready. Tap Run Search.`);
    }catch(e){if(ticket===version) status(e.message);}
    controls();
  }
  $('demandFile').addEventListener('change',async e=>{
    await ShareStore.clearPendingSharedFile();
    await load(e.target.files[0]);
  });
  $('ignoreShelf').addEventListener('change',()=>{
    results=[];$('demandResults').hidden=true;
    if(demands.length) status('Matching option changed. Tap Run Search to update results.');
  });
  $('clearDemand').addEventListener('click',async()=>{
    await ShareStore.clearPendingSharedFile();$('demandFile').value='';await load(null);
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
  const demandQty=d=>[d.box&&`${d.box} box`,d.pcs&&`${d.pcs} pcs`].filter(Boolean).join(' · ')||'—';
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
    for(const result of results){
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
      if(!offers.length){rows.push(`<tr class="group-start"><td>${visibleItems}</td><td class="names">${esc(result.demand.name)}</td><td colspan="4">Not found — no compatible inventory entry</td><td>${esc(demandQty(result.demand))}</td><td></td></tr>`);continue;}
      offers.forEach((o,i)=>{
        const copyIndex=copyOffers.push(`${String(o.item.name||'').trim()}-----${discountForCopy(o.item.discount_pct)}`)-1;
        rows.push(`<tr class="${i===0?'group-start':''}"><td>${visibleItems}.${offerLetter(i)}</td><td class="names">${esc(result.demand.name)}</td><td class="names">${esc(o.item.name)}<button type="button" class="copy-offer" data-copy-offer="${copyIndex}" aria-label="Copy ${esc(o.item.name)} and discount">Copy</button></td><td>${esc(o.item.vendor||'Not specified')}</td><td>${money(o.item.discount_pct)}</td><td>${money(o.item.tp)}</td><td>${esc(demandQty(result.demand))}</td><td><div class="${o.status==='review'?'review':''}"><strong>${o.status==='review'?'Needs review':'Matching details'}</strong><p class="note">${esc(o.reason)}</p>${o.item.bonus_text?`<p class="note">Bonus: ${esc(o.item.bonus_text)}</p>`:''}</div></td></tr>`);
      });
    }
    $('visibleResultCount').textContent=`Showing ${visibleItems} demand item${visibleItems===1?'':'s'}${visibleOffers?` and ${visibleOffers} vendor offer${visibleOffers===1?'':'s'}`:''} below.`;
    $('resultRows').innerHTML=rows.join('')||'<tr><td colspan="8">No results in this view.</td></tr>';
  }
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
      }
    }
    catch(e){status('Could not restore the shared file. Use Upload Demand to select it.');}
  })();
})();
