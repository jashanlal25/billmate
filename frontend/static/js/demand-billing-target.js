(function(){
  'use strict';
  const $=id=>document.getElementById(id);
  const dialog=$('demandBillingTarget'),mode=$('demandBillingMode');
  const search=$('demandBillingSearch'),list=$('demandBillingList');
  const status=$('demandBillingStatus'),more=$('demandBillingMore');
  const guest=document.querySelector('main.demand').dataset.guest==='true';
  let choose=null,version=0,offset=0,timer=null;
  function finish(target){
    const callback=choose;
    dialog.close();
    if(callback)callback(target);
  }
  async function load(append=false){
    const ticket=++version,currentMode=mode.value;
    if(!append){offset=0;list.replaceChildren();}
    more.hidden=true;status.textContent='Loading invoices…';
    try{
      let rows,total;
      if(guest){
        const query=search.value.trim().toLowerCase();
        const invoices=JSON.parse(localStorage.getItem('g_invoices')||'[]');
        const filtered=invoices.filter(inv=>inv.status===currentMode&&
          (!query||`${inv.invoice_number} ${inv.customer_name}`.toLowerCase().includes(query)));
        total=filtered.length;rows=filtered.slice(offset,offset+20);
      }else{
        const params=new URLSearchParams({billing_target:currentMode,q:search.value.trim(),offset:String(offset),limit:'20'});
        const response=await fetch('/api/invoices?'+params.toString(),{cache:'no-store'});
        if(!response.ok)throw Error('Could not load invoices. Try again.');
        const data=await response.json();
        if(!Array.isArray(data.items))throw Error('Could not load invoices. Try again.');
        rows=data.items;total=data.total;
      }
      if(ticket!==version||!dialog.open)return;
      for(const inv of rows){
        if(inv.status!==currentMode)continue;
        const button=document.createElement('button');button.type='button';
        button.textContent=String(inv.invoice_number||'Pending draft');
        const detail=document.createElement('small');
        detail.textContent=`${inv.customer_name||'Walk-in'} · ${inv.invoice_date||''} · Rs.${Number(inv.total||0).toFixed(2)}`;
        button.appendChild(detail);
        button.addEventListener('click',()=>finish(String(inv.id)));
        list.appendChild(button);
      }
      offset+=rows.length;more.hidden=offset>=total||rows.length===0;
      status.textContent=total?`${total} ${currentMode==='draft'?'pending draft':'saved invoice'}${total===1?'':'s'}. Select one below.`:
        `No ${currentMode==='draft'?'pending drafts':'editable saved invoices'} found.`;
    }catch(error){
      if(ticket!==version||!dialog.open)return;
      status.textContent=error.message||'Could not load invoices. Try again.';
      more.hidden=false;more.textContent='Retry';
    }
  }
  function changeMode(){
    clearTimeout(timer);version++;search.value='';more.textContent='Load more';
    const existing=mode.value!=='new';
    $('demandBillingExisting').hidden=!existing;
    $('demandBillingNew').hidden=existing;
    if(existing)load();
  }
  mode.addEventListener('change',changeMode);
  search.addEventListener('input',()=>{
    clearTimeout(timer);version++;list.replaceChildren();more.hidden=true;
    status.textContent='Searching…';timer=setTimeout(()=>load(),250);
  });
  more.addEventListener('click',()=>{more.textContent='Load more';load(true);});
  $('demandBillingNew').addEventListener('click',()=>finish('new'));
  $('demandBillingCancel').addEventListener('click',()=>dialog.close());
  dialog.addEventListener('close',()=>{version++;clearTimeout(timer);choose=null;});
  window.DemandBillingTarget={open(callback){
    choose=callback;mode.value='new';changeMode();dialog.showModal();
  }};
})();
