(() => {
  const byId = id => document.getElementById(id);
  const start = byId('profitStart'), end = byId('profitEnd'), group = byId('profitGroup'), search = byId('profitSearch');
  const labels = {customer:'Customer', item:'Item', day:'Day', month:'Month'};
  const currency = value => 'Rs. ' + Number(value).toLocaleString('en-PK', {minimumFractionDigits:2, maximumFractionDigits:2});
  const todayParts = new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Karachi', year:'numeric', month:'2-digit', day:'2-digit'}).formatToParts(new Date());
  const today = Object.fromEntries(todayParts.map(p => [p.type,p.value]));
  const iso = (y,m,d) => `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
  let controller, loaded = false;
  function preset(period) {
    const y=Number(today.year), m=Number(today.month);
    end.value=iso(y,m,today.day);
    if(period==='today') start.value=end.value;
    else if(period==='year') start.value=iso(y,1,1);
    else if(period==='last-month') {
      const last=new Date(Date.UTC(y,m-1,0));
      start.value=iso(last.getUTCFullYear(),last.getUTCMonth()+1,1);
      end.value=iso(last.getUTCFullYear(),last.getUTCMonth()+1,last.getUTCDate());
    } else start.value=iso(y,m,1);
  }
  async function load() {
    if(!byId('profitFilters').reportValidity()) return;
    if(start.value>end.value) {byId('profitStatus').textContent='Start date must be before or equal to end date.';return;}
    if(controller) controller.abort();
    controller=new AbortController();
    const current=controller;
    byId('profitRefresh').disabled=true;
    byId('profitSummary').hidden=true;
    byId('profitWarning').hidden=true;
    byId('profitRows').replaceChildren();
    byId('profitStatus').textContent='Loading profit…';
    try {
      const params=new URLSearchParams({start:start.value,end:end.value,group_by:group.value,q:search.value.trim()});
      const response=await fetch('/api/profit?'+params,{signal:current.signal,cache:'no-store',headers:{'Accept':'application/json','Content-Type':'application/json'}});
      if(!response.ok) {
        const data=await response.json().catch(()=>({}));
        throw new Error(data.error||'Unable to load profit. Please try again.');
      }
      const data=await response.json(), s=data.summary;
      const cards=[['Purchase total',s.purchases,'All purchases in these dates'],['Sales amount',s.sales,'Saved sales in this breakdown'],['Cost of sold items',s.cost,'Matched purchase costs'],[s.complete?'Gross profit':'Known gross profit',s.profit,s.margin===null?'No matched sales':`${s.margin}% margin on matched sales`]];
      byId('profitSummary').innerHTML=cards.map(([label,value,note],i)=>`<div class="profit-stat"><small>${label}</small><strong class="${i===3?(value<0?'profit-negative':'profit-positive'):''}">${currency(value)}</strong><small>${esc(note)}</small></div>`).join('');
      byId('profitSummary').hidden=false;
      if(!s.complete) {
        byId('profitWarning').textContent=`Purchase costs are missing for ${s.missing_qty} sold units. Rs. ${(s.sales-s.matched_sales).toFixed(2)} of sales is uncosted. Known gross profit includes only quantities with a matched purchase. Enter the purchase with the correct date, or create it from its sales invoice, then refresh.`;
        byId('profitWarning').hidden=false;
      }
      byId('profitTitle').textContent=labels[data.group_by]+' wise profit';
      byId('profitStatus').textContent=`${data.start} to ${data.end} · ${data.rows.length} ${labels[data.group_by].toLowerCase()} groups · Updated just now`;
      byId('profitRows').innerHTML=data.rows.length?`<table class="profit-table"><thead><tr><th>${labels[data.group_by]}</th><th>Qty sold</th><th>Sales amount</th><th>Purchase cost of sold items</th><th>Gross profit</th><th>Margin</th></tr></thead><tbody>${data.rows.map(row=>`<tr><td>${esc(row.label)}${row.complete?'':`<small>Missing cost: ${row.missing_qty} units</small>`}</td><td data-label="Qty sold"><span>${row.qty}</span></td><td data-label="Sales amount"><span>${currency(row.sales)}</span></td><td data-label="Cost of sold items"><span>${currency(row.cost)}</span></td><td data-label="${row.complete?'Gross profit':'Known profit'}"><span class="${row.profit<0?'profit-negative':'profit-positive'}">${currency(row.profit)}${row.complete?'':'*'}</span></td><td data-label="Margin"><span>${row.margin===null?'—':row.margin+'%'}</span></td></tr>`).join('')}</tbody></table>`:'<div class="profit-empty">No saved sales match these filters. Purchases will show above; profit appears when items are sold.</div>';
      loaded=true;
    } catch(error) {
      if(error.name!=='AbortError') {byId('profitStatus').textContent=error.message;loaded=false;}
    } finally {if(current===controller) byId('profitRefresh').disabled=false;}
  }
  byId('profitFilters').addEventListener('submit',event=>{event.preventDefault();load();});
  group.addEventListener('change',()=>{search.value='';search.placeholder=group.value==='customer'?'Customer name':group.value==='item'?'Item name':group.value==='day'?'YYYY-MM-DD':'YYYY-MM';load();});
  start.addEventListener('change',load);end.addEventListener('change',load);
  document.querySelectorAll('[data-period]').forEach(button=>button.addEventListener('click',()=>{preset(button.dataset.period);load();}));
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&loaded)load();});
  window.addEventListener('pageshow',event=>{if(event.persisted)load();});
  preset('month');load();
})();
