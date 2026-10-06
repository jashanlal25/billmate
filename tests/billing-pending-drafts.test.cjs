const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync(require('node:path').join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('function _renderHistoryRows('),html.indexOf('function _guestViewInvoice('));
const draft=id=>({id,invoice_number:'DRAFT-'+id,status:'draft',customer_name:'Walk-in',total:100});
function setup(drafts,{guest=false,failed=false}={}){
  const nodes={},urls=[];
  const context={IS_GUEST:guest,setupCompleted:true,
    document:{getElementById(id){return nodes[id]||=( {textContent:'',innerHTML:'',hidden:false});}},
    GuestStore:{getInvoices(){return[...drafts,{id:99,invoice_number:'SSD-0028',status:'posted',total:1049}];}},
    esc(s){return String(s??'').replace(/"/g,'&quot;');},statusLabel:s=>s,
    async fetch(url){
      urls.push(url);
      if(url.includes('billing_target=draft')){
        const offset=Number(new URL(url,'https://billmate.test').searchParams.get('offset'));
        return{ok:!failed,json:async()=>({items:drafts.slice(offset,offset+20),total:drafts.length})};
      }
      return{ok:true,json:async()=>({items:[{id:99,invoice_number:'SSD-0028',status:'posted',total:1049}]})};
    }};
  vm.createContext(context);vm.runInContext(source,context);return{context,nodes,urls};
}
test('Billing shows the same three automatic drafts as Demand Search and keeps recent invoices',async()=>{
  const t=setup([draft(1),draft(2),draft(3)]);await t.context.loadHistory();
  assert.equal(t.nodes.pendingDraftTitle.textContent,'Pending drafts (3)');
  for(let id=1;id<=3;id++)assert.match(t.nodes.pendingDraftList.innerHTML,new RegExp('DRAFT-'+id));
  assert.equal((t.nodes.pendingDraftList.innerHTML.match(/▶ Resume/g)||[]).length,3);
  assert.match(t.nodes.histList.innerHTML,/SSD-0028/);assert.equal(t.nodes.pendingDraftMore.hidden,true);
});
test('all drafts remain accessible beyond the five recent invoices and the first page',async()=>{
  const t=setup(Array.from({length:21},(_,i)=>draft(i+1)));await t.context.loadPendingDrafts();
  assert.equal((t.nodes.pendingDraftList.innerHTML.match(/▶ Resume/g)||[]).length,20);
  assert.equal(t.nodes.pendingDraftMore.hidden,false);await t.context.loadPendingDrafts(true);
  assert.match(t.urls[1],/offset=20/);
  assert.equal((t.nodes.pendingDraftList.innerHTML.match(/▶ Resume/g)||[]).length,21);
  assert.equal(t.nodes.pendingDraftMore.hidden,true);
});
test('unavailable pending drafts show a loading error rather than a false zero',async()=>{
  const t=setup([draft(1)],{failed:true});await t.context.loadPendingDrafts();
  assert.equal(t.nodes.pendingDraftTitle.textContent,'Pending drafts');
  assert.match(t.nodes.pendingDraftList.textContent,/Could not load/);
});
test('guest pending drafts are counted and rendered separately from saved invoices',async()=>{
  const t=setup([draft('ginv_1')],{guest:true});await t.context.loadHistory();
  assert.equal(t.nodes.pendingDraftTitle.textContent,'Pending drafts (1)');
  assert.match(t.nodes.pendingDraftList.innerHTML,/_guestLoadIntoBuilder\(&quot;ginv_1&quot;\)/);
  assert.doesNotMatch(t.nodes.histList.innerHTML,/DRAFT-/);assert.equal(t.urls.length,0);
});
