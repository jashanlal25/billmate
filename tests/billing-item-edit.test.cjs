const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync(require('node:path').join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('let _ieOriginal ='),html.indexOf("document.addEventListener('click', ()=>{ document.querySelectorAll('.line-menu.open')"));
const offer={id:2,name:'EMPAA VENDOR B',code:'+021',vendor:'B',vendor_code:'+021',vendor_name:'EMPAA ORIGINAL B',vendor_list_no:'000897',vendor_discount_pct:8,discount_pct:3,tp:100,retail_price:120,tax_pct:0,bonus_text:'10+1',rate_source:'B list'};
const previous={...offer,id:null,historical:true,previous_invoice:'SSD-0013'};
function setup(){
 const nodes={};
 const row={item_id:1,item_name:'EMPAA A',qty:7,tp:90,disc:1,vendor:'A',vendor_code:'2983',vendor_list_no:'000052',vendor_discount_pct:2};
 const context={lines:[row],document:{getElementById(id){return nodes[id] ||= {value:'',textContent:'',innerHTML:'',classList:{add(){},remove(){}}};},querySelectorAll(){return[];}},setTimeout(){return 1;},clearTimeout(){},_fetchItems(){throw Error('not invoked by test');},esc:s=>s,toast(){},calcLine(l){l.lineNet=l.qty*l.tp*(1-l.disc/100);},renderLines(){},recalc(){}};
 vm.createContext(context);vm.runInContext(source,context);
 return {context,nodes,row,run:s=>vm.runInContext(s,context)};
}
test('replacement changes supplier identity, retains quantity and isolates customer discount',()=>{
 const t=setup();t.context.offer=offer;
 t.run('openItemEdit(0); _ieOffers=[offer]; selectItemEdit(0)');
 assert.equal(t.context.lines[0],t.row,'Selection must not commit before Apply');
 t.nodes.ie_disc.value='0';t.run('saveItemEdit()');
 const l=t.context.lines[0];
 assert.equal(l.item_id,2);assert.equal(l.qty,7);assert.equal(l.vendor,'B');
 assert.equal(l.vendor_code,'+021');assert.equal(l.vendor_list_no,'000897');
 assert.equal(l.vendor_name,'EMPAA ORIGINAL B');assert.equal(l.vendor_discount_pct,8);assert.equal(l.disc,0);
 assert.equal(l.lineNet,700);assert.equal(offer.discount_pct,3,'Catalog must stay unchanged');
});
test('cancel discards all pending replacement and amount edits',()=>{
 const t=setup();t.context.offer=offer;t.run('openItemEdit(0); _ieOffers=[offer]; selectItemEdit(0); closeItemEdit()');
 assert.equal(t.context.lines[0],t.row);assert.equal(t.row.vendor,'A');
});
test('invalid price keeps editor pending and does not modify billing',()=>{
 const t=setup();t.run('openItemEdit(0)');t.nodes.ie_tp.value='-2';t.run('saveItemEdit()');assert.equal(t.context.lines[0],t.row);
});
test('row identity prevents editing a different row after array changes',()=>{
 const t=setup();t.run('openItemEdit(0); lines.shift(); lines.push({item_name:"unrelated"}); saveItemEdit()');
 assert.equal(t.context.lines[0].item_name,'unrelated');
});
test('cancelling a historical replacement keeps original item and vendor untouched',async()=>{
 const t=setup();let confirmation;
 t.context.previous=previous;t.context.BMConfirm=async(...args)=>{confirmation=args;return false;};
 t.run('openItemEdit(0); _ieOffers=[previous]');await t.run('selectItemEdit(0)');
 assert.match(confirmation[0],/SSD-0013/);assert.match(confirmation[0],/Saved vendor: B/);
 assert.equal(confirmation[2].okText,'Use previous details');
 assert.equal(t.run('_ieDraft.item_id'),1);assert.equal(t.context.lines[0],t.row);
 assert.equal(t.nodes.ie_history_notice.hidden,true);
});
test('confirmed history remains a pending edit with a warning, then applies with original quantity',async()=>{
 const t=setup();t.context.previous=previous;t.context.BMConfirm=async()=>true;
 t.run('openItemEdit(0); _ieOffers=[previous]');await t.run('selectItemEdit(0)');
 assert.equal(t.context.lines[0],t.row);assert.equal(t.nodes.ie_history_notice.hidden,false);
 assert.match(t.nodes.ie_history_notice.textContent,/Previous bill details · SSD-0013/);
 assert.match(t.nodes.ie_history_notice.textContent,/availability unverified/);
 t.run('saveItemEdit()');const line=t.context.lines[0];
 assert.equal(line.historical,true);assert.equal(line.previous_invoice,'SSD-0013');
 assert.equal(line.qty,7);assert.equal(line.vendor,'B');assert.equal(line.item_id,null);
});
test('selecting a current offer clears the historical warning without another confirmation',async()=>{
 const t=setup();let prompts=0;t.context.previous=previous;t.context.offer=offer;
 t.context.BMConfirm=async()=>{prompts++;return true;};
 t.run('openItemEdit(0); _ieOffers=[previous,offer]');await t.run('selectItemEdit(0)');await t.run('selectItemEdit(1)');
 assert.equal(prompts,1);assert.equal(t.nodes.ie_history_notice.hidden,true);
 assert.equal(t.run('_ieDraft.historical'),false);assert.equal(t.run('_ieDraft.previous_invoice'),'');
});
test('closing and reopening the editor invalidates an outstanding historical confirmation',async()=>{
 const t=setup();let resolve;t.context.previous=previous;
 t.context.BMConfirm=()=>new Promise(r=>{resolve=r;});
 t.run('openItemEdit(0); _ieOffers=[previous]');const pending=t.run('selectItemEdit(0)');
 t.run('closeItemEdit();openItemEdit(0)');resolve(true);await pending;
 assert.equal(t.run('_ieDraft.item_id'),1);assert.equal(t.nodes.ie_history_notice.hidden,true);
});
test('search groups historical matches after current offers with one labelled divider',async()=>{
 const t=setup();let search;t.context.setTimeout=callback=>{search=callback;return 1;};
 t.context._fetchItems=async()=>[previous,offer];
 t.run('openItemEdit(0)');await search();
 const html=t.nodes.ie_results.innerHTML;
 assert(html.indexOf('selectItemEdit(0)')<html.indexOf('<summary'));
 assert(html.indexOf('<summary')<html.indexOf('Previous bill SSD-0013'));
 assert.match(html,/Not in current vendor list/);assert.match(html,/Saved TP: 100.00/);
 assert.equal((html.match(/<summary/g)||[]).length,1);
 assert.match(html,/<details class="ie-history-group">/);
 assert.match(html,/class="ie-history-arrow" aria-hidden="true">v</);
});
test('editing an existing historical row does not request replacement confirmation',()=>{
 const t=setup();t.row.historical=true;t.row.previous_invoice='SSD-0001';
 t.context.BMConfirm=()=>{throw Error('Existing row should not ask');};
 t.run('openItemEdit(0);saveItemEdit()');assert.equal(t.context.lines[0].item_id,1);
});
