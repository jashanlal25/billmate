const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync(require('node:path').join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('let _ieOriginal ='),html.indexOf("document.addEventListener('click', ()=>{ document.querySelectorAll('.line-menu.open')"));
const offer={id:2,name:'EMPAA VENDOR B',code:'+021',vendor:'B',vendor_code:'+021',vendor_name:'EMPAA ORIGINAL B',vendor_list_no:'000897',vendor_discount_pct:8,discount_pct:3,tp:100,retail_price:120,tax_pct:0,bonus_text:'10+1',rate_source:'B list'};
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
