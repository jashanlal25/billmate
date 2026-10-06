const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync(require('node:path').join(__dirname,'../frontend/templates/billing.html'),'utf8');
const init=html.slice(html.indexOf("const urlParams=new URLSearchParams"),html.indexOf('function toTitleCase'));
const importer=html.slice(html.indexOf('async function importDemandSelection'),html.indexOf('// Promote the live auto-draft'));
function setup(query,inv){
  let onload;const calls=[];
  const notice={style:{},textContent:''};
  const context={URLSearchParams,IS_GUEST:false,GuestStore:{getInvoice(){return inv;}},
    window:{location:{search:query},addEventListener(name,callback){onload=callback;}},
    document:{getElementById(){return notice;}},
    async fetch(){calls.push('fetch');return{ok:!!inv,json:async()=>inv};},
    loadIntoBuilder(id){calls.push(['load',id]);},_guestLoadIntoBuilder(id){calls.push(['guest',id]);},
    async restoreAutoDraft(){calls.push('restore');},async importDemandSelection(){calls.push('import');},
    currentInv:null};
  vm.createContext(context);vm.runInContext(init,context);
  return{context,calls,notice,load:()=>onload()};
}
test('new demand invoice does not restore the old automatic draft',async()=>{
  const t=setup('?demand_selection=1&demand_new=1');await t.load();
  assert.deepEqual(t.calls,['import']);
});
for(const status of ['posted','draft'])test(`demand appends only after loading chosen ${status} invoice`,async()=>{
  const inv={id:42,status};const t=setup('?demand_selection=1&edit=42',inv);
  await t.load();assert.deepEqual(t.calls,['fetch',['load',42],'import']);
  assert.equal(t.context.currentInv,inv);
});
for(const status of ['finalised','cancelled'])test(`a ${status} target cannot receive demand items`,async()=>{
  const t=setup('?demand_selection=1&edit=42',{id:42,status});await t.load();
  assert.deepEqual(t.calls,['fetch']);assert.match(t.notice.textContent,/no longer editable/);
});
test('failed target load retains demand transfer without importing',async()=>{
  const t=setup('?demand_selection=1&edit=42');await t.load();
  assert.deepEqual(t.calls,['fetch']);assert.match(t.notice.textContent,/could not be loaded/);
});
test('guest saved invoice uses the local builder',async()=>{
  const t=setup('?demand_selection=1&edit=ginv_42',{id:'ginv_42',status:'posted'});
  t.context.IS_GUEST=true;await t.load();assert.deepEqual(t.calls,[['guest','ginv_42'],'import']);
});
test('import retains existing rows and invoice identity and skips repeated inventory items',async()=>{
  const item={id:2,name:'New tablet',vendor:'B',tp:50};
  const original={item_id:1,item_name:'Original tablet',qty:3,tp:100,disc:5};
  const notice={style:{},textContent:''};let removed=false;
  const context={document:{getElementById(){return notice;}},sessionStorage:{
    getItem(){return JSON.stringify([{item:{id:1,name:'Original tablet',vendor:'A'},qty:3},{item,qty:2,customerDiscount:10}]);},
    removeItem(){removed=true;}},lines:[original],savedInvoiceId:42,currentInv:{invoice_number:'INV-42'},
    async _fetchItems(){return[{id:1,name:'Original tablet',vendor:'A'},item];},
    calcLine(line){line.lineNet=line.qty*line.tp*(1-line.disc/100);},renderLines(){},recalc(){}};
  vm.createContext(context);vm.runInContext(importer,context);await context.importDemandSelection();
  assert.equal(context.savedInvoiceId,42);assert.equal(context.lines[0],original);
  assert.equal(context.lines.length,2);assert.equal(context.lines[1].lineNet,90);
  assert.match(notice.textContent,/INV-42/);assert.match(notice.textContent,/1 skipped/);assert.equal(removed,true);
});
