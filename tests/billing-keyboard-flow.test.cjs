const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const edits=html.slice(html.indexOf('function updateQty('),html.indexOf('function updateTax('));
const navigation=html.slice(html.indexOf('const _CART_COL ='),html.indexOf('// Row on which F5/F8/F9 act'));

test('quantity Enter keeps the row mounted and advances focus to discount, then search',()=>{
  const line={qty:1,tp:100,disc:10,tax:2,lineNet:90};
  const amount={textContent:''};
  const focusLog=[];
  let context;
  function field(name){return {
    focus(){
      if(context.document.activeElement===qty) context.updateQty(0,qty.value);
      if(context.document.activeElement===disc) context.updateDisc(0,disc.value);
      context.document.activeElement=this;
      focusLog.push(name);
    },select(){},
  };}
  const qty=field('qty');qty.value='3';
  const disc=field('discount');disc.value='12';
  const search=field('search');
  const cells=Array.from({length:9},()=>({querySelector(){return null;}}));
  cells[2].querySelector=()=>qty;
  cells[3].querySelector=()=>disc;
  const row={querySelectorAll(){return cells;}};
  let renders=0, drafts=0, recalculations=0;
  context={lines:[line],addOnTop:true,document:{activeElement:qty,
    getElementById(id){return id==='linesBody'?{querySelectorAll(){return [row];}}:search;},
    querySelector(selector){assert.equal(selector,'#linesBody tr[data-line-index="0"]');return {querySelectorAll(){return Object.assign([...cells],{7:amount});}};}
  },calcLine(l){l.lineNet=l.qty*l.tp*(1-l.disc/100);},renderLines(){renders++;},
    scheduleAutoDraft(){drafts++;},recalc(){recalculations++;}};
  vm.createContext(context);
  vm.runInContext(edits+navigation,context);
  context._navCartField(0,'d');
  assert.equal(context.document.activeElement,disc);
  assert.equal(line.qty,3);
  assert.equal(amount.textContent,'Rs.276.00');
  context._focusSearch();
  assert.equal(context.document.activeElement,search);
  assert.equal(line.disc,12);
  assert.equal(amount.textContent,'Rs.270.00');
  assert.deepEqual(focusLog,['discount','search']);
  assert.equal(renders,0,'an edit must not replace the active input');
  assert.equal(drafts,2);
  assert.equal(recalculations,2);
});
