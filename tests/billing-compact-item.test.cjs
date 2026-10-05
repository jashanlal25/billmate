const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
const source=html.slice(html.indexOf('const _compactLines ='),html.indexOf('function renderLines()'));

test('new entries finish at discount; reopened cards collapse again on return to search',()=>{
  const listeners={};
  const classes=new Set();
  const row={dataset:{lineIndex:'0'},children:[],classList:{add:c=>classes.add(c),remove:c=>classes.delete(c)}};
  const discount={closest:()=>row};
  const qty={closest:()=>row};
  row.children[3]={querySelector:()=>discount};
  const line={qty:3,disc:13};
  const context={lines:[line],document:{addEventListener:(type,fn)=>listeners[type]=fn,querySelector:()=>row}};
  vm.createContext(context);vm.runInContext(source,context);
  listeners.focusin({target:{id:'itemSearch',closest:()=>null},relatedTarget:qty});
  assert.equal(classes.size,0,'quantity must not collapse the card');
  listeners.focusin({target:{id:'elsewhere',closest:()=>null},relatedTarget:discount});
  assert.equal(classes.size,0,'discount blur elsewhere must not collapse the card');
  listeners.focusin({target:{id:'itemSearch',closest:()=>null},relatedTarget:discount});
  assert.ok(classes.has('line-compact'));
  assert.ok(vm.runInContext('_compactLines.has(lines[0])',context));
  listeners.click({target:{closest:selector=>selector.startsWith('#linesBody')?row:{}}});
  assert.ok(classes.has('line-compact'),'compact controls must remain usable');
  listeners.click({target:{closest:selector=>selector.startsWith('#linesBody')?row:null}});
  assert.equal(classes.size,0);
  assert.equal(vm.runInContext('_compactLines.has(lines[0])',context),false);
  // The search can already have focus when a card background is clicked.
  listeners.click({target:{id:'itemSearch',closest:()=>null}});
  assert.ok(classes.has('line-compact'),'clicking search closes a reopened card even without a new focus event');
  listeners.focusin({target:{tagName:'INPUT',closest:()=>row}});
  assert.equal(classes.size,0,'clicking/focusing a compact input opens the existing editor');
  listeners.focusin({target:{id:'itemSearch',closest:()=>null},relatedTarget:null});
  assert.ok(classes.has('line-compact'),'returning to search closes a reopened card even if relatedTarget is missing');
  assert.ok(vm.runInContext('_compactLines.has(lines[0])',context));
  assert.deepEqual(line,{qty:3,disc:13});
});

