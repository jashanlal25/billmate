const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../frontend/templates/items.html'), 'utf8');
function setup(names){
  class Element {
    constructor(){ this.value=''; this.children=[]; this.attrs={}; this.events={}; }
    setAttribute(k,v){ this.attrs[k]=v; }
    removeAttribute(k){ delete this.attrs[k]; }
    addEventListener(k,fn){ (this.events[k] ||= []).push(fn); }
    dispatchEvent(e){ for(const fn of this.events[e.type] || []) fn(e); }
    after(node){ this.list=node; }
    replaceChildren(){ this.children=[]; }
    append(node){ this.children.push(node); }
    contains(node){ return this === node || this.children.includes(node); }
    scrollIntoView(){}
  }
  const inputs = {f_vendor:new Element(),importVendor:new Element()};
  const document = new Element();
  document.getElementById = id=>inputs[id];
  document.createElement = ()=>new Element();
  const context = vm.createContext({document, Event:class { constructor(type){this.type=type;} }});
  const start = source.indexOf('let supplierNames = []');
  vm.runInContext(source.slice(start, source.indexOf('\nloadCategories();', start)), context);
  vm.runInContext(`supplierNames=['G.H MEDICAL','GEHI DR','GH','<Vendor>'];`, context);
  if(names) vm.runInContext('supplierNames=' + JSON.stringify(names), context);
  function fire(node,type,extra={}){ node.dispatchEvent({type,preventDefault(){},stopPropagation(){},...extra}); }
  return {inputs,document,fire};
}
test('both vendor fields filter punctuation and select names using touch/click',()=>{
  const {inputs,fire}=setup();
  for(const input of Object.values(inputs)){
    input.value='g h'; fire(input,'input');
    assert.deepEqual(input.list.children.map(x=>x.textContent),['GH','G.H MEDICAL']);
    fire(input.list.children[1],'click');
    assert.equal(input.value,'G.H MEDICAL');
    assert.equal(input.list.hidden,true);
    assert.equal(input.attrs['aria-expanded'],'false');
  }
});
test('keyboard navigation selects, Escape and outside interaction dismiss',()=>{
  const {inputs,document,fire}=setup(); const input=inputs.importVendor;
  fire(input,'focus'); fire(input,'keydown',{key:'ArrowDown'}); fire(input,'keydown',{key:'Enter'});
  assert.equal(input.value,'G.H MEDICAL');
  fire(input,'focus'); fire(input,'keydown',{key:'Escape'}); assert.equal(input.list.hidden,true);
  fire(input,'focus'); fire(document,'pointerdown',{target:{}}); assert.equal(input.list.hidden,true);
  fire(input,'focus'); fire(input,'keydown',{key:'Tab'}); assert.equal(input.list.hidden,true);
});
test('new names remain editable and supplier text is not interpreted as HTML',()=>{
  const {inputs,fire}=setup(); const input=inputs.f_vendor;
  input.value='New supplier'; fire(input,'input');
  assert.equal(input.value,'New supplier'); assert.equal(input.list.hidden,true);
  input.value='<'; fire(input,'input');
  assert.equal(input.list.children.at(-1).textContent,'<Vendor>');
});

test('backspacing a middle name retains the saved full-name suggestion',()=>{
  const {inputs,fire}=setup(['MAJID HANZLA TRADER','OTHER SUPPLIER']);
  for(const input of Object.values(inputs)){
    for(const query of ['HAnzla','HAnzl','HAnz','HAn','HA','H']){
      input.value=query; fire(input,'input');
      assert.ok(input.list.children.some(option=>option.textContent==='MAJID HANZLA TRADER'),query);
      assert.equal(input.value,query, 'suggestions must not overwrite typing');
    }
  }
});
test('full filename and reordered words find the shorter saved vendor',()=>{
  const {inputs,fire}=setup(['HANZLA','MAJID HANZLA TRADER','OTHER TRADER']);
  const input=inputs.importVendor;
  for(const query of ['Majid Hanzla Trader','Hanzla Majid','Majid Hanzl']){
    input.value=query; fire(input,'input');
    const names=input.list.children.map(option=>option.textContent);
    assert.ok(names.includes('HANZLA'),query);
    assert.ok(names.includes('MAJID HANZLA TRADER'),query);
    assert.ok(!names.includes('OTHER TRADER'),query);
    assert.equal(names[0],'MAJID HANZLA TRADER');
  }
});

test('complete HAnzla plus trailing spaces keeps HAnzla Majid visible without deletion',()=>{
  const {inputs,fire}=setup(['HAnzla Majid','MAJID HANZLA TRADER','OTHER SUPPLIER']);
  for(const input of Object.values(inputs)){
    for(const query of ['HAnzla','HAnzla ','HAnzla  ',' HAnzla ','HAnzla\u00a0']){
      input.value=query; fire(input,'input');
      assert.deepEqual(input.list.children.map(option=>option.textContent),['HAnzla Majid','MAJID HANZLA TRADER'],JSON.stringify(query));
      assert.equal(input.list.hidden,false);
      assert.equal(input.attrs['aria-expanded'],'true');
      assert.equal(input.value,query,'preserve the typed name and spaces');
    }
    fire(input.list.children[0],'click');
    assert.equal(input.value,'HAnzla Majid');
    assert.equal(input.list.hidden,true);
  }
});
