const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('frontend/templates/items.html','utf8');
test('import viewport follows keyboard height and pans the vendor inside the scroll area',()=>{
  const props={};const content={scrollTop:0,getBoundingClientRect:()=>({top:60,bottom:300})};
  const list={hidden:false,getBoundingClientRect:()=>({top:100})};
  const field={getBoundingClientRect:()=>({top:320,bottom:364})};
  const overlay={classList:{contains:()=>true,toggle:(name,on)=>props[name]=on},style:{setProperty:(k,v)=>props[k]=v},querySelector:()=>content};
  const ctx={window:{visualViewport:{height:400,offsetTop:24}},requestAnimationFrame:fn=>fn(),document:{activeElement:field,getElementById:id=>id==='importVendor-options'?list:id==='importModal'?overlay:id==='importVendorRow'?{contains:el=>el===field}:field}};
  vm.createContext(ctx);
  vm.runInContext(html.slice(html.indexOf('function syncImportViewport(){'),html.indexOf("window.addEventListener('resize', syncImportViewport)")),ctx);
  ctx.syncImportViewport();
  assert.equal(props['--import-height'],'400px');assert.equal(props['--import-top'],'24px');assert.equal(content.scrollTop,228);
  assert.equal(props['--import-vendors-height'],'192px');
  list.getBoundingClientRect=()=>({top:240});ctx.syncImportViewport();
  assert.equal(props['--import-vendors-height'],'52px');
  content.scrollTop=228;
  ctx.document.activeElement=null;ctx.window.visualViewport={height:800,offsetTop:0};ctx.syncImportViewport();
  assert.equal(props['vendor-editing'],false);assert.equal(props['--import-height'],'800px');assert.equal(content.scrollTop,228);
});
test('initial appearance honours saved dark/light/dim and otherwise uses device dark mode',()=>{
  const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
  for(const [saved,system,expected] of [['dark',false,'dark'],['light',true,''],['dim',true,'dim'],[null,true,'dark'],[null,false,'']]){
    let theme;vm.runInNewContext(script,{localStorage:{getItem:()=>saved},window:{matchMedia:()=>({matches:system})},document:{documentElement:{setAttribute:(k,v)=>theme=v}}});
    assert.equal(theme,expected);
  }
});
