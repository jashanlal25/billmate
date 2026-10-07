const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {safeName,canShare,canvasBlob}=require('../frontend/static/js/invoice-image.js');

test('image download names cannot contain directories or leading dots',()=>{
  assert.equal(safeName('../../SSD 0027'),'_.._SSD_0027');
  assert.equal(safeName('SSD-0027'),'SSD-0027');
  assert.equal(safeName('...'),'invoice');
});

test('an unsupported or throwing file-share capability selects the save fallback',()=>{
  const oldShare=navigator.share,oldCanShare=navigator.canShare;
  try{
    navigator.share=()=>{};navigator.canShare=()=>false;
    assert.equal(canShare([{}]),false);
    navigator.canShare=()=>{throw new Error('unsupported');};
    assert.equal(canShare([{}]),false);
    navigator.canShare=()=>true;
    assert.equal(canShare([{}]),true);
  }finally{
    if(oldShare===undefined)delete navigator.share;else navigator.share=oldShare;
    if(oldCanShare===undefined)delete navigator.canShare;else navigator.canShare=oldCanShare;
  }
});

test('empty canvas output is rejected instead of offering a corrupt image',async()=>{
  await assert.rejects(canvasBlob({toBlob:fn=>fn(null)}),/Could not create/);
  const blob=new Blob(['jpeg'],{type:'image/jpeg'});
  assert.equal(await canvasBlob({toBlob:(fn,type,quality)=>{
    assert.equal(type,'image/jpeg');assert.equal(quality,0.95);fn(blob);
  }}),blob);
});

test('saved and viewed images reuse PDF preferences without modifying the invoice',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../frontend/templates/billing.html'),'utf8');
  const source=html.slice(html.indexOf('function imageToCustomer(){'),html.indexOf('function pdfToCustomer(){'));
  const invoice={invoice_number:'SSD-27',lines:[{item_name:'MED A',qty:2}]};
  const before=JSON.stringify(invoice), calls=[];
  const ctx={lastSavedInv:invoice,currentInv:invoice,_invWithPhone:i=>i,
    _psShowVendor:()=>false,_psShowBalance:()=>true,_psShowPhone:()=>false,
    _showRateSourcePref:()=>true,_showVendorPref:()=>false,_mShowBalancePref:()=>false,_mShowPhonePref:()=>true,
    buildInvoicePrintHtml:(...args)=>{calls.push(args);return 'PDF layout';},
    BillMateInvoiceImage:{prepare:args=>args}};
  vm.createContext(ctx);vm.runInContext(source,ctx);
  const saved=ctx.imageToCustomer(),viewed=ctx.imageToCustomerModal();
  assert.equal(saved.filename,'SSD-27');assert.equal(viewed.html,'PDF layout');
  assert.deepEqual(calls[0],[invoice,true,false,false,true,false]);
  assert.deepEqual(calls[1],[invoice,true,true,false,false,true]);
  assert.equal(JSON.stringify(invoice),before);
});
