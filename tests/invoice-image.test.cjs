const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {safeName,canShare,canvasBlob,shareFiles}=require('../frontend/static/js/invoice-image.js');

test('image download names cannot contain directories or leading dots',()=>{
  assert.equal(safeName('../../SSD 0027'),'_.._SSD_0027');
  assert.equal(safeName('SSD-0027'),'SSD-0027');
  assert.equal(safeName('...'),'invoice');
});

test('the Android bridge enables sharing without a browser file-share API',async()=>{
  const messages=[];
  globalThis.__BILLMATE_NATIVE__=true;globalThis.__BILLMATE_IMAGE_SHARE__=true;
  globalThis.BillMateNativeShare={postMessage:s=>messages.push(JSON.parse(s))};
  globalThis.FileReader=class {
    readAsDataURL(file){file.arrayBuffer().then(bytes=>{
      this.result='data:'+file.type+';base64,'+Buffer.from(bytes).toString('base64');this.onload();
    });}
  };
  try{
    const files=[new File([new Uint8Array([255,216,255,0,255,217])],'SSD-34.jpg',{type:'image/jpeg'})];
    assert.equal(canShare(files),true);
    await shareFiles(files,'SSD-34');
    assert.equal(messages[0].action,'share_images');
    assert.equal(messages[0].files[0].filename,'SSD-34.jpg');
    assert.equal(messages[0].files[0].mime,'image/jpeg');
    assert.equal(Buffer.from(messages[0].files[0].data_b64,'base64').length,6);
    assert.equal(canShare(Array(51).fill(files[0])),false);
    assert.equal(canShare([{size:21*1024*1024}]),false);
  }finally{
    delete globalThis.__BILLMATE_NATIVE__;delete globalThis.__BILLMATE_IMAGE_SHARE__;
    delete globalThis.BillMateNativeShare;delete globalThis.FileReader;
  }
});

test('older Android apps request an update rather than accepting an unsupported image action',async()=>{
  const messages=[];
  globalThis.__BILLMATE_NATIVE__=true;
  globalThis.BillMateNativeShare={postMessage:s=>messages.push(JSON.parse(s))};
  try{
    const files=[new File(['image'],'SSD-34.jpg',{type:'image/jpeg'})];
    assert.equal(canShare(files),true,'the Share button remains available');
    await assert.rejects(shareFiles(files),/Update BillMate/);
    assert.deepEqual(messages,[{action:'check_update'}]);
  }finally{delete globalThis.__BILLMATE_NATIVE__;delete globalThis.BillMateNativeShare;}
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
