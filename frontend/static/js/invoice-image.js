(function(root){
  'use strict';
  const PAGE_WIDTH=794, PAGE_HEIGHT=1123, CONTENT_HEIGHT=1090;
  let rendererPromise=null, active=null;

  function safeName(value){
    return String(value||'invoice').replace(/[^A-Za-z0-9._-]+/g,'_').replace(/^\.+/,'')||'invoice';
  }
  function nativeBridge(){
    return !!(root.__BILLMATE_NATIVE__ && root.BillMateNativeShare && typeof root.BillMateNativeShare.postMessage==='function');
  }
  function canShare(files){
    if(nativeBridge())return files.length>0 && files.length<=50 && files.reduce((n,f)=>n+f.size,0)<=20*1024*1024;
    try{return !!(root.navigator.share && root.navigator.canShare && root.navigator.canShare({files}));}
    catch(_){return false;}
  }
  function imageData(file){
    return new Promise((resolve,reject)=>{
      const reader=new FileReader();
      reader.onerror=()=>reject(new Error('Could not read the bill image. Please try again.'));
      reader.onload=()=>{
        const value=String(reader.result||''), comma=value.indexOf(',');
        if(comma<0)return reject(new Error('Invalid bill image. Please try again.'));
        resolve({filename:file.name,mime:file.type,data_b64:value.slice(comma+1)});
      };
      reader.readAsDataURL(file);
    });
  }
  async function shareFiles(files,title){
    if(nativeBridge()){
      if(!root.__BILLMATE_IMAGE_SHARE__){
        root.BillMateNativeShare.postMessage(JSON.stringify({action:'check_update'}));
        throw new Error('Update BillMate to enable image sharing, then reopen this bill and tap Share image.');
      }
      if(!canShare(files))throw new Error('These images are too large to share together. Share each page separately.');
      const images=await Promise.all(files.map(imageData));
      root.BillMateNativeShare.postMessage(JSON.stringify({action:'share_images',files:images}));
      return;
    }
    return root.navigator.share({files,title:title||'Invoice'});
  }
  function loadRenderer(){
    if(root.html2canvas) return Promise.resolve(root.html2canvas);
    if(rendererPromise) return rendererPromise;
    rendererPromise=new Promise((resolve,reject)=>{
      const script=document.createElement('script');
      const timer=setTimeout(()=>fail(),20000);
      function fail(){clearTimeout(timer);script.remove();rendererPromise=null;reject(new Error('Image renderer could not load. Check your connection and try again.'));}
      script.src='https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
      script.onload=()=>{clearTimeout(timer);if(root.html2canvas)resolve(root.html2canvas);else fail();};
      script.onerror=fail;
      document.head.appendChild(script);
    });
    return rendererPromise;
  }
  function canvasBlob(canvas){
    return new Promise((resolve,reject)=>canvas.toBlob(blob=>{
      if(blob && blob.size)resolve(blob);else reject(new Error('Could not create the bill image.'));
    },'image/jpeg',0.95));
  }
  function paginate(doc){
    const body=doc.body;
    const table=body.querySelector('table');
    if(!table || !table.tBodies[0])throw new Error('No bill items to render.');
    const rows=[...table.tBodies[0].rows].map(row=>row.cloneNode(true));
    if(!rows.length)throw new Error('No bill items to render.');
    const header=[...body.children].slice(0,[...body.children].indexOf(table)).map(el=>el.cloneNode(true));
    const ending=[...body.children].slice([...body.children].indexOf(table)+1).filter(el=>!el.classList.contains('no-print')).map(el=>el.cloneNode(true));
    const pages=[];
    let currentTable;
    function start(){
      body.replaceChildren(...header.map(el=>el.cloneNode(true)));
      currentTable=table.cloneNode(true);currentTable.tBodies[0].replaceChildren();body.appendChild(currentTable);
    }
    const overflows=()=>body.getBoundingClientRect().height>CONTENT_HEIGHT;
    start();
    for(const row of rows){
      currentTable.tBodies[0].appendChild(row);
      if(overflows()){
        row.remove();
        if(!currentTable.tBodies[0].rows.length)throw new Error('An item is too tall for an image page. Please use Share PDF for this bill.');
        pages.push(body.innerHTML);start();currentTable.tBodies[0].appendChild(row);
        if(overflows())throw new Error('An item is too tall for an image page. Please use Share PDF for this bill.');
      }
    }
    body.append(...ending.map(el=>el.cloneNode(true)));
    if(overflows()){
      ending.forEach(()=>body.lastElementChild.remove());
      pages.push(body.innerHTML);start();
      currentTable.remove();body.append(...ending.map(el=>el.cloneNode(true)));
      if(overflows())throw new Error('The bill summary is too tall for an image page. Please use Share PDF.');
    }
    pages.push(body.innerHTML);
    return pages;
  }
  function makeDialog(){
    const dialog=document.createElement('dialog');
    dialog.setAttribute('aria-label','Share bill images');
    dialog.style.cssText='width:min(620px,94vw);max-height:90vh;border:0;border-radius:16px;padding:20px;background:#fff;color:#1a1a2e;box-shadow:0 12px 60px #0005;margin:auto';
    dialog.innerHTML='<div style="display:flex;align-items:center;justify-content:space-between;gap:12px"><strong style="font-size:1.1em">Bill images</strong><button type="button" data-close aria-label="Close bill images" style="border:0;border-radius:8px;padding:8px 12px;cursor:pointer">Close</button></div><p data-status role="status" aria-live="polite" style="font-size:.9em;margin:14px 0">Preparing bill images…</p><button type="button" data-share style="display:none;width:100%;border:0;border-radius:10px;background:#0f766e;color:white;font-weight:700;padding:12px;cursor:pointer">Share images</button><div data-pages style="display:grid;gap:18px;margin-top:16px"></div>';
    document.body.appendChild(dialog);dialog.showModal();
    return dialog;
  }
  async function prepare(options){
    if(active) active.close();
    const previousFocus=document.activeElement;
    const dialog=makeDialog(), urls=[], files=[];
    const status=dialog.querySelector('[data-status]'), share=dialog.querySelector('[data-share]');
    let cancelled=false, frame=null;
    const state={close};active=state;
    function close(){
      if(cancelled)return;cancelled=true;
      if(frame)frame.remove();
      dialog.close();dialog.remove();
      // Android may still be reading a downloaded blob through its WebView.
      setTimeout(()=>urls.forEach(url=>URL.revokeObjectURL(url)),60000);
      if(active===state)active=null;
      if(previousFocus && previousFocus.isConnected)previousFocus.focus();
    }
    dialog.querySelector('[data-close]').onclick=close;
    dialog.addEventListener('cancel',e=>{e.preventDefault();close();});
    try{
      const render=await loadRenderer();if(cancelled)return;
      frame=document.createElement('iframe');
      frame.setAttribute('sandbox','allow-same-origin');
      frame.setAttribute('aria-hidden','true');frame.tabIndex=-1;
      frame.style.cssText=`position:fixed;left:-10000px;top:0;width:${PAGE_WIDTH}px;height:${PAGE_HEIGHT}px;border:0;pointer-events:none`;
      const loaded=new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(new Error('Bill preview timed out. Please try again.')),15000);
        frame.onload=()=>{clearTimeout(timer);resolve();};
      });
      frame.srcdoc=options.html;document.body.appendChild(frame);await loaded;if(cancelled)return;
      const doc=frame.contentDocument;
      // Images reuse the PDF template in an isolated frame with scripts disabled.
      doc.querySelectorAll('script,.no-print').forEach(el=>el.remove());
      const style=doc.createElement('style');
      style.textContent=`html{width:${PAGE_WIDTH}px}body{width:${PAGE_WIDTH}px;max-width:none;margin:0;padding:24px 30px;height:auto;min-height:0}td,th{overflow-wrap:anywhere}table{table-layout:fixed}table th:nth-child(2){width:29%}.totals-table{table-layout:auto}`;
      doc.head.appendChild(style);
      if(doc.fonts)await doc.fonts.ready;
      const pages=paginate(doc);
      for(let i=0;i<pages.length;i++){
        if(cancelled)return;
        status.textContent=`Preparing image ${i+1} of ${pages.length}…`;
        doc.body.innerHTML=pages[i];
        if(pages.length>1){
          const label=doc.createElement('div');
          label.style.cssText='margin-top:12px;font-size:10px;color:#888;text-align:right';
          label.textContent=`${options.title||'Invoice'} · Page ${i+1} of ${pages.length}`;doc.body.appendChild(label);
        }
        const canvas=await render(doc.body,{scale:2,backgroundColor:'#fff',windowWidth:PAGE_WIDTH,windowHeight:PAGE_HEIGHT,height:Math.ceil(doc.body.getBoundingClientRect().height),logging:false});
        const blob=await canvasBlob(canvas);canvas.width=canvas.height=0;if(cancelled)return;
        const name=safeName(options.filename)+(pages.length>1?`-${i+1}`:'')+'.jpg';
        const file=new File([blob],name,{type:'image/jpeg'});files.push(file);
        const url=URL.createObjectURL(blob);urls.push(url);
        const card=document.createElement('div');
        const img=document.createElement('img');img.src=url;img.alt=`Bill image ${i+1} of ${pages.length}`;
        img.style.cssText='width:100%;height:auto;border:1px solid #ddd;border-radius:8px';
        const save=document.createElement('a');save.href=url;save.download=name;save.textContent=`Save image${pages.length>1?' '+(i+1):''}`;
        save.style.cssText='display:block;text-align:center;padding:10px;color:#0f766e;font-weight:700';
        card.append(img,save);
        if(canShare([file])){
          const one=document.createElement('button');one.type='button';one.textContent=`Share image${pages.length>1?' '+(i+1):''}`;
          one.style.cssText='width:100%;padding:10px;border:0;border-radius:8px;background:#e6f5f0;color:#0f766e;font-weight:700;cursor:pointer';
          one.onclick=async()=>{
            one.disabled=true;
            try{await shareFiles([file],options.title);}
            catch(err){if(err && err.name!=='AbortError')status.textContent=nativeBridge()?err.message:'Sharing is unavailable. Save this image and attach it in WhatsApp.';}
            finally{one.disabled=false;}
          };
          card.appendChild(one);
        }
        dialog.querySelector('[data-pages]').appendChild(card);
      }
      frame.remove();frame=null;
      status.textContent=nativeBridge()&&!root.__BILLMATE_IMAGE_SHARE__?'Update BillMate to enable image sharing. Tap Share images to check for the update.':canShare(files)?`${files.length===1?'Image ready':'Images ready'}. Tap Share images and choose your customer.`:'Save the images below, then attach them in WhatsApp. You can also open BillMate in Chrome to use the share menu.';
      if(canShare(files)){
        share.style.display='block';
        share.onclick=async()=>{
          if(share.disabled)return;share.disabled=true;
          try{await shareFiles(files,options.title);}
          catch(err){if(err && err.name!=='AbortError')status.textContent=nativeBridge()?err.message:'Sharing is unavailable. Save the images below and attach them in WhatsApp.';}
          finally{share.disabled=false;}
        };
      }
      return files;
    }catch(err){
      if(frame){frame.remove();frame=null;}
      if(!cancelled)status.textContent=err.message||'Could not prepare bill images. Please try again.';
      return [];
    }
  }
  root.BillMateInvoiceImage={prepare};
  if(typeof module!=='undefined' && module.exports)module.exports={safeName,canShare,paginate,canvasBlob,prepare,shareFiles};
})(typeof window!=='undefined'?window:globalThis);
