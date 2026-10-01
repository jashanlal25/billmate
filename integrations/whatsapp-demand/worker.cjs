'use strict';
const fs=require('node:fs');
const path=require('node:path');
const matcher=require('../../frontend/static/js/demand-matcher.js');
const parser=require('../../frontend/static/js/demand-text-parser.js');
const parseHtml=require('./html-parser.cjs');
const API='https://api.whatsapp.com/agent/v1';
const MAX=8*1024*1024;
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function messages(data){
  return (data.entry||[]).flatMap(e=>(e.changes||[]).flatMap(c=>c.value?.messages||[]));
}
function report(rows,items,ignore=false){
  const inventory=matcher.prepare(items,ignore);
  const results=rows.map(d=>matcher.match(d,inventory,ignore));
  const lines=[`BillMate Demand Search: ${rows.length} items; ${items.length} inventory entries.`,
    `Matched: ${results.filter(r=>r.status==='match').length}; Review: ${results.filter(r=>r.status==='review').length}; Missing: ${results.filter(r=>r.status==='missing').length}.`,
    'Review offers need verification. No stock or bills changed.',''];
  results.forEach((r,i)=>{
    const d=r.demand;
    lines.push(`${i+1}. ${d.name} | Qty: ${[d.qty,d.box&&d.box+' box',d.pcs&&d.pcs+' pcs'].filter(Boolean).join(' / ')||'unspecified'}`);
    if(!r.offers.length)lines.push('MISSING');
    for(const o of r.offers){
      lines.push(`${o.status==='match'?'MATCH':'REVIEW'} | ${o.item.name} | TP: ${o.item.tp??'—'} | Discount: ${o.item.discount_pct??'—'}% | Vendor: ${o.item.vendor||'unspecified'}`);
      if(o.status==='review')lines.push(`Check: ${o.reason}`);
    }
    lines.push('');
  });
  return {text:lines.join('\n'),results};
}
async function boundedBytes(response,max=MAX){
  if(Number(response.headers.get('content-length'))>max)throw Error('File is too large (maximum 8 MB).');
  const chunks=[];let size=0;
  for await(const chunk of response.body){
    size+=chunk.length;
    if(size>max)throw Error('File is too large (maximum 8 MB).');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
class Pilot {
  constructor(config,fetcher=fetch){
    this.config=config;this.fetch=fetcher;this.cookie='';this.lastSend=0;
    const url=new URL(config.billmate);
    if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('BILLMATE_URL must be an HTTPS origin.');
    this.billmate=url.origin;
  }
  async wa(endpoint,options={}){
    const response=await this.fetch(API+endpoint,{...options,redirect:'error',
      headers:{Authorization:`Bearer ${this.config.token}`,...options.headers},signal:AbortSignal.timeout(35000)});
    if(!response.ok)throw Error(`WhatsApp request failed (${response.status}).`);
    return response.status===204?{}:response.json();
  }
  async bm(endpoint,options={}){
    if(!this.cookie)await this.login();
    let response=await this.fetch(this.billmate+endpoint,{...options,redirect:'manual',headers:{Accept:'application/json',Cookie:this.cookie,...options.headers},signal:AbortSignal.timeout(60000)});
    if(response.status===401||response.status===302){
      await this.login();
      response=await this.fetch(this.billmate+endpoint,{...options,redirect:'manual',headers:{Accept:'application/json',Cookie:this.cookie,...options.headers},signal:AbortSignal.timeout(60000)});
    }
    if(!response.ok)throw Error(`BillMate could not process the request (${response.status}).`);
    const cookies=response.headers.getSetCookie?.()||[];
    const session=cookies.find(c=>c.startsWith('session='));
    if(session)this.cookie=session.split(';')[0];
    return response.json();
  }
  async login(){
    const response=await this.fetch(this.billmate+'/auth/login',{method:'POST',redirect:'error',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({username:this.config.username,password:this.config.password}),signal:AbortSignal.timeout(30000)});
    const data=await response.json();
    if(!response.ok||!data.success||data.redirect)throw Error('BillMate sign-in failed. Use a regular registered account.');
    const cookie=response.headers.getSetCookie().find(c=>c.startsWith('session='));
    if(!cookie)throw Error('BillMate did not provide a session.');
    this.cookie=cookie.split(';')[0];
  }
  async send(to,text){
    await pause(Math.max(0,5200-(Date.now()-this.lastSend)));this.lastSend=Date.now();
    return this.wa('/messages',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({messaging_product:'whatsapp',to,type:'text',text:{body:text.slice(0,4096)}})});
  }
  async handle(message){
    const to=message.from;
    if(!/^user:/.test(to)||this.config.owner&&to!==this.config.owner)return;
    let rows;
    if(message.type==='text'){
      const text=message.text?.body||'';
      if(/^(help|start|hi|hello|\/help)$/i.test(text.trim())){
        return this.send(to,'BillMate Demand pilot: send a TXT, PDF or HTM/HTML demand file, or paste an item list with quantities. I search supplier lists already saved in your BillMate account. This pilot does not import supplier lists or change stock.');
      }
      rows=parser.parse(text);
    }else if(message.type==='document'){
      const doc=message.document;
      const name=path.basename(doc.filename||'');
      if(!/\.(txt|pdf|html?)$/i.test(name))throw Error('Send a TXT, PDF or HTM/HTML demand file.');
      const media=await this.wa('/media/'+encodeURIComponent(doc.id));
      const url=new URL(media.url);
      if(url.protocol!=='https:'||url.hostname!=='lookaside.fbsbx.com'||url.username||url.password)throw Error('Unexpected attachment download host.');
      const response=await this.fetch(url,{redirect:'error',headers:{Authorization:`Bearer ${this.config.token}`},signal:AbortSignal.timeout(60000)});
      if(!response.ok)throw Error('Attachment could not be downloaded; please resend it.');
      const bytes=await boundedBytes(response,/\.pdf$/i.test(name)?MAX:4*1024*1024);
      if(/\.pdf$/i.test(name)){
        const form=new FormData();form.append('file',new Blob([bytes],{type:'application/pdf'}),name);
        const data=await this.bm('/api/demand/pdf-text',{method:'POST',body:form});
        rows=data.rows?.length?data.rows:parser.parse(data.text);
      }else if(/\.html?$/i.test(name)){
        const {JSDOM}=require('jsdom');
        const window=new JSDOM('').window;
        try{rows=parseHtml(bytes.toString('utf8'),window.DOMParser);}finally{window.close();}
      }else rows=parser.parse(bytes.toString('utf8'));
    }else return this.send(to,'For this pilot, send a demand document or paste the demand as text.');
    if(!rows.length||rows.length>2000)throw Error('Send between 1 and 2,000 demand items.');
    const items=await this.bm('/api/items');
    if(!Array.isArray(items))throw Error('BillMate inventory could not be read.');
    const result=report(rows,items,this.config.ignore);
    if(result.text.length<=4096)return this.send(to,result.text);
    const form=new FormData();form.append('messaging_product','whatsapp');form.append('type','text/plain');
    form.append('file',new Blob([result.text],{type:'text/plain'}),'BillMate-demand-results.txt');
    const media=await this.wa('/media',{method:'POST',body:form});
    await this.send(to,result.text.split('\n').slice(0,3).join('\n')+'\nFull results attached.');
    await pause(5200);this.lastSend=Date.now();
    return this.wa('/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messaging_product:'whatsapp',to,type:'document',document:{id:media.id,filename:'BillMate-demand-results.txt'}})});
  }
}
async function main(){
  const config={token:process.env.WHATSAPP_AGENT_TOKEN,billmate:process.env.BILLMATE_URL||'https://billmate-med.vercel.app',username:process.env.BILLMATE_USERNAME,password:process.env.BILLMATE_PASSWORD,owner:process.env.WHATSAPP_OWNER_ID,ignore:process.env.IGNORE_SHELF_CODES==='true'};
  if(!config.token||!config.username||!config.password)throw Error('Set the WhatsApp token and BillMate credentials in the private .env file.');
  const pilot=new Pilot(config);
  const stateFile=path.join(__dirname,'state.json');
  let state={offset:0,handled:[]};
  if(fs.existsSync(stateFile))state=JSON.parse(fs.readFileSync(stateFile,'utf8'));
  const save=()=>{fs.writeFileSync(stateFile+'.tmp',JSON.stringify(state),{mode:0o600});fs.renameSync(stateFile+'.tmp',stateFile);};
  await pilot.login();
  console.log('Demand pilot listening. No inventory writes are enabled.');
  while(true){
    const started=Date.now();
    try{
      const update=await pilot.wa(`/updates?offset=${state.offset}&limit=50&timeout=25`);
      for(const message of messages(update)){
        if(state.handled.includes(message.id))continue;
        try{await pilot.handle(message);}
        catch(error){await pilot.send(message.from,error.message);}
        state.handled.push(message.id);state.handled=state.handled.slice(-5000);save();
      }
      if(Number.isSafeInteger(update.next_offset)){state.offset=update.next_offset;save();}
      await pause(Math.max(0,4200-(Date.now()-started)));
    }catch(error){console.error('Agent connection failed; retrying in 15 seconds.');await pause(15000);}
  }
}
if(require.main===module)main().catch(()=>{console.error('Pilot could not start. Check private configuration and account access.');process.exitCode=1;});
module.exports={Pilot,report,messages,boundedBytes};
