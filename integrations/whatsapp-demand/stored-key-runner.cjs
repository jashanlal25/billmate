// Keeps server-side Demand Search processing active without copying the agent key.
'use strict';
const endpoint=process.env.BILLMATE_POLL_URL;
const token=process.env.BILLMATE_POLL_TOKEN;
if(!endpoint||!token)throw Error('Set BILLMATE_POLL_URL and BILLMATE_POLL_TOKEN from Admin → WhatsApp Agent.');
const url=new URL(endpoint);
if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||!/^\/api\/whatsapp-agent\/runner\/\d+$/.test(url.pathname))throw Error('Invalid BillMate runner URL.');
(async()=>{
  console.log('BillMate Demand runner started.');
  while(true){
    let delay=6000;
    try{
      const response=await fetch(url,{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(110000)});
      if(response.status===401||response.status===403){console.error('Runner access revoked. Generate a new configuration in BillMate.');process.exitCode=1;break;}
      if(!response.ok&&response.status!==409&&response.status!==429){console.error('Demand processing unavailable; retrying.');delay=15000;}
    }catch(error){console.error('BillMate connection unavailable; retrying.');delay=15000;}
    await new Promise(resolve=>setTimeout(resolve,delay));
  }
})();
