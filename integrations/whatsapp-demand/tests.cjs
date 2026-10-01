const {test}=require('node:test');
const assert=require('node:assert/strict');
const {Pilot,report,messages,boundedBytes}=require('./worker.cjs');
const config={billmate:'https://billmate-med.vercel.app',token:'test-secret',username:'demo',password:'demo',owner:'user:1'};
test('same matcher preserves vendors and distinguishes review and missing items',()=>{
  const items=[{name:'PANADOL 500MG TAB',vendor:'A',tp:100,discount_pct:5},{name:'PANADOL 500MG TABLET',vendor:'B',tp:120,discount_pct:10},{name:'PANADOL 250MG TAB',vendor:'C'}];
  const before=JSON.stringify(items);
  const {text,results}=report([{name:'PANADOL 500MG TAB',qty:'2'},{name:'PANDOL 500MG TAB'},{name:'AMOXIL CAP'}],items);
  assert.equal(results[0].offers.length,2);
  assert.equal(results[1].status,'review');assert.equal(results[2].status,'missing');
  assert.match(text,/Qty: 2/);assert.match(text,/Vendor: B/);assert.match(text,/REVIEW/);
  assert.equal(JSON.stringify(items),before);
});
test('text demand reads only inventory and sends results; unauthorized user is ignored',async()=>{
  const calls=[];
  const p=new Pilot(config,async(url,options)=>{
    calls.push({url,options});
    if(url.endsWith('/api/items'))return new Response(JSON.stringify([{name:'PANADOL TAB',vendor:'A',tp:100,discount_pct:10}]),{headers:{'Content-Type':'application/json'}});
    if(url.endsWith('/messages'))return new Response('{}');
    throw Error('Unexpected request: '+url);
  });
  p.cookie='session=test';
  await p.handle({from:'user:2',type:'text',text:{body:'PANADOL TAB (2)'}});
  assert.equal(calls.length,0);
  await p.handle({from:'user:1',type:'text',text:{body:'PANADOL TAB (2)'}});
  assert.equal(calls.length,2);
  assert.equal(calls[0].url,'https://billmate-med.vercel.app/api/items');
  assert.match(JSON.parse(calls[1].options.body).text.body,/MATCH/);
  assert.equal(calls[1].options.headers.Authorization,'Bearer test-secret');
  assert.equal(calls[0].options.headers.Authorization,undefined);
});
test('attachment URL cannot send agent token to another host',async()=>{
  const calls=[];
  const p=new Pilot(config,async(url)=>{calls.push(url);return new Response(JSON.stringify({url:'https://example.com/private'}));});
  await assert.rejects(p.handle({from:'user:1',type:'document',document:{id:'media1',filename:'demand.txt'}}),/Unexpected attachment/);
  assert.equal(calls.length,1);
});
test('oversized streaming files are stopped without trusting Content-Length',async()=>{
  const r=new Response(new Uint8Array(20));
  await assert.rejects(boundedBytes(r,10),/too large/);
});
test('official updates envelope supports messages mixed with receipts',()=>{
  assert.deepEqual(messages({entry:[{changes:[{value:{messages:[{id:'a'}],statuses:[{id:'b'}]}}]}]}),[{id:'a'}]);
});
test('HTML parser reads demand rows without executing supplied scripts',()=>{
  const {JSDOM}=require('jsdom');const window=new JSDOM('').window;
  try{
    const rows=require('./html-parser.cjs')('<script>throw Error("executed")</script><table><tr><th>Item Name</th><th>Box</th><th>PCS</th></tr><tr><td>PANADOL TAB</td><td>2</td><td>10</td></tr></table>',window.DOMParser);
    assert.equal(rows.length,1);assert.equal(rows[0].box,'2');assert.equal(rows[0].pcs,'10');
  }finally{window.close();}
});
