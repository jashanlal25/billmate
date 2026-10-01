// Uses the same HTML table rules as the Demand Search page.
module.exports = function(text, Parser) {
  function parseHtml(text){
    // Detached document: uploaded scripts and styles never enter the app.
    const doc=new Parser().parseFromString(text,'text/html');
    const rows=[];
    for(const table of doc.querySelectorAll('table')){
      let columns=null;
      for(const tr of table.querySelectorAll('tr')){
        if(tr.closest('table')!==table) continue;
        const cells=Array.from(tr.children).filter(c=>/^(TD|TH)$/.test(c.tagName));
        const values=cells.map(c=>c.textContent.replace(/\s+/g,' ').trim());
        const headers=values.map(v=>v.toLowerCase());
        const name=headers.findIndex(v=>/^(item\s*name|product\s*name|description|item|product)$/.test(v));
        if(name>=0){columns={name,code:headers.findIndex(v=>/^(?:item\s*)?code$/.test(v)),box:headers.indexOf('box'),pcs:headers.indexOf('pcs'),tp:headers.findIndex(v=>/^(?:tp|t\.?p\.?|tp\s*rate|trade\s*price|purchase\s*(?:price|rate))$/.test(v)),retail:headers.findIndex(v=>/^(?:retail(?:\s*price)?|mrp|sale\s*price)$/.test(v)),discount:headers.findIndex(v=>/^(?:disc(?:ount)?\s*%?|discount\s*rate)$/.test(v)),bonus:headers.findIndex(v=>/^(?:bonus|bonus\s*(?:%|rate))$/.test(v))};continue;}
        if(!columns||!cells.length||cells.some(c=>c.querySelector('table'))) continue;
        const item=values[columns.name];
        if(!item||!/[a-z]/i.test(item)||cells.length<=columns.name||/^(total|grand total|sub total)\b/i.test(item)) continue;
        if(cells.some(c=>c.querySelector('input,button,select'))) continue;
        const readPrice=index=>{
          const match=(index>=0?values[index]||'':'').replace(/,/g,'').match(/\d+(?:\.\d+)?/);
          const price=match?Number(match[0]):0;
          return Number.isFinite(price)&&price>0?price:null;
        };
        const discountText=columns.discount>=0?values[columns.discount]||'':'';
        const discountMatch=discountText.match(/^\s*(\d+(?:\.\d+)?)\s*%?/);
        rows.push({name:item,code:columns.code>=0?values[columns.code]||'':'',box:columns.box>=0?values[columns.box]||'':'',pcs:columns.pcs>=0?values[columns.pcs]||'':'',tp:readPrice(columns.tp),retail:readPrice(columns.retail),discount_pct:discountMatch?Number(discountMatch[1]):null,bonus:columns.bonus>=0?values[columns.bonus]||'':''});
      }
    }
    if(!rows.length) throw Error('No demand items found. Use an HTML table with an Item Name column.');
    if(rows.length>2000) throw Error('Please split this demand into files of no more than 2,000 items.');
    return rows;
  }
  return parseHtml(text);
};
