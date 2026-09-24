/* Plain-text demand lists: one item per line, optional (quantity) and lazmi. */
(function(root){
  'use strict';
  function parse(text){
    const rows=[];
    for(const raw of String(text||'').split(/\r?\n/)){
      let line=raw.trim().replace(/^\s*(?:[-•*]\s+|\d+[.)]\s+)/,'').trim();
      if(!line)continue;
      if(!/[a-z]/i.test(line))throw Error(`Invalid demand item: ${line.slice(0,60)}`);
      const required=/\s*lazmi\s*$/i.test(line);
      if(required)line=line.replace(/\s*lazmi\s*$/i,'').trim();
      const quantity=line.match(/\s*\((\d+)\)\s*$/);
      if(quantity)line=line.slice(0,quantity.index).trim();
      if(!line||!/[a-z]/i.test(line))throw Error('A demand item name is missing.');
      rows.push({name:line,qty:quantity?quantity[1]:'',required,code:'',box:'',pcs:''});
      if(rows.length>2000)throw Error('Please split this demand into files of no more than 2,000 items.');
    }
    if(!rows.length)throw Error('Enter at least one demand item, one per line.');
    return rows;
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={parse};
  else root.DemandTextParser={parse};
})(typeof window!=='undefined'?window:globalThis);
