/* Plain-text demand lists and supplier-style order messages. */
(function(root){
  'use strict';
  function parseOrderMessage(text){
    const rows=[];
    let item={code:'',qty:'',discount_pct:null,bonus:''};
    for(const raw of String(text).split(/\r?\n/)){
      const field=raw.trim().match(/^\*?(Code|QTY|Disc|Bonus|ITM)\*?\s*:\s*(.*)$/i);
      if(!field)continue; // Customer, List No, separators and totals are not items.
      const [,label,value]=field;
      switch(label.toLowerCase()){
        case 'code': item.code=value.trim();break;
        case 'qty': item.qty=value.trim();break;
        case 'disc': {
          const number=value.match(/^-?\d+(?:\.\d+)?/);
          item.discount_pct=number?Number(number[0]):null;
          break;
        }
        case 'bonus': item.bonus=value.trim();break;
        case 'itm': {
          const name=value.trim();
          if(!name||!/[a-z]/i.test(name))throw Error('An ITM field is missing its medicine name.');
          if(item.qty&&!/^\d+(?:\.\d+)?$/.test(item.qty))throw Error(`Invalid quantity for ${name}.`);
          rows.push({name,qty:item.qty,code:item.code,discount_pct:item.discount_pct,
            bonus:item.bonus,required:false,box:'',pcs:''});
          if(rows.length>2000)throw Error('Please split this demand into lists of no more than 2,000 items.');
          item={code:'',qty:'',discount_pct:null,bonus:''};
          break;
        }
      }
    }
    if(!rows.length)throw Error('No ITM entries found in the pasted order.');
    return rows;
  }
  function parse(text){
    if(/^\s*\*?ITM\*?\s*:/im.test(String(text||'')))return parseOrderMessage(text);
    const rows=[];
    for(const raw of String(text||'').split(/\r?\n/)){
      let line=raw.trim().replace(/^\s*(?:[-•*]\s+|\d+[.)]\s+)/,'').trim();
      if(!line)continue;
      if(!/[a-z]/i.test(line))throw Error(`Invalid demand item: ${line.slice(0,60)}`);
      const required=/\s*lazmi\s*$/i.test(line);
      if(required)line=line.replace(/\s*lazmi\s*$/i,'').trim();
      // Multiple dots (or an ellipsis) separate quantity; a single decimal dot does not.
      let quantity=line.match(/\s*\((\d+)\)\s*$/)
        ||line.match(/[\s.\-…]+(\d+)\s*(?:pcs?|pieces?|x)\s*$/i)
        ||line.match(/\s*(?:\.{2,}|…+|-{2,})\s*(\d+)\s*$/);
      if(quantity)line=line.slice(0,quantity.index).trim();
      else {
        // A bare leading count belongs to quantity, not medicine strength.
        // Keep strength-first names such as "20 mg Medicine" intact.
        const leading=line.match(/^(\d+)\s+(?=[a-z])/i);
        if(leading&&!/^(?:mg|mcg|g|ml|iu|%)\b/i.test(line.slice(leading[0].length))){
          quantity=leading;
          line=line.slice(leading[0].length).trim();
        }else{
          // Only infer a bare trailing count after a form and an earlier strength.
          // "Getryl 1" and "Dromax cap 500" remain names, not quantities.
          const trailing=line.match(/\s+(\d+)\s*$/);
          const name=trailing?line.slice(0,trailing.index).trim():'';
          if(trailing&&/\d/.test(name)&&/\b(?:caps?|capsules?|tabs?|tablets?|syp|syrup|susp|suspension|inj|injection|drops?|cream|sachets?|inhaler)\.?$/i.test(name)){
            quantity=trailing;
            line=name;
          }
        }
      }
      if(quantity)line=line.replace(/[.\-…]+\s*$/,'').trim();
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
