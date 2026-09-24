/* Pure matching rules shared by the Demand Search page and regression tests. */
(function(root){
  'use strict';
  const forms = {
    tab:'tablet', tabs:'tablet', tablet:'tablet', tablets:'tablet',
    syp:'syrup', syr:'syrup', syrup:'syrup',
    cap:'capsule', caps:'capsule', capsule:'capsule', capsules:'capsule',
    susp:'suspension', suspension:'suspension', inj:'injection', injection:'injection',
    drop:'drops', drops:'drops', drp:'drops', sachet:'sachet', sachets:'sachet', satch:'sachet',
    cream:'cream', crm:'cream', oint:'ointment', ointment:'ointment', gel:'gel',
    lotion:'lotion', shampoo:'shampoo', solution:'solution', sol:'solution', spray:'spray'
  };
  function profile(name, ignoreShelf=false){
    let text=String(name||'').toLowerCase().normalize('NFKC');
    if(ignoreShelf) text=text.replace(/\s+[a-z]-\d+\s*$/i,'');
    text=text.replace(/^\s*sp\.(?=\s)/,'syp');
    text=text.replace(/(\d)\s+(mg|mcg|g|ml|iu)\b/g,'$1$2')
      .replace(/(\d),(?=\d{3}\b)/g,'$1').replace(/(\d)\s*[x×]\s*(\d)/g,'$1x$2');
    const tokens=(text.match(/[a-z0-9]+(?:[.][0-9]+)?%?/g)||[]).map(t=>forms[t]||t);
    const form=[...new Set(tokens.filter(t=>Object.values(forms).includes(t)))].sort();
    const numbers=tokens.filter(t=>/^\d/.test(t)).sort();
    const words=[...new Set(tokens.filter(t=>!form.includes(t)&&!/^\d/.test(t)))].sort();
    const specs={};
    for(const token of numbers){
      const unit=token.match(/(?:mg|mcg|ml|iu|g|%)$/);
      const group=unit?unit[0]:/^\d/.test(token)?'count':'name';
      (specs[group] ||= []).push(token);
    }
    const combinedStrength=(text.match(/\b\d+(?:\.\d+)?\s*\/\s*\d+(?:\.\d+)?/g)||[])
      .map(value=>value.replace(/\s+/g,'')).sort();
    return {form,numbers,specs,words,combinedStrength,plus:/\+/.test(text),key:[...new Set(tokens)].sort().join(' ')};
  }
  function distance(a,b){
    let prev=Array.from({length:b.length+1},(_,i)=>i);
    for(let i=1;i<=a.length;i++){
      const next=[i];
      for(let j=1;j<=b.length;j++) next[j]=Math.min(next[j-1]+1,prev[j]+1,prev[j-1]+(a[i-1]!==b[j-1]));
      prev=next;
    }
    return prev[b.length];
  }
  const same=(a,b)=>a.join('|')===b.join('|');
  function compare(d,v){
    // An explicit conflicting form or strength/pack never becomes an offer.
    if(d.form.length&&v.form.length&&!same(d.form,v.form)) return null;
    if(!same(d.combinedStrength,v.combinedStrength))return null;
    if(d.numbers.length&&v.numbers.length){
      const numberPart=t=>Number((t.match(/^\d+(?:\.\d+)?/)||[])[0]);
      const left=d.numbers.map(numberPart),right=v.numbers.map(numberPart);
      // An explicit different strength or pack size must never be suggested.
      if(!left.some(x=>right.includes(x))) return null;
      if(left.length===right.length&&!same(left.slice().sort((a,b)=>a-b),right.slice().sort((a,b)=>a-b))) return null;
      if(left.length!==right.length && !(left.every(x=>right.includes(x))||right.every(x=>left.includes(x)))) return null;
      for(const a of d.numbers)for(const b of v.numbers){
        if(numberPart(a)===numberPart(b)){
          const ua=a.replace(/^\d+(?:\.\d+)?/,'');
          const ub=b.replace(/^\d+(?:\.\d+)?/,'');
          if(ua&&ub&&ua!==ub) return null;
        }
      }
    }
    if(!d.words.length||!v.words.length) return null;
    const exactWords=same(d.words,v.words);
    if(!exactWords){
      if(d.words.length!==v.words.length) return null;
      let edits=0;
      for(let i=0;i<d.words.length;i++){
        const a=d.words[i],b=v.words[i];
        if(a===b) continue;
        if(Math.min(a.length,b.length)<5||a[0]!==b[0]) return null;
        edits+=distance(a,b);
      }
      if(edits>1) return null;
    }
    const reasons=[];
    if(!exactWords) reasons.push('Spelling differs');
    if(!d.form.length) reasons.push('Choose / verify form');
    else if(!v.form.length) reasons.push('Vendor form missing');
    if(!same(d.numbers,v.numbers)) reasons.push('Check strength / pack size and units');
    if(d.plus!==v.plus) reasons.push('Plus sign differs in item names');
    if(d.key!==v.key&&!reasons.length) reasons.push('Name details differ');
    return {status:reasons.length?'review':'match',reason:reasons.join('; ')||'Name and stated details match'};
  }
  function prepare(items,ignoreShelf){return items.map(item=>({item,profile:profile(item.name,ignoreShelf)}));}
  function match(demand,inventory,ignoreShelf){
    const p=profile(demand.name,ignoreShelf);
    const offers=[];
    for(const entry of inventory){
      const result=compare(p,entry.profile);
      if(result) offers.push({...result,item:entry.item});
    }
    return {demand,offers,status:offers.some(o=>o.status==='match')?'match':offers.length?'review':'missing'};
  }
  function price(item){
    const tp=Number(item.tp),discount=Number(item.discount_pct||0);
    return Number.isFinite(tp)&&tp>0&&Number.isFinite(discount)&&discount>=0&&discount<=100 ? tp*(1-discount/100):null;
  }
  const api={profile,compare,prepare,match,price};
  if(typeof module!=='undefined'&&module.exports) module.exports=api;
  else root.DemandMatcher=api;
})(typeof window!=='undefined'?window:globalThis);
