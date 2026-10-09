/* BillMate in-app confirmation dialog. Uses the page's existing theme variables. */
(function(){
  'use strict';
  let activeResolve=null;
  let lastFocus=null;

  function getOverlay(){
    let overlay=document.getElementById('bmConfirmOverlay');
    if(overlay) return overlay;
    overlay=document.createElement('div');
    overlay.id='bmConfirmOverlay';
    overlay.setAttribute('role','dialog');
    overlay.setAttribute('aria-modal','true');
    overlay.setAttribute('aria-labelledby','bmConfirmTitle');
    overlay.setAttribute('aria-describedby','bmConfirmMessage');
    overlay.innerHTML=
      '<div id="bmConfirmCard" role="document">'+
        '<div id="bmConfirmIcon" aria-hidden="true">?</div>'+
        '<div id="bmConfirmTitle"></div>'+
        '<div id="bmConfirmMessage"></div>'+
        '<div id="bmConfirmActions">'+
          '<button type="button" class="bm-confirm-btn bm-confirm-cancel">Cancel</button>'+
          '<button type="button" class="bm-confirm-btn bm-confirm-ok">OK</button>'+
        '</div>'+
      '</div>';
    document.body.appendChild(overlay);

    const finish=function(value){
      if(!activeResolve) return;
      const resolve=activeResolve;
      activeResolve=null;
      overlay.classList.remove('open');
      if(lastFocus && typeof lastFocus.focus==='function'){
        try{lastFocus.focus();}catch(_){}
      }
      resolve(!!value);
    };
    overlay.querySelector('.bm-confirm-cancel').addEventListener('click',()=>finish(false));
    overlay.querySelector('.bm-confirm-ok').addEventListener('click',()=>finish(true));
    overlay.addEventListener('click',e=>{if(e.target===overlay)finish(false);});
    overlay.addEventListener('keydown',e=>{
      if(e.key==='Escape'){e.preventDefault();finish(false);return;}
      if(e.key==='Enter' && document.activeElement===overlay.querySelector('.bm-confirm-ok')){
        e.preventDefault();finish(true);
      }
    });
    overlay._finish=finish;
    return overlay;
  }

  window.BMConfirm=function(message,title='Please confirm',options={}){
    const overlay=getOverlay();
    if(activeResolve) overlay._finish(false);
    lastFocus=document.activeElement;
    overlay.querySelector('#bmConfirmTitle').textContent=title;
    overlay.querySelector('#bmConfirmMessage').textContent=message;
    overlay.classList.add('open');
    const ok=overlay.querySelector('.bm-confirm-ok');
    ok.textContent=options.okText||'OK';
    overlay.querySelector('.bm-confirm-cancel').textContent=options.cancelText||'Cancel';
    setTimeout(()=>ok.focus(),0);
    return new Promise(resolve=>{activeResolve=resolve;});
  };
})();
