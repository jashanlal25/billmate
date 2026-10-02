/* Unified BillMate account/logout dialog for standalone pages. */
(function(){
  function openAccountDialog(){
    let overlay=document.getElementById('bmAccountOverlay');
    if(!overlay){
      overlay=document.createElement('div');
      overlay.id='bmAccountOverlay';
      overlay.setAttribute('role','dialog');
      overlay.setAttribute('aria-modal','true');
      overlay.innerHTML='<div id="bmAccountCard"><div id="bmAccountTitle">Logout</div><div id="bmAccountMessage">Are you sure you want to log out?</div><div id="bmAccountActions"><button type="button" class="bm-account-btn bm-account-cancel">Cancel</button><button type="button" class="bm-account-btn bm-account-logout">Logout</button></div></div>';
      document.body.appendChild(overlay);
      const close=()=>overlay.classList.remove('open');
      overlay.querySelector('.bm-account-cancel').addEventListener('click',close);
      overlay.querySelector('.bm-account-logout').addEventListener('click',()=>{window.location.href='/auth/logout';});
      overlay.addEventListener('click',e=>{if(e.target===overlay)close();});
      document.addEventListener('keydown',e=>{if(e.key==='Escape'&&overlay.classList.contains('open')){e.preventDefault();close();}});
    }
    document.querySelectorAll('.user-menu.open').forEach(m=>m.classList.remove('open'));
    overlay.classList.add('open');
    setTimeout(()=>overlay.querySelector('.bm-account-cancel').focus(),0);
  }
  document.addEventListener('click',e=>{
    const trigger=e.target.closest('.user-menu .user-name');
    if(!trigger)return;
    e.preventDefault();
    e.stopPropagation();
    openAccountDialog();
  },true);
  window.openAccountDialog=openAccountDialog;
})();