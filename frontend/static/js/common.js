// === Theme Toggle (3-state: light / dim / dark) ===
const themes = ['light', 'dim', 'dark'];
const themeIcons = { light: '☀️', dim: '🌤️', dark: '🌙' };
let _theme = localStorage.getItem('theme') || 'light';

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t === 'light' ? '' : t);
  const btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = themeIcons[t];
  localStorage.setItem('theme', t);
  _theme = t;
}
applyTheme(_theme);

function toggleTheme() {
  applyTheme(themes[(themes.indexOf(_theme) + 1) % themes.length]);
}

// === Toast ===
function toast(msg, err = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (err ? ' error' : '');
  setTimeout(() => t.className = 'toast', 2800);
}

// === Mobile Nav Toggle ===
function toggleNav() {
  document.getElementById('navMenu').classList.toggle('open');
}

// === HTML Escape (prevents XSS when inserting user data into innerHTML) ===
function esc(s){
  return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// === Title Case ===
function toTitleCase(str) {
  return str.replace(/(\b\w)/g, c => c.toUpperCase());
}

// === User Menu Click-Outside ===
document.addEventListener('click', e => {
  document.querySelectorAll('.user-menu.open').forEach(m => {
    if (!m.contains(e.target)) m.classList.remove('open');
  });
});

// === Shop Logo from Settings ===
(function(){
  const cached = localStorage.getItem('_shopName');
  if (cached) {
    const el = document.getElementById('shopLogo');
    if (el) el.textContent = cached;
  }
})();
fetch('/api/settings')
  .then(r => r.json())
  .then(s => {
    if (s.shop_name) {
      const el = document.getElementById('shopLogo');
      if (el) el.textContent = s.shop_name;
      localStorage.setItem('_shopName', s.shop_name);
    }
    window._shopSettings = s;
  });


// === Number Input: clear on focus, restore on blur, format 2 decimals ===
document.addEventListener('focusin', e => {
  if (e.target.type === 'number') {
    e.target.dataset._prev = e.target.value;
    e.target.value = '';
  }
});
document.addEventListener('focusout', e => {
  if (e.target.type === 'number') {
    if (e.target.value === '' || e.target.value === null) {
      e.target.value = e.target.dataset._prev || '';
    } else {
      const dec = e.target.step && e.target.step.includes('0.001') ? 3 : 2;
      e.target.value = parseFloat(e.target.value).toFixed(dec);
    }
  }
});


// === Modern site dialogs ===
function _billmateDialog(text, mode='confirm') {
  return new Promise(resolve => {
    const old=document.getElementById('billmateDialog');
    if(old) old.remove();
    const overlay=document.createElement('div');
    overlay.id='billmateDialog';
    overlay.className='bm-dialog-overlay';
    const box=document.createElement('div');
    box.className='bm-dialog';
    box.setAttribute('role', mode==='confirm' ? 'dialog' : 'alertdialog');
    box.setAttribute('aria-modal','true');
    box.innerHTML='<div class="bm-dialog-icon">'+(mode==='confirm'?'❓':'ℹ️')+'</div>'+
      '<div class="bm-dialog-title">'+(mode==='confirm'?'Please confirm':'BillMate')+'</div>'+
      '<div class="bm-dialog-text"></div>'+
      '<div class="bm-dialog-actions"></div>';
    box.querySelector('.bm-dialog-text').textContent=String(text);
    const actions=box.querySelector('.bm-dialog-actions');
    const finish=value=>{overlay.remove();resolve(value);};
    if(mode==='confirm'){
      const cancel=document.createElement('button'); cancel.className='bm-dialog-btn secondary'; cancel.textContent='Cancel';
      const ok=document.createElement('button'); ok.className='bm-dialog-btn primary'; ok.textContent='Confirm';
      cancel.onclick=()=>finish(false); ok.onclick=()=>finish(true);
      actions.append(cancel,ok);
      overlay.addEventListener('click',e=>{if(e.target===overlay)finish(false);});
      box.addEventListener('keydown',e=>{if(e.key==='Escape')finish(false);});
      setTimeout(()=>ok.focus(),0);
    }else{
      const ok=document.createElement('button'); ok.className='bm-dialog-btn primary'; ok.textContent='OK';
      ok.onclick=()=>finish(true); actions.append(ok); setTimeout(()=>ok.focus(),0);
    }
    overlay.appendChild(box); document.body.appendChild(overlay);
  });
}
function BMConfirm(text){ return _billmateDialog(text,'confirm'); }
function BMAlert(text){ return _billmateDialog(text,'alert'); }
