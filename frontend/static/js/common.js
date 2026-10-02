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
function toggleNav(force) {
  const menu = document.getElementById('navMenu');
  if (!menu) return;
  const shouldOpen = typeof force === 'boolean' ? force : !menu.classList.contains('open');
  menu.classList.toggle('open', shouldOpen);
}

// Close the mobile navigation after choosing a page or tapping outside it.
// Capture phase makes this run before page-specific click handlers.
document.addEventListener('click', e => {
  const menu = document.getElementById('navMenu');
  const button = document.querySelector('.nav-hamburger');
  if (!menu || !menu.classList.contains('open')) return;
  if (e.target.closest('#navMenu a, #navMenu button') ||
      (!menu.contains(e.target) && !(button && button.contains(e.target)))) {
    toggleNav(false);
  }
}, true);

// === HTML Escape (prevents XSS when inserting user data into innerHTML) ===
function esc(s){
  return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// === Title Case ===
function toTitleCase(str) {
  return str.replace(/(\b\w)/g, c => c.toUpperCase());
}

// === Unified Account / Logout Dialog ===
function openAccountDialog() {
  let overlay = document.getElementById('bmAccountOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'bmAccountOverlay';
    overlay.setAttribute('role','dialog');
    overlay.setAttribute('aria-modal','true');
    overlay.innerHTML =
      '<div id="bmAccountCard">' +
        '<div id="bmAccountTitle">Logout</div>' +
        '<div id="bmAccountMessage">Are you sure you want to log out?</div>' +
        '<div id="bmAccountActions">' +
          '<button type="button" class="bm-account-btn bm-account-cancel">Cancel</button>' +
          '<button type="button" class="bm-account-btn bm-account-logout">Logout</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(overlay);
    const close = () => {
      overlay.classList.remove('open');
      document.querySelectorAll('.user-menu.open').forEach(m => m.classList.remove('open'));
    };
    overlay.querySelector('.bm-account-cancel').addEventListener('click', close);
    overlay.querySelector('.bm-account-logout').addEventListener('click', () => {
      window.location.href = '/auth/logout';
    });
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && overlay.classList.contains('open')) { e.preventDefault(); close(); }
    });
  }
  document.querySelectorAll('.user-menu.open').forEach(m => m.classList.remove('open'));
  overlay.classList.add('open');
  const cancel = overlay.querySelector('.bm-account-cancel');
  if (cancel) setTimeout(() => cancel.focus(), 0);
}

// Account button is handled centrally so every page gets the same UI.
document.addEventListener('click', e => {
  const trigger = e.target.closest('.user-menu .user-name');
  if (!trigger) return;
  e.preventDefault();
  e.stopPropagation();
  openAccountDialog();
}, true);

document.addEventListener('click', e => {
  document.querySelectorAll('.user-menu.open').forEach(m => {
    if (!m.contains(e.target)) m.classList.remove('open');
  });
});
// === Header branding ===
(function(){
  // Keep the SSD MEDICOS reference branding intact. Shop settings are still
  // available through window._shopSettings but never replace the header markup.
  fetch('/api/settings')
    .then(r => r.json())
    .then(s => { window._shopSettings = s; })
    .catch(()=>{});
})();


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


