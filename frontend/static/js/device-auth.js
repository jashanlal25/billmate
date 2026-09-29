/* Native biometric vault. No passwords or login tokens go into web storage. */
(function () {
  const pending = new Map();
  let sequence = 0;
  const bridge = window.BillMateNativeAuth;
  function call(action, data = {}) {
    if (!bridge) return Promise.reject(new Error('Use password login on this device.'));
    return new Promise((resolve, reject) => {
      const id = String(++sequence);
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Fingerprint request timed out. Please try again.')); }, 120000);
      pending.set(id, {resolve, reject, timer});
      bridge.postMessage(JSON.stringify({id, action, ...data}));
    });
  }
  if (bridge) bridge.onmessage = event => {
    let data;
    try { data = JSON.parse(event.data); } catch (_) { return; }
    const request = pending.get(data.id);
    if (!request) return;
    clearTimeout(request.timer); pending.delete(data.id);
    if (data.error) request.reject(new Error(data.error)); else request.resolve(data);
  };
  let context = {kind: 'login', username: ''};
  let rememberedUsername = '';
  window.BillMateDeviceAuth = {
    enrollRequested() { return !!document.getElementById('enableFingerprint')?.checked && !!bridge; },
    async save(result) {
      // AJAX login does not always notify Android's Autofill service itself.
      if (bridge) { try { await call('autofill_commit', context); } catch (_) {} }
      if (result.fingerprint_error) { alert(result.fingerprint_error); return; }
      if (!result.device_token || !bridge) return;
      try {
        await call('enroll', {kind: context.kind, username: result.username, token: result.device_token});
      } catch (error) { alert('Login succeeded. Fingerprint was not enabled: ' + error.message); }
    },
    async init(kind, username = '') {
      context = {kind, username};
      if (!bridge) return;
      try {
        const state = await call('status', context);
        document.getElementById('fingerprintSetup').hidden = !state.available;
        document.getElementById('fingerprintUnlock').hidden = !state.available || !state.saved;
        document.getElementById('fingerprintForget').hidden = !state.saved;
        rememberedUsername = state.username || '';
        const input = document.getElementById('l_user');
        if (input && !input.value && state.username) input.value = state.username;
      } catch (_) { /* Password entry remains available on older APKs. */ }
    },
    async unlock() {
      const button = document.getElementById('fingerprintUnlock');
      button.disabled = true;
      const errorBox = document.getElementById('fingerprintError');
      errorBox.textContent = '';
      try {
        const input = document.getElementById('l_user');
        if (context.kind === 'login' && input?.value.trim() && input.value.trim() !== rememberedUsername) {
          throw new Error('Fingerprint is linked to ' + rememberedUsername + '. Use a password for another account.');
        }
        const unlocked = await call('unlock', context);
        const response = await fetch('/auth/device-login', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({kind: context.kind, token: unlocked.token})
        });
        const result = await response.json();
        if (!response.ok) {
          if (result.forget) { await call('forget', context); await this.init(context.kind, context.username); }
          throw new Error(result.error || 'Use your password to log in.');
        }
        const next = new URLSearchParams(location.search).get('next');
        let target = result.redirect || '/billing';
        if (context.kind === 'login' && next) {
          const url = new URL(next, location.origin);
          if (url.origin === location.origin && next.startsWith('/')) target = url.pathname + url.search + url.hash;
        }
        location.assign(target);
      } catch (error) { errorBox.textContent = error.message; }
      finally { button.disabled = false; }
    },
    async forget() {
      if (!confirm('Remove fingerprint access for this account on this phone?')) return;
      await call('forget', context); await this.init(context.kind, context.username);
    }
  };
})();
