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
    enrollRequested() { return false; },
    async save(result) {
      // Complete password login only. Enrollment is an explicit, separate action.
      if (bridge) { try { await call('autofill_commit', {...context, username: result.username || context.username}); } catch (_) {} }
    },
    async setup(kind, username) {
      const button = document.getElementById('setupButton');
      const errorBox = document.getElementById('setupMessage');
      const passwordInput = document.getElementById('setupPassword');
      if (button.disabled) return;
      button.disabled = true; errorBox.textContent = '';
      try {
        if (!bridge) throw new Error('Fingerprint setup requires the BillMate Android app.');
        const password = passwordInput.value;
        const response = await fetch('/auth/fingerprint/token', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({kind, password, enroll_fingerprint: true})
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Password verification failed.');
        if (!result.device_token) throw new Error(result.fingerprint_error || 'Fingerprint setup is unavailable.');
        passwordInput.value = '';
        // No Autofill commit, navigation or login alert competes with this prompt.
        await call('enroll', {kind, username: result.username, token: result.device_token});
        errorBox.textContent = kind === 'admin' ? 'Admin fingerprint enabled on this phone.' : 'Login fingerprint enabled on this phone.';
        await this.init(kind, username);
      } catch (error) { errorBox.textContent = error.message; }
      finally { passwordInput.value = ''; button.disabled = false; }
    },
    async init(kind, username = '') {
      context = {kind, username};
      if (!bridge) return;
      try {
        const state = await call('status', context);
        const setup = document.getElementById('fingerprintSetup');
        if (setup) setup.hidden = !state.available;
        const setupButton = document.getElementById('setupButton');
        if (setupButton) setupButton.disabled = !state.available || state.setupVersion !== 2;
        document.getElementById('fingerprintUnlock').hidden = !state.available || !state.saved;
        const forgetButton = document.getElementById('fingerprintForget');
        if (forgetButton) forgetButton.hidden = !state.saved;
        rememberedUsername = state.username || '';
        const status = document.getElementById('setupStatus');
        if (status) status.textContent = state.setupVersion !== 2 ? 'Update BillMate to v1.11 or later before enabling fingerprint.' : state.saved ? 'Fingerprint access is already enabled.' : state.available ? 'Verify your password, then scan your fingerprint.' : 'Set up a supported fingerprint in phone settings first.';
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
      if (!(await BMConfirm('Remove fingerprint access for this account on this phone?'))) return;
      await call('forget', context); await this.init(context.kind, context.username);
    }
  };
})();
