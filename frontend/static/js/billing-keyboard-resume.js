/* Resume an interrupted item search after switching to WhatsApp and back.
   Keep this separate from cart navigation: never select all or rebuild a row. */
(function (root) {
  'use strict';
  const doc = root.document;
  const viewport = root.visualViewport;
  let field = null, caret = null, pending = null;
  let away = false, dismissed = false, restoreTimer = null, dismissTimer = null;
  let fullHeight = viewport ? viewport.height : root.innerHeight;
  let viewportWidth = viewport ? viewport.width : root.innerWidth;
  let keyboardOpen = false;

  function eligible(node) {
    return node && node.id === 'itemSearch' && node.isConnected &&
      !node.disabled && !node.readOnly && node.getClientRects().length > 0;
  }
  function remember() {
    if (doc.activeElement === field && eligible(field)) {
      caret = [field.selectionStart, field.selectionEnd, field.selectionDirection];
    }
  }
  function cancelTimers() {
    root.clearTimeout(restoreTimer);
    root.clearTimeout(dismissTimer);
  }
  function suspend() {
    if (away) return;
    away = true;
    cancelTimers();
    remember();
    pending = eligible(field) && !dismissed &&
      (doc.activeElement === field || doc.activeElement === doc.body)
      ? {field: field, value: field.value, caret: caret} : null;
  }
  function resume() {
    if (doc.hidden || !doc.hasFocus() || !away) return;
    root.clearTimeout(restoreTimer);
    // Wait for the app-switch animation and viewport to settle first.
    restoreTimer = root.setTimeout(function () {
      if (doc.hidden || !doc.hasFocus()) return;
      away = false;
      const state = pending;
      pending = null;
      if (!state || !eligible(state.field) || state.field.value !== state.value) return;
      const active = doc.activeElement;
      if (active && active !== state.field && active !== doc.body && active !== doc.documentElement) return;
      if (doc.querySelector('.overlay.open, .sum-overlay.open, dialog[open], [aria-modal="true"]')) return;
      // Android can leave a field focused with its keyboard closed. Reacquire
      // focus instead of relying on focus() on an already-focused element.
      if (doc.activeElement === state.field) state.field.blur();
      state.field.focus({preventScroll: true});
      if (doc.activeElement !== state.field) return;
      if (state.caret && state.caret[0] !== null) {
        state.field.setSelectionRange(state.caret[0], state.caret[1], state.caret[2]);
      }
      state.field.scrollIntoView({block: 'nearest', inline: 'nearest'});
    }, 80);
  }
  doc.addEventListener('focusin', function (event) {
    if (event.target !== field) dismissed = false;
    field = eligible(event.target) ? event.target : null;
    caret = null;
    if (!field) pending = null;
    remember();
  });
  ['input', 'keyup', 'select', 'selectionchange'].forEach(function (name) {
    doc.addEventListener(name, remember);
  });
  doc.addEventListener('pointerdown', function (event) {
    pending = null;
    cancelTimers();
    if (!doc.hidden && doc.hasFocus()) away = false;
    if (event.target.id === 'itemSearch') dismissed = false;
  }, true);
  doc.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { pending = null; dismissed = true; }
  });
  doc.addEventListener('visibilitychange', function () {
    if (doc.hidden) suspend(); else resume();
  });
  root.addEventListener('blur', suspend);
  root.addEventListener('focus', resume);
  root.addEventListener('pagehide', suspend);
  root.addEventListener('pageshow', resume);
  if (viewport) viewport.addEventListener('resize', function () {
    // Ignore pinch zoom and reset the baseline when rotating the phone.
    if (Math.abs(viewport.scale - 1) > 0.05) return;
    if (Math.abs(viewport.width - viewportWidth) > 80) {
      viewportWidth = viewport.width;
      fullHeight = viewport.height;
      keyboardOpen = false;
      return;
    }
    fullHeight = Math.max(fullHeight, viewport.height);
    const open = fullHeight - viewport.height > 150;
    if (open) {
      keyboardOpen = true;
      dismissed = false;
      root.clearTimeout(dismissTimer);
      if (!away && eligible(field)) field.scrollIntoView({block: 'nearest', inline: 'nearest'});
    } else if (keyboardOpen) {
      keyboardOpen = false;
      // App switching can close the IME just before visibilitychange fires.
      // Only a dismissal while staying in Billing disables auto-resume.
      if (!away && !doc.hidden && doc.hasFocus()) dismissTimer = root.setTimeout(function () {
        if (!away && !doc.hidden && doc.hasFocus() && !keyboardOpen) dismissed = true;
      }, 180);
    }
  });
})(window);
