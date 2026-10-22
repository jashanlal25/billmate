// Installed at document start by the APK, only on the trusted BillMate origin.
(function () {
  'use strict';
  if (window.BillMateBillingKeyboard) return;
  let field = null, selection = null, saved = null;
  function eligible(node) {
    return node && node.id === 'itemSearch' && node.isConnected &&
      !node.disabled && !node.readOnly && node.getClientRects().length > 0;
  }
  function remember() {
    if (document.activeElement !== field || !eligible(field)) return;
    selection = [field.selectionStart, field.selectionEnd, field.selectionDirection];
  }
  document.addEventListener('focusin', function (event) {
    field = eligible(event.target) ? event.target : null;
    selection = null;
    remember();
  });
  ['input', 'keyup', 'select', 'selectionchange'].forEach(function (name) {
    document.addEventListener(name, remember);
  });
  // A new interaction cancels a queued restore; never steal focus from a dialog
  // or another field selected as the app returns.
  document.addEventListener('pointerdown', function () { saved = null; }, true);
  window.BillMateBillingKeyboard = {
    capture: function () {
      remember();
      const active = document.activeElement;
      saved = eligible(field) && (active === field || active === document.body)
        ? {field: field, value: field.value, selection: selection} : null;
    },
    restore: function () {
      const state = saved;
      saved = null;
      if (!state || !eligible(state.field) || state.field.value !== state.value) return false;
      const active = document.activeElement;
      if (active && active !== state.field && active !== document.body && active !== document.documentElement) return false;
      if (document.querySelector('[role="dialog"][aria-modal="true"], dialog[open]')) return false;
      state.field.focus({preventScroll: true});
      if (document.activeElement !== state.field) return false;
      if (state.selection && state.selection[0] !== null) {
        state.field.setSelectionRange(state.selection[0], state.selection[1], state.selection[2]);
      }
      state.field.scrollIntoView({block: 'nearest', inline: 'nearest'});
      return true;
    }
  };
})();
