/* One contact picker for Billing, Customers and Admin. The browser API is not
   usable in every Android WebView, even when navigator.contacts is exposed. */
(function () {
  'use strict';
  let supportedProperties = ['tel'];
  if (navigator.contacts && typeof navigator.contacts.getProperties === 'function') {
    navigator.contacts.getProperties().then(properties => {
      if (properties.includes('tel')) supportedProperties = properties.includes('name') ? ['tel', 'name'] : ['tel'];
    }).catch(() => {});
  }

  function cleanPhone(value) {
    return String(value || '').replace(/^tel:/i, '').replace(/[\s\-()]/g, '');
  }
  function fill(contact, fields) {
    const phone = cleanPhone(Array.isArray(contact.tel) ? contact.tel[0] : contact.tel);
    const name = Array.isArray(contact.name) ? contact.name[0] : contact.name;
    if (!phone) return false;
    const phoneInput = document.getElementById(fields.phoneId);
    if (!phoneInput) return false;
    phoneInput.value = phone;
    phoneInput.dispatchEvent(new Event('input', {bubbles: true}));
    if (fields.whatsappId) {
      const whatsappInput = document.getElementById(fields.whatsappId);
      if (whatsappInput) { whatsappInput.value = phone; whatsappInput.dispatchEvent(new Event('input', {bubbles: true})); }
    }
    if (fields.nameId && name) {
      const nameInput = document.getElementById(fields.nameId);
      if (nameInput && !nameInput.value.trim()) {
        nameInput.value = name;
        nameInput.dispatchEvent(new Event('input', {bubbles: true}));
      }
    }
    return true;
  }
  function parseVcards(text) {
    const cards = [];
    const unfolded = text.replace(/\r\n[ \t]|\n[ \t]/g, '').split(/\r?\n/);
    let card = null;
    for (const line of unfolded) {
      if (/^BEGIN:VCARD$/i.test(line)) card = {name: '', tel: ''};
      else if (/^END:VCARD$/i.test(line)) {
        if (card && card.tel) cards.push(card);
        card = null;
      } else if (card) {
        const separator = line.indexOf(':');
        if (separator < 0) continue;
        const key = line.slice(0, separator).split(';')[0].split('.').pop().toUpperCase();
        const value = line.slice(separator + 1).replace(/\\([,;\\nN])/g, (_, char) => char.toLowerCase() === 'n' ? ' ' : char);
        if (key === 'FN') card.name = value;
        if (key === 'TEL' && !card.tel) card.tel = value;
      }
    }
    return cards;
  }
  function fallback(fields, reason) {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;z-index:100000;background:#0009;display:flex;align-items:center;justify-content:center;padding:16px';
    const panel = document.createElement('div');
    panel.style.cssText = 'width:min(440px,100%);max-height:80vh;overflow:auto;background:var(--card,#fff);color:var(--text,#111);padding:20px;border-radius:16px;box-shadow:0 16px 48px #0005';
    const title = document.createElement('h3'); title.textContent = 'Choose a contact';
    const guide = document.createElement('p');
    guide.style.cssText = 'margin:12px 0;line-height:1.5;font-size:.9em';
    guide.textContent = reason === 'unsupported' ? 'Your browser cannot open phone contacts directly. Export a contact from your Contacts app as a .vcf file, then choose it here.' : 'The phone contact picker could not open in this app. You can export a contact as a .vcf file from Contacts and choose it here.';
    const file = document.createElement('input'); file.type = 'file'; file.accept = '.vcf,text/vcard,text/x-vcard';
    file.style.cssText = 'width:100%;margin:8px 0 12px';
    const search = document.createElement('input'); search.type = 'search'; search.placeholder = 'Find contact in file…';
    search.style.cssText = 'display:none;width:100%;padding:10px;margin:8px 0;border:1px solid #888;border-radius:8px';
    const list = document.createElement('div'); list.style.cssText = 'max-height:40vh;overflow:auto';
    const close = document.createElement('button'); close.type = 'button'; close.textContent = 'Cancel';
    close.style.cssText = 'padding:10px 16px;margin-top:12px;border-radius:8px;cursor:pointer';
    close.onclick = () => overlay.remove();
    overlay.onclick = event => { if (event.target === overlay) overlay.remove(); };
    let cards = [];
    function render() {
      list.replaceChildren();
      const query = search.value.toLowerCase();
      for (const card of cards.filter(c => (c.name + ' ' + c.tel).toLowerCase().includes(query)).slice(0, 100)) {
        const button = document.createElement('button'); button.type = 'button';
        button.textContent = `${card.name || 'Unnamed contact'} · ${card.tel}`;
        button.style.cssText = 'display:block;width:100%;text-align:left;padding:11px;border:0;border-bottom:1px solid #8885;background:transparent;color:inherit;cursor:pointer';
        button.onclick = () => { if (fill(card, fields)) overlay.remove(); };
        list.append(button);
      }
      if (!list.childElementCount) list.textContent = 'No contacts with phone numbers found.';
    }
    search.oninput = render;
    file.onchange = async () => {
      if (!file.files?.[0]) return;
      try { cards = parseVcards(await file.files[0].text()); search.style.display = 'block'; render(); }
      catch (_) { list.textContent = 'Could not read this contact file.'; }
    };
    panel.append(title, guide, file, search, list, close); overlay.append(panel); document.body.append(overlay);
  }
  let activeFields = null;
  window.BillMateContacts = {
    nativeFill(name, phone) {
      if (!activeFields) return;
      fill({name: name || '', tel: phone || ''}, activeFields);
      activeFields = null;
    },
    async pick(fields) {
      activeFields = fields;
      // Native BillMate APK: open the actual Android phone Contacts picker.
      // The website continues to use the browser Contact Picker when available.
      if (window.BillMateNative && typeof window.BillMateNative.pickContact === 'function') {
        window.BillMateNative.pickContact();
        return;
      }
      if (navigator.contacts && typeof navigator.contacts.select === 'function') {
        try {
          const result = await navigator.contacts.select(supportedProperties, {multiple: false});
          if (result?.length && !fill(result[0], fields)) fallback(fields, 'no-phone');
          return;
        } catch (error) {
          if (error?.name === 'AbortError') { activeFields = null; return; }
        }
      }
      activeFields = null;
      fallback(fields, 'unsupported');
    },
    init() {
      document.querySelectorAll('.contact-pick-btn').forEach(button => button.style.display = 'inline-flex');
    }
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', window.BillMateContacts.init);
  else window.BillMateContacts.init();
})();
