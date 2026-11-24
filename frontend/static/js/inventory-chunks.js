(function () {
  'use strict';

  const threshold = 4_400_000;
  const chunkBytes = 2_000_000;
  const maxBytes = 15 * 1024 * 1024;
  let pending;

  async function upload(file, vendor, progress) {
    if (file.size > maxBytes) throw new Error('Inventory files can be up to 15 MiB.');
    if (!pending || pending.file !== file || pending.vendor !== vendor) {
      const hash = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
      pending = {
        file,
        vendor,
        id: crypto.randomUUID(),
        digest: Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join(''),
        offset: 0,
      };
    }
    const current = pending;

    while (current.offset < file.size) {
      progress(Math.floor(current.offset / chunkBytes) + 1, Math.ceil(file.size / chunkBytes));
      const body = new FormData();
      body.append('upload_id', current.id);
      body.append('filename', file.name);
      body.append('vendor', vendor);
      body.append('size', file.size);
      body.append('digest', current.digest);
      body.append('offset', current.offset);
      body.append('chunk', file.slice(current.offset, current.offset + chunkBytes), 'chunk.bin');
      let response, result;
      try {
        response = await fetch('/api/items/import/chunk', {method: 'POST', body});
        result = await response.json();
      } catch {
        throw new Error('Upload interrupted. Tap Import to retry.');
      }
      if (!response.ok) {
        if (result.restart) pending = null;
        throw new Error(result.error || 'Upload interrupted. Tap Import to retry.');
      }
      if (typeof result.added === 'number') {
        pending = null;
        return result;
      }
      if (!Number.isInteger(result.received) || result.received <= current.offset ||
          result.received >= file.size || result.received % chunkBytes) {
        throw new Error('Upload progress could not be confirmed. Tap Import to retry.');
      }
      current.offset = result.received;
    }
  }

  window.InventoryChunks = {
    applies(file) {
      return file && file.size > threshold && /\bBillMateNative\//.test(navigator.userAgent);
    },
    upload,
  };
})();
