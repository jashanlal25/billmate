// BillMate shared-import store — a single pending file received via
// Android's Web Share Target (e.g. WhatsApp → Share → BillMate).
// DB: billmate-share, object store: pending_import, one record: 'pending'.
(function(global){
  'use strict';

  const DB_NAME = 'billmate-share';
  const STORE = 'pending_import';
  const RECORD_ID = 'pending';

  function _open(){
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if(!db.objectStoreNames.contains(STORE)){
          db.createObjectStore(STORE, {keyPath: 'id'});
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function _tx(db, mode){
    return db.transaction(STORE, mode).objectStore(STORE);
  }

  // Save a shared file as the pending import. A previous pending file that
  // was never adopted is simply replaced.
  async function savePendingSharedFile(file){
    const db = await _open();
    await new Promise((resolve, reject) => {
      const store = _tx(db, 'readwrite');
      // clear() first: only ONE pending import may exist — a newer share
      // always wins over a stale un-adopted one.
      const clr = store.clear();
      clr.onsuccess = () => {
        const req = store.put({
          id: RECORD_ID,
          filename: file.name,
          type: file.type || 'text/html',
          size: file.size,
          blob: file,
          created: Date.now(),
          source: 'web-share-target',
        });
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      };
      clr.onerror = () => reject(clr.error);
    });
    db.close();
  }

  // Read the pending shared file, reconstructing a real File object.
  // Returns null when nothing is pending.
  async function takePendingSharedFile(){
    const db = await _open();
    const rec = await new Promise((resolve, reject) => {
      const req = _tx(db, 'readonly').get(RECORD_ID);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
    db.close();
    if(!rec || !rec.blob) return null;
    const file = new File([rec.blob], rec.filename, {
      type: rec.type || 'text/html',
      lastModified: rec.created || Date.now(),
    });
    return file;
  }

  // Discard the pending file (after import, cancel, or expiry).
  async function clearPendingSharedFile(){
    try{
      const db = await _open();
      await new Promise((resolve, reject) => {
        const req = _tx(db, 'readwrite').clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
      db.close();
    }catch(e){ /* best effort */ }
  }

  // Drop records older than 24h so a forgotten share never haunts the user.
  async function pruneStale(){
    try{
      const db = await _open();
      const rec = await new Promise((resolve) => {
        const req = _tx(db, 'readonly').get(RECORD_ID);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
      db.close();
      if(rec && Date.now() - (rec.created || 0) > 24*60*60*1000){
        await clearPendingSharedFile();
      }
    }catch(e){ /* best effort */ }
  }

  global.ShareStore = {
    savePendingSharedFile,
    takePendingSharedFile,
    clearPendingSharedFile,
    pruneStale,
  };
})(window);
