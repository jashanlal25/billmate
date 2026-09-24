// BillMate shared-import store — a single pending file received via
// Android's Web Share Target (e.g. WhatsApp → Share → BillMate).
// DB: billmate-share, object store: pending_import, one record: 'pending'.
(function(global){
  'use strict';

  const DB_NAME = 'billmate-share';
  const STORE = 'pending_import';
  const DEMAND_STORE = 'saved_demand';
  const RECORD_ID = 'pending';
  const DIRECT_INVENTORY_KEY = 'billmate-share-direct-inventory';

  function directInventoryEnabled(){
    try{ return localStorage.getItem(DIRECT_INVENTORY_KEY) === '1'; }
    catch(e){ return false; }
  }

  function setDirectInventory(enabled){
    try{
      localStorage.setItem(DIRECT_INVENTORY_KEY, enabled ? '1' : '0');
      return true;
    }catch(e){ return false; }
  }

  function _open(){
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 2);
      req.onupgradeneeded = () => {
        const db = req.result;
        if(!db.objectStoreNames.contains(STORE)){
          db.createObjectStore(STORE, {keyPath: 'id'});
        }
        if(!db.objectStoreNames.contains(DEMAND_STORE)){
          db.createObjectStore(DEMAND_STORE, {keyPath: 'id'});
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function _tx(db, mode){
    return db.transaction(STORE, mode).objectStore(STORE);
  }

  async function saveDemand(file, owner){
    const db = await _open();
    try{
      await new Promise((resolve, reject) => {
        const req = db.transaction(DEMAND_STORE, 'readwrite').objectStore(DEMAND_STORE)
          .put({id: 'current', owner, blob: file, filename: file.name, type: file.type, created: Date.now()});
        req.onsuccess = resolve;
        req.onerror = () => reject(req.error);
      });
    }finally{db.close();}
  }

  async function getDemand(owner){
    const db = await _open();
    try{
      const rec = await new Promise((resolve, reject) => {
        const req = db.transaction(DEMAND_STORE, 'readonly').objectStore(DEMAND_STORE).get('current');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      if(!rec || rec.owner !== owner || !rec.blob)return null;
      return new File([rec.blob], rec.filename, {type: rec.type, lastModified: rec.created});
    }finally{db.close();}
  }

  async function clearDemand(){
    const db = await _open();
    try{
      await new Promise((resolve, reject) => {
        const req = db.transaction(DEMAND_STORE, 'readwrite').objectStore(DEMAND_STORE).delete('current');
        req.onsuccess = resolve;
        req.onerror = () => reject(req.error);
      });
    }finally{db.close();}
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
    directInventoryEnabled,
    setDirectInventory,
    saveDemand,
    getDemand,
    clearDemand,
  };
})(window);
