const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const source = fs.readFileSync('frontend/static/js/inventory-chunks.js', 'utf8');

test('only Android files above 4.4 MB are chunked', () => {
  const navigator = { userAgent: 'Mozilla BillMateNative/1.15' };
  const window = {};
  vm.runInNewContext(source, { window, navigator });
  assert.equal(window.InventoryChunks.applies({ size: 4_399_999 }), false);
  assert.equal(window.InventoryChunks.applies({ size: 4_400_000 }), false);
  assert.equal(window.InventoryChunks.applies({ size: 4_400_001 }), true);
  navigator.userAgent = 'Mozilla Android Chrome';
  assert.equal(window.InventoryChunks.applies({ size: 5_438_164 }), false);
});

test('Android upload retries the interrupted part with the same upload ID', async () => {
  const file = new Blob([Buffer.alloc(5_438_164)]);
  file.name = 'list.htm';
  const window = {};
  const requests = [];
  async function fetch(url, { body }) {
    assert.equal(url, '/api/items/import/chunk');
    requests.push([body.get('upload_id'), Number(body.get('offset')), body.get('chunk').size]);
    if (requests.length === 2) throw new Error('connection dropped');
    const received = Number(body.get('offset')) + body.get('chunk').size;
    return { ok: true, json: async () => received === file.size ? { added: 3 } : { received } };
  }
  vm.runInNewContext(source, { window, crypto: webcrypto, FormData, fetch });
  const upload = () => window.InventoryChunks.upload(file, 'Test vendor', () => {});
  await assert.rejects(upload(), /Tap Import to retry/);
  assert.deepEqual(await upload(), { added: 3 });
  assert.deepEqual(requests.map(row => row.slice(1)), [
    [0, 2_000_000], [2_000_000, 2_000_000], [2_000_000, 2_000_000], [4_000_000, 1_438_164],
  ]);
  assert.equal(new Set(requests.map(row => row[0])).size, 1);
});
