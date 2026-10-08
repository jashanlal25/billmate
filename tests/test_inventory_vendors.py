"""Vendor summaries and filtered item reads share account visibility."""
from test_billed_item_search import BilledItemSearchTest, service, db, Item


class InventoryVendorsTest(BilledItemSearchTest):
    def test_vendor_counts_and_filtered_items(self):
        for code, vendor, uid, global_item, active in [
            ('A', ' DOSANI ', 1, False, True),
            ('B', 'DOSANI', 1, False, True),
            ('C', 'JANGDA', 2, False, True),
            ('D', 'SHARED', None, True, True),
            ('E', 'HIDDEN', 1, False, False),
            ('F', None, 1, False, True),
        ]:
            db.session.add(Item(code=code, name='Medicine '+code, vendor=vendor, retail_price=12, tp=10,
                                user_id=uid, is_global=global_item, is_active=active))
        db.session.commit()
        summary = self.client.get('/api/items/count').json
        self.assertEqual({v['name']:v['count'] for v in summary['vendors']},
                         {'':1, 'DOSANI':2, 'SHARED':1})
        self.assertEqual(summary['total'], 4)
        rows = self.client.get('/api/items?vendor=DOSANI').json
        self.assertEqual({i['code'] for i in rows}, {'A','B'})
        self.assertEqual(self.client.get('/api/items?vendor=JANGDA').json, [])
        self.assertEqual(len(self.client.get('/api/items?vendor=DOSANI&vendor=SHARED').json), 3)
        self.assertEqual(len(self.client.get('/api/items?vendor=&q=Medicine').json), 1)
        self.assertEqual(len(self.client.get('/api/items?q=Medicine').json), 4)
        with self.client.session_transaction() as s:
            s['is_guest'] = True
        self.assertEqual(self.client.get('/api/items/count').json['vendors'],
                         [{'name':'SHARED','count':1}])
