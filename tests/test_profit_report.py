"""Profit amounts, dated FIFO, linked purchases, filters, and access isolation."""
import sys
import unittest
from datetime import date
from pathlib import Path
from types import SimpleNamespace as Row
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from profit_report import build_profit_report

D = date.fromisoformat

def line(qty=1, amount=100, item_id=1, name='Medicine', tax=0):
    return Row(qty=qty, line_total=amount, line_net=amount, item_id=item_id,
               item_name=name, tax_pct=tax)

def purchase(id=1, when='2026-10-01', lines=None, source=None):
    lines=lines or [line()]
    return Row(id=id, purchase_date=D(when), total_cost=sum(l.line_total for l in lines),
               source_invoice_id=source, lines=lines)

def invoice(id=1, when='2026-10-02', lines=None, discount=0, customer=1, name='Customer', status='posted'):
    return Row(id=id, invoice_date=D(when), status=status, lines=lines or [line(amount=150)],
               discount_amount=discount, customer_id=customer, customer_name_snap=name)

class ProfitReportTest(unittest.TestCase):
    def report(self, p, i, start='2026-10-01', end='2026-10-31', **kwargs):
        return build_profit_report(p, i, D(start), D(end), **kwargs)

    def test_discount_tax_and_unsold_stock(self):
        r=self.report([purchase(lines=[line(qty=10,amount=800)])],
                      [invoice(lines=[line(qty=2,amount=240,tax=5)],discount=10)])
        s=r['summary']
        self.assertEqual((s['purchases'],s['sales'],s['cost'],s['profit']), (800,240,160,80))
        self.assertTrue(s['complete'])

    def test_fifo_consumes_prior_period_sales(self):
        p=[purchase(lines=[line(qty=2,amount=160)]),
           purchase(id=2,when='2026-10-03',lines=[line(qty=2,amount=200)])]
        i=[invoice(lines=[line(qty=2,amount=240)]),invoice(id=2,when='2026-10-04')]
        r=self.report(p,i,start='2026-10-04')['summary']
        self.assertEqual((r['cost'],r['profit']), (100,50))
        self.assertEqual(r['purchases'],0)

    def test_future_unlinked_cost_is_not_guessed(self):
        r=self.report([purchase(when='2026-10-10')],[invoice()])['summary']
        self.assertEqual((r['missing_qty'],r['cost'],r['profit']), (1,0,0))
        self.assertFalse(r['complete'])

    def test_late_linked_purchase_reserved_for_source_sale(self):
        p=[purchase(lines=[line(amount=70)]),purchase(id=2,when='2026-11-01',source=2,lines=[line(amount=90)])]
        r=self.report(p,[invoice(),invoice(id=2,when='2026-10-03')])['summary']
        self.assertEqual((r['cost'],r['profit'],r['purchases']), (160,140,70))
        self.assertTrue(r['complete'])

    def test_partial_cost_reports_only_matched_sales_profit(self):
        s=self.report([purchase(lines=[line(amount=80)])],
                      [invoice(lines=[line(qty=2,amount=300)])])['summary']
        self.assertEqual((s['sales'],s['matched_sales'],s['cost'],s['profit'],s['missing_qty']), (300,150,80,70,1))

    def test_grouping_and_query_do_not_change_fifo(self):
        p=[purchase(lines=[line(amount=80)]),purchase(id=2,lines=[line(amount=100)])]
        i=[invoice(name='Alpha'),invoice(id=2,customer=2,name='Beta',when='2026-10-04')]
        r=self.report(p,i,query='beta')
        self.assertEqual(r['rows'][0]['label'],'Beta')
        self.assertEqual(r['summary']['cost'],100)
        self.assertEqual(r['summary']['purchases'],180)
        for group in ('customer','item','day','month'):
            self.assertEqual(self.report(p,i,group_by=group)['summary']['profit'],120)

    def test_manual_line_matches_unique_name_but_not_ambiguous_vendor(self):
        p=[purchase(lines=[line(amount=80)])]
        i=[invoice(lines=[line(amount=150,item_id=None,name=' medicine ')])]
        self.assertTrue(self.report(p,i)['summary']['complete'])
        p.append(purchase(id=2,lines=[line(amount=100,item_id=2)]))
        self.assertFalse(self.report(p,i)['summary']['complete'])

    def test_linked_surplus_and_cancelled_source_return_to_dated_stock(self):
        p=[purchase(source=1,lines=[line(qty=2,amount=160)])]
        s=self.report(p,[invoice(),invoice(id=2,when='2026-10-03')])['summary']
        self.assertEqual((s['cost'],s['missing_qty']), (160,0))
        s=self.report(p,[invoice(status='cancelled'),invoice(id=2)])['summary']
        self.assertEqual((s['cost'],s['missing_qty']), (80,0))

    def test_future_source_reservation_is_consistent_across_date_ranges(self):
        p=[purchase(source=2)]
        i=[invoice(),invoice(id=2,when='2026-11-01')]
        october=self.report(p,i)['summary']
        extended=self.report(p,i,end='2026-11-30')['summary']
        self.assertEqual(october['missing_qty'],1)
        self.assertEqual(extended['missing_qty'],1)
        self.assertEqual(extended['cost'],100)

    def test_zero_cost_loss_and_non_sale_statuses(self):
        s=self.report([purchase(lines=[line(qty=2,amount=0)])],
                      [invoice(),invoice(id=2,status='draft'),invoice(id=3,status='cancelled')])['summary']
        self.assertEqual(s['profit'],150)
        self.assertTrue(s['complete'])
        self.assertEqual(self.report([purchase(lines=[line(amount=200)])],[invoice()])['summary']['profit'],-50)


if __name__ == '__main__':
    unittest.main()
