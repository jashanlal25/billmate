"""
Quick DB query tool — run from backend/ folder:
  python db_query.py "SELECT * FROM users"
  python db_query.py "SELECT * FROM invoices LIMIT 10"
  python db_query.py tables
"""
import sys
sys.path.insert(0, '.')
from app import app, db

query = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else 'tables'

with app.app_context():
    if query.strip().lower() == 'tables':
        rows = db.session.execute(db.text(
            "SELECT tablename, (SELECT count(*) FROM information_schema.columns "
            "WHERE table_name=tablename) as cols "
            "FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )).fetchall()
        print('%-30s %s' % ('Table', 'Columns'))
        print('-' * 40)
        for r in rows:
            count = db.session.execute(db.text(f'SELECT count(*) FROM "{r[0]}"')).scalar()
            print('%-30s %-8s  rows: %s' % (r[0], r[1], count))
    else:
        rows = db.session.execute(db.text(query)).fetchall()
        if not rows:
            print('No rows returned.')
        else:
            cols = db.session.execute(db.text(query)).keys()
            header = '  '.join(str(c)[:18].ljust(18) for c in cols)
            print(header)
            print('-' * len(header))
            for r in rows:
                print('  '.join(str(v)[:18].ljust(18) for v in r))
        print(f'\n{len(rows)} row(s)')
