"""SHOWCASE files use encoded rows; never execute their JavaScript."""
import base64
import ast
import json
import re
import sys
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from supplier_showcase import decode_showcase_html
from test_supplier_import import env, upload
from models import Item, Supplier, db


def showcase(rows):
    key = [146, 152, 3, 234]
    seed = 246
    digest = 2166136261
    packed = bytearray()
    for j, value in enumerate(rows.encode()):
        byte = value ^ ((key[j % len(key)] + (j % 256) * 31 + seed) & 255)
        packed.append(byte)
        seed = byte
        digest = ((digest ^ value) * 16777619) & 0xffffffff
    encoded = base64.b64encode(packed).decode()
    chunks = [encoded[:len(encoded)//2], encoded[len(encoded)//2:]]
    return ('<html><div>List No: 000092</div><table><tbody id="itemsBody"></tbody></table>'
            '<script>var target=document.getElementById("itemsBody");'
            'target.innerHTML=(function(){var a=' + json.dumps(chunks[::-1]) +
            ',b=[1,0],c=' + json.dumps(key) + ",d=246,t='';" +
            'n^((c[j%c.length]+((j%256)*31)+d)&255);' +
            'if(f!==' + str(digest) + ')throw 0;})()</script></html>')


ROWS = ('<tr class="item-row" data-tp="100" data-disc="12" '
        'data-tax="2" data-bonus="10+1"><td>0041</td>'
        '<td>ACICON 20MG TAB.</td><td></td><td>12%</td>'
        '<td>10+1</td><td>100</td><td>2</td></tr>')


def test_decode_and_classic_passthrough():
    assert ROWS in decode_showcase_html(showcase(ROWS))
    assert decode_showcase_html(ROWS) == ROWS


def viewer(inner):
    script = 'let html=' + json.dumps(inner) + ';frame.srcdoc=html;'
    packed = base64.b64encode(bytes(n ^ 37 for n in script.encode())).decode()
    return ('<html><iframe id="showcase"></iframe><script>var p=' + json.dumps([packed]) +
            ',m=[0],k=[37];a.charCodeAt(i)^k[i%k.length]</script></html>')


def test_nested_hosted_viewer():
    assert ROWS in decode_showcase_html(viewer(showcase(ROWS)))
    with pytest.raises(ValueError):
        decode_showcase_html(viewer(showcase(ROWS)).replace('k=[37]', 'k=[]'))


def fetcher():
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'backend/app.py').read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_fetch_supplier_offer')
    import bs4
    namespace = dict(re=re, _get_bs4=lambda: bs4)
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'fetch', 'exec'), namespace)
    return namespace['_fetch_supplier_offer']


def test_short_link_and_existing_provider_fetch():
    headers = Message(); headers['Content-Type'] = 'text/html; charset=utf-8'
    with patch('http.client.HTTPSConnection') as connect:
        response = connect.return_value.getresponse.return_value.__enter__.return_value
        response.status = 200; response.headers = headers
        response.read.return_value = viewer(showcase(ROWS)).encode()
        soup, rows = fetcher()('https://anassystem.com/dotnetclients/s/CxSmhIovV6D-E9vk')
        assert len(rows) == 1 and rows[0]['data-tp'] == '100'
        connect.assert_called_with('anassystem.com', timeout=20)
        response.read.return_value = showcase(ROWS).encode()
        assert len(fetcher()('https://anas-system.com/clients/view/1389/' + 'a'*32 + '?expires=1793969681')[1]) == 1
        response.status = 410
        with pytest.raises(ValueError, match='fresh offer link'):
            fetcher()('https://anassystem.com/dotnetclients/s/CxSmhIovV6D-E9vk')


def test_short_link_preview_and_confirm(env):
    import bs4
    soup = bs4.BeautifulSoup(decode_showcase_html(viewer(showcase(ROWS))), 'html.parser')
    namespace = env.application.view_functions['import_items'].__globals__
    namespace.update(json=json, Supplier=Supplier,
                     _fetch_supplier_offer=lambda url: (soup, soup.select('tr.item-row')))
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'backend/app.py').read_text())
    parser = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_parse_offer_cell')
    exec(compile(ast.Module(body=[parser], type_ignores=[]), 'parser', 'exec'), namespace)
    db.session.add(Supplier(user_id=1, code='S1', name='DOSANI', is_active=True))
    db.session.commit()
    form = dict(vendor='DOSANI', offer_url='https://anassystem.com/dotnetclients/s/CxSmhIovV6D-E9vk')
    preview = env.post('/import', data=dict(form, preview='1'))
    assert preview.status_code == 200 and preview.json['count'] == 1
    assert Item.query.count() == 0
    result = env.post('/import', data=dict(form, signature=preview.json['signature']))
    assert result.status_code == 200, result.json
    assert Item.query.one().vendor_code == '0041'


@pytest.mark.parametrize('url', [
    'https://anassystem.com.evil.test/dotnetclients/s/CxSmhIovV6D-E9vk',
    'https://anassystem.com/dotnetclients/s/../../private',
    'http://anassystem.com/dotnetclients/s/CxSmhIovV6D-E9vk',
    'https://anassystem.com/dotnetclients/s/CxSmhIovV6D-E9vk?url=http://localhost',
])
def test_short_link_validation(url):
    with patch('http.client.HTTPSConnection') as connect:
        with pytest.raises(ValueError):
            fetcher()(url)
        connect.assert_not_called()


def test_upload_preserves_supplier_fields_and_reimport_identity(env):
    for _ in range(2):
        response = upload(env, showcase(ROWS))
        assert response.status_code == 200, response.json
    item = Item.query.one()
    assert (item.name, item.vendor_code, item.vendor_list_no) == ('ACICON 20MG TAB.', '0041', '000092')
    assert (float(item.tp), float(item.discount_pct), float(item.tax_pct), item.bonus_text) == (100, 12, 2, '10+1')


def test_corrupt_payload_keeps_catalogue(env):
    assert upload(env, showcase(ROWS)).status_code == 200
    broken = showcase(ROWS).replace('if(f!==', 'if(f!==9')
    response = upload(env, broken)
    assert response.status_code == 400
    assert 'previous catalogue was kept' in response.json['error']
    assert Item.query.filter_by(is_active=True).count() == 1


@pytest.mark.parametrize('before,after', [(',b=[1,0]', ',b=[2,0]'),
                                       (',c=[146, 152, 3, 234]', ',c=[]'),
                                       ('((j%256)*31)', '((j%256)*32)')])
def test_unsupported_or_malformed_data_is_rejected(before, after):
    with pytest.raises(ValueError):
        decode_showcase_html(showcase(ROWS).replace(before, after))
