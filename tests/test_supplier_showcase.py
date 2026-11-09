"""SHOWCASE files use encoded rows; never execute their JavaScript."""
import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from supplier_showcase import decode_showcase_html
from test_supplier_import import env, upload
from models import Item


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
