"""Read Anas offline SHOWCASE data without executing uploaded JavaScript."""
import base64
import binascii
import json
import re


def _unwrap_showcase_viewer(html):
    """Extract the iframe's literal HTML from the known hosted viewer."""
    if not re.search(r'<iframe\b[^>]*\bid=[\'"]showcase[\'"]', html, re.I):
        return html
    error = 'Could not decode the supplier SHOWCASE viewer; the previous catalogue was kept'
    match = re.search(r'var p=(\[.*?\]),m=(\[.*?\]),k=(\[.*?\]);', html, re.S)
    if not match or 'a.charCodeAt(i)^k[i%k.length]' not in html:
        raise ValueError(error)
    try:
        chunks, order, key = (json.loads(match[i]) for i in (1, 2, 3))
        if (not isinstance(chunks, list) or not 0 < len(chunks) <= 100000
                or any(not isinstance(x, str) for x in chunks)
                or not isinstance(order, list) or len(order) != len(chunks)
                or any(type(i) is not int for i in order)
                or sorted(order) != list(range(len(chunks)))
                or not isinstance(key, list) or not 0 < len(key) <= 256
                or any(type(n) is not int or not 0 <= n <= 255 for n in key)):
            raise ValueError(error)
        packed = ''.join(chunks[i] for i in order)
        if len(packed) > 12 * 1024 * 1024:
            raise ValueError(error)
        data = base64.b64decode(packed, validate=True)
        script = bytes(n ^ key[i % len(key)] for i, n in enumerate(data)).decode('utf-8')
        literal = re.search(r'let html=("(?:\\.|[^"\\])*");', script, re.S)
        if not literal or 'frame.srcdoc=html' not in script:
            raise ValueError(error)
        inner = json.loads(literal[1])
        if len(inner) > 12 * 1024 * 1024 or not inner.rstrip().lower().endswith('</html>'):
            raise ValueError(error)
        return inner
    except (ValueError, TypeError, KeyError, IndexError, binascii.Error):
        raise ValueError(error) from None


def decode_showcase_html(html):
    html = _unwrap_showcase_viewer(html)
    # Only the itemsBody payload is inventory. Other encoded payloads contain ads.
    scripts = re.findall(r'<script\b[^>]*>(.*?)</script\s*>', html, re.I | re.S)
    for script in scripts:
        if not re.search(r'getElementById\([\'"]itemsBody[\'"]\)', script):
            continue
        if 'target.innerHTML=(function(){var a=[' not in script:
            continue
        error = 'Could not decode the supplier SHOWCASE list; the previous catalogue was kept'
        match = re.search(
            r'var a=(\[.*?\]),b=(\[.*?\]),c=(\[.*?\]),d=(\d+),t=\'\';',
            script, re.S)
        checksum = re.search(r'if\(f!==(\d+)\)throw 0', script)
        # Require the known byte transform, rather than guessing future formats.
        transform = 'n^((c[j%c.length]+((j%256)*31)+d)&255)'
        if not match or not checksum or transform not in script:
            raise ValueError(error)
        try:
            chunks, order, key = (json.loads(match[i]) for i in (1, 2, 3))
            seed = int(match[4])
            if (not isinstance(chunks, list) or not 0 < len(chunks) <= 100000
                    or any(not isinstance(x, str) for x in chunks)
                    or not isinstance(order, list) or len(order) != len(chunks)
                    or any(type(i) is not int for i in order)
                    or sorted(order) != list(range(len(chunks)))
                    or not isinstance(key, list) or not 0 < len(key) <= 256
                    or any(type(n) is not int or not 0 <= n <= 255 for n in key)
                    or not 0 <= seed <= 255):
                raise ValueError(error)
            packed = ''.join(chunks[i] for i in order)
            if len(packed) > 12 * 1024 * 1024:
                raise ValueError(error)
            data = base64.b64decode(packed, validate=True)
            decoded = bytearray(len(data))
            digest = 2166136261
            for j, byte in enumerate(data):
                value = byte ^ ((key[j % len(key)] + (j % 256) * 31 + seed) & 255)
                decoded[j] = value
                seed = byte
                digest = ((digest ^ value) * 16777619) & 0xffffffff
            if digest != int(checksum[1]):
                raise ValueError(error)
            rows = decoded.decode('utf-8')
        except (ValueError, TypeError, KeyError, IndexError, binascii.Error):
            raise ValueError(error) from None
        body = re.compile(r'(<tbody\b[^>]*\bid=[\'"]itemsBody[\'"][^>]*>)\s*(</tbody\s*>)', re.I)
        html, count = body.subn(lambda m: m[1] + rows + m[2], html, count=1)
        if not count:
            raise ValueError(error)
        break
    return html
