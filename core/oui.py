"""MAC vendor lookup from the offline IEEE OUI seed (data/oui.csv)."""
import csv, os, re

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'oui.csv')
_cache = None

def _load():
    global _cache
    if _cache is None:
        _cache = {}
        if os.path.exists(_PATH):
            with open(_PATH, encoding='utf-8') as f:
                for r in csv.DictReader(f):
                    _cache[r['oui']] = (r['vendor_short'], r['vendor_full'])
    return _cache

def vendor(mac, full=False):
    """Return vendor name for a MAC in any common format, or '' if unknown."""
    h = re.sub(r'[^0-9a-fA-F]', '', mac or '').upper()
    if len(h) < 6: return ''
    v = _load().get(h[:6])
    return (v[1] if full else v[0]) if v else ''

def badge(name):
    """Monogram for a vendor badge, e.g. 'Cisco Systems' -> 'CS'."""
    w = re.findall(r'[A-Za-z0-9]+', name or '')
    return ''.join(x[0] for x in w[:2]).upper() or '?'
