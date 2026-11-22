"""Rebuild data/oui.csv from the Wireshark 'manuf' file (IEEE-derived).
Usage: pip download manuf -d /tmp/mf && tar xzf /tmp/mf/manuf-*.tar.gz -C /tmp/mf
       python3 scripts/update_oui.py /tmp/mf/manuf-*/manuf/manuf
"""
import csv, os, re, sys

src = sys.argv[1]
dst = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'oui.csv')
rows = {}
for l in open(src, encoding='utf-8', errors='ignore'):
    if l.startswith('#') or not l.strip(): continue
    p = l.rstrip('\n').split('\t')
    m = p[0].strip()
    if not re.fullmatch(r'[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}', m): continue
    short = p[1].strip() if len(p) > 1 else ''
    full = p[2].strip() if len(p) > 2 else short
    rows[m.replace(':', '').upper()] = (short or full, full or short)
with open(dst, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f); w.writerow(['oui', 'vendor_short', 'vendor_full'])
    for k in sorted(rows): w.writerow([k, *rows[k]])
print('wrote', len(rows), 'entries to', dst)
