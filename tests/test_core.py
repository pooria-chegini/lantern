import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import oui, linkquality as lq

def test_vendor():
    assert oui.vendor('00:00:0c:12:34:56') == 'Cisco'
    assert oui.vendor('0000.0C12.3456') == 'Cisco'
    assert oui.vendor('ffffff000000') in ('', oui.vendor('FFFFFF000000'))
    assert oui.vendor('zz') == ''

def test_badge():
    assert oui.badge('Cisco Systems') == 'CS'
    assert oui.badge('') == '?'

def test_linkquality():
    assert lq.assess({'in_pkts': 400, 'out_pkts': 300})['grade'] == 'Too low to judge'
    r = lq.assess({'in_pkts': 500000, 'out_pkts': 500000, 'crc': 500})
    assert r['loss_pct'] == 0.05 and r['grade'] == 'Good'
    assert lq.assess({'in_pkts': 10**6})['grade'] == 'Excellent'
    assert lq.grade(2.0) == 'Poor'

if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'): f(); print('ok', n)
