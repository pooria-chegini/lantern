"""Severity, confidence and remediation-status handling (pure logic, no I/O)."""
STATUSES = [('open', 'Open'), ('in_progress', 'In progress'), ('fixed_pending', 'Fixed - pending verification'),
            ('accepted_risk', 'Accepted risk'), ('false_positive', 'False positive')]
# share of the penalty that still counts for each status
PENALTY = {'open': 1.0, 'in_progress': 1.0, 'fixed_pending': 1.0, 'accepted_risk': 0.5, 'false_positive': 0.0}
# confidence: how directly the rule reads an explicit config line (High) vs infers it (Medium/Low)
CONF = {'telnet': 'High', 'http': 'High', 'secret': 'High', 'aaa': 'Medium', 'vty_acl': 'High', 'timeout': 'High',
        'ios': 'Low', 'backup': 'Low', 'cdp': 'Medium', 'copp': 'Medium'}

def severity(weight):
    return 'Critical' if weight >= 6 else 'High' if weight >= 4 else 'Medium' if weight >= 2 else 'Low'

def confidence(cid):
    return CONF.get(cid, 'Medium')

def effective(det, status):
    """Score 0-100 after applying statuses ({check_id: status}). N/A checks are skipped."""
    num = den = 0.0
    for d in det:
        if d['score'] is None: continue
        st = status.get(d['id'], 'open')
        if st == 'false_positive': continue
        pen = d['weight'] * (1 - d['score']) * PENALTY.get(st, 1.0)
        den += d['weight']; num += d['weight'] - pen
    return round(100 * num / den, 1) if den else 0.0

def compare(old, new):
    """Return (improved, regressed) lists of (title, old%, new%) between two detail lists."""
    o = {d['id']: d for d in old}; imp, reg = [], []
    for d in new:
        p = o.get(d['id'])
        if not p or p['score'] is None or d['score'] is None: continue
        row = (d['title'], round(p['score'] * 100), round(d['score'] * 100))
        if d['score'] > p['score']: imp.append(row)
        elif d['score'] < p['score']: reg.append(row)
    return imp, reg

def sparkline(vals, w=240, h=50):
    v = [x for x in vals if x is not None]
    if len(v) < 2: return ''
    lo, hi = min(v), max(v); rng = (hi - lo) or 1
    pts = ' '.join(f'{4 + i * (w - 8) / (len(v) - 1):.1f},{h - 4 - (x - lo) / rng * (h - 8):.1f}' for i, x in enumerate(v))
    return f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}"><polyline points="{pts}" fill="none" stroke="#0d9488" stroke-width="2"/></svg>'
