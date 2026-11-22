"""Per-port link quality from interface counters.

loss % = (in errors + CRC + output drops + output errors + queue drops) / (total in + out packets) * 100
Ports with fewer than MIN_PACKETS packets are reported as 'too low to judge'.
"""
MIN_PACKETS = 1000

def loss_pct(errors, total_packets):
    if total_packets < MIN_PACKETS: return None
    return round(100.0 * errors / total_packets, 3)

def grade(pct):
    if pct is None: return 'Too low to judge'
    if pct == 0: return 'Excellent'
    if pct < 0.1: return 'Good'
    if pct < 1.0: return 'Fair'
    return 'Poor'

def assess(c):
    """c: dict with in_pkts, out_pkts, in_errors, crc, out_drops, out_errors, queue_drops (missing keys = 0)."""
    g = lambda k: int(c.get(k, 0) or 0)
    total = g('in_pkts') + g('out_pkts')
    errs = g('in_errors') + g('crc') + g('out_drops') + g('out_errors') + g('queue_drops')
    pct = loss_pct(errs, total)
    return dict(total=total, errors=errs, loss_pct=pct, grade=grade(pct))
