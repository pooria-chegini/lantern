import re

ABBR = [('TwentyFiveGigE', 'Twe'), ('TenGigabitEthernet', 'Te'), ('FortyGigabitEthernet', 'Fo'), ('HundredGigE', 'Hu'),
        ('GigabitEthernet', 'Gi'), ('FastEthernet', 'Fa'), ('Port-channel', 'Po'), ('TwoGigabitEthernet', 'Tw'),
        ('FiveGigabitEthernet', 'Fi'), ('Ethernet', 'Eth'), ('Loopback', 'Lo')]

def short(n):
    n = (n or '').strip()
    for a, b in ABBR:
        if n.startswith(a): return b + n[len(a):]
    return n

def norm_mac(s):
    h = re.sub(r'[^0-9a-fA-F]', '', s or '').lower()
    return f'{h[0:4]}.{h[4:8]}.{h[8:12]}' if len(h) == 12 else h

def parse_version(out):
    r = {}
    m = re.search(r'Version (\d[\w\.\(\)]*)', out); r['version'] = m.group(1).rstrip(',') if m else ''
    m = re.search(r'Model [Nn]umber\s*:\s*(\S+)', out) or re.search(r'^cisco (\S+) \(', out, re.M)
    r['model'] = m.group(1) if m else ''
    m = re.search(r'System [Ss]erial [Nn]umber\s*:\s*(\S+)', out) or re.search(r'Processor board ID (\S+)', out)
    r['serial'] = m.group(1) if m else ''
    m = re.search(r'uptime is (.+)', out); r['uptime'] = m.group(1).strip() if m else ''
    return r

def parse_if_status(out):
    lines = out.splitlines()
    hi = next((i for i, l in enumerate(lines) if l.strip().startswith('Port') and 'Status' in l), None)
    if hi is None: return []
    h = lines[hi]
    if 'Name' not in h: return []
    nc, sc = h.index('Name'), h.index('Status')
    res = []
    for l in lines[hi + 1:]:
        if not l.strip() or len(l) <= sc: continue
        port = l[:nc].strip()
        if not port or ' ' in port: continue
        t = l[sc:].split(None, 4)
        if len(t) < 4: continue
        res.append(dict(name=port, descr=l[nc:sc].strip(), status=t[0], vlan=t[1], duplex=t[2], speed=t[3],
                        ptype=t[4] if len(t) > 4 else ''))
    return res

def parse_errdis(out):
    r = {}
    for l in out.splitlines():
        m = re.match(r'^(\S+)\s+.*?err-disabled\s+(\S+)', l)
        if m: r[m.group(1)] = m.group(2)
    return r

def parse_cdp(out):
    res = []
    for blk in re.split(r'-{10,}', out):
        d = re.search(r'Device ID:\s*(\S+)', blk)
        i = re.search(r'Interface:\s*([^,\s]+)', blk)
        if not (d and i): continue
        ip = re.search(r'IP(?:v4)? [Aa]ddress:\s*(\S+)', blk)
        p = re.search(r'Platform:\s*([^,\n]+)', blk)
        po = re.search(r'Port ID \(outgoing port\):\s*(\S+)', blk)
        cap = re.search(r'Capabilities:\s*(.+)', blk)
        res.append(dict(local_if=short(i.group(1)), rhost=d.group(1), rip=ip.group(1) if ip else '', caps=cap.group(1).strip() if cap else '',
                        rif=short(po.group(1)) if po else '', rplat=p.group(1).strip() if p else ''))
    return res

def parse_vlans(out):
    res, cur = [], None
    for l in out.splitlines():
        m = re.match(r'^(\d+)\s+(\S+)\s+(active|act/\S+|suspend|sus/\S+)\s*(.*)$', l)
        if m:
            cur = dict(vid=int(m.group(1)), name=m.group(2), status=m.group(3), ports=m.group(4).strip()); res.append(cur)
        elif cur and re.match(r'^\s{10,}\S', l):
            cur['ports'] += ' ' + l.strip()
        else:
            cur = None
    return res

def parse_macs(out):
    res = []
    for l in out.splitlines():
        m = re.match(r'^\s*(\d+|All)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\S+)\s+(?:\d+\s+)?(\S+)\s*$', l)
        if m and m.group(3).upper() == 'DYNAMIC' and m.group(4).upper() not in ('CPU', 'DROP'):
            res.append(dict(vlan=m.group(1), mac=m.group(2).lower(), port=short(m.group(4))))
    return res

def parse_counters(out):
    """Per-interface counters from 'show interfaces' (IOS/IOS-XE)."""
    res, cur = [], None
    def num(pat, t):
        m = re.search(pat, t)
        return int(m.group(1)) if m else 0
    blocks = re.split(r'^(?=\S)', out, flags=re.M)
    for b in blocks:
        m = re.match(r'^(\S+) is .*line protocol', b)
        if not m: continue
        t = b
        res.append(dict(
            name=short(m.group(1)),
            in_pkts=num(r'(\d+) packets input', t),
            out_pkts=num(r'(\d+) packets output', t),
            in_errors=num(r'(\d+) input errors', t),
            crc=num(r'(\d+) CRC', t),
            out_errors=num(r'(\d+) output errors', t),
            out_drops=num(r'Total output drops: (\d+)', t),
            queue_drops=0))
    return res

def parse_arp(out):
    return [dict(ip=m.group(1), mac=m.group(2).lower(), iface=short(m.group(3)))
            for m in re.finditer(r'^Internet\s+(\S+)\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(\S+)', out, re.M)]

def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or ''))

PROBLEM_STATUS = {'err-disabled': 'critical', 'inactive': 'warn', 'faulty': 'critical', 'suspended': 'warn', 'err-dis': 'critical'}

def if_problems(ifs):
    out = []
    for i in ifs:
        st = i['status'].lower()
        if st in PROBLEM_STATUS:
            out.append((PROBLEM_STATUS[st], i['name'], st))
        elif st == 'connected' and i['duplex'].lower() in ('half', 'a-half'):
            out.append(('warn', i['name'], 'connected with duplex = half'))
        elif st == 'connected' and i['speed'].lower() in ('10', 'a-10'):
            out.append(('warn', i['name'], 'connected at 10Mbps speed'))
    return out

def redact(cfg):
    pat = re.compile(r'((?:password|secret|key|community|authentication-key|auth-key)(?: [0-9]{1,2})?) \S+')
    return '\n'.join(pat.sub(r'\1 <hidden>', l) if re.search(r'password|secret|key|community', l) else l for l in cfg.splitlines())
