import json, re, hashlib
from datetime import datetime
from . import checks
from .parsers import *

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, created TEXT, targets TEXT, status TEXT,
  total INT DEFAULT 0, done INT DEFAULT 0, found INT DEFAULT 0, avg REAL);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, ip TEXT UNIQUE, hostname TEXT, first_seen TEXT,
  last_ok TEXT, last_try TEXT, last_error TEXT, last_result_id INT);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY, scan_id INT, device_id INT, created TEXT, ip TEXT,
  hostname TEXT, platform TEXT, model TEXT, serial TEXT, uptime TEXT, version TEXT, score REAL, error TEXT,
  warn TEXT, nprob INT DEFAULT 0, details TEXT, config TEXT);
CREATE TABLE IF NOT EXISTS ifaces(result_id INT, name TEXT, descr TEXT, status TEXT, vlan TEXT, duplex TEXT,
  speed TEXT, ptype TEXT, problem TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS neighbors(result_id INT, local_if TEXT, rhost TEXT, rip TEXT, rif TEXT, rplat TEXT, caps TEXT);
CREATE TABLE IF NOT EXISTS vlans(result_id INT, vid INT, name TEXT, status TEXT, ports TEXT);
CREATE TABLE IF NOT EXISTS macs(result_id INT, mac TEXT, vlan TEXT, port TEXT, uplink INT, port_macs INT);
CREATE TABLE IF NOT EXISTS arps(result_id INT, ip TEXT, mac TEXT, iface TEXT);
CREATE TABLE IF NOT EXISTS counters(result_id INT, name TEXT, in_pkts INT, out_pkts INT, in_errors INT,
  crc INT, out_errors INT, out_drops INT, queue_drops INT);
CREATE TABLE IF NOT EXISTS check_status(device_id INT, check_id TEXT, status TEXT, note TEXT, updated TEXT, PRIMARY KEY(device_id,check_id));
CREATE INDEX IF NOT EXISTS i_res_dev ON results(device_id, id);
CREATE INDEX IF NOT EXISTS i_if_res ON ifaces(result_id);
CREATE INDEX IF NOT EXISTS i_nb_res ON neighbors(result_id);
CREATE INDEX IF NOT EXISTS i_vl_res ON vlans(result_id);
CREATE INDEX IF NOT EXISTS i_mac_mac ON macs(mac);
CREATE INDEX IF NOT EXISTS i_mac_res ON macs(result_id);
CREATE INDEX IF NOT EXISTS i_arp_ip ON arps(ip);
CREATE INDEX IF NOT EXISTS i_arp_mac ON arps(mac);
CREATE INDEX IF NOT EXISTS i_arp_res ON arps(result_id);
"""
CHILD = ('ifaces', 'neighbors', 'vlans', 'macs', 'arps', 'counters')
now = lambda: datetime.now().strftime('%Y-%m-%d %H:%M')

def mark_failed(c, ip, err):
    c.execute('INSERT OR IGNORE INTO devices(ip,first_seen) VALUES(?,?)', (ip, now()))
    c.execute('UPDATE devices SET last_try=?, last_error=? WHERE ip=?', (now(), err, ip))

def ingest(c, scan_id, ip, raw, min_versions, keep):
    cfg = raw['config']
    host, plat, ver = checks.detect(cfg)
    res = checks.audit(cfg, plat, min_versions)
    v = parse_version(raw.get('version', ''))
    ifs = parse_if_status(raw.get('ifs', ''))
    reasons = parse_errdis(raw.get('errdis', ''))
    cdp = parse_cdp(raw.get('cdp', ''))
    macs = parse_macs(raw.get('mac', ''))
    probs = {n: (sev, why) for sev, n, why in if_problems(ifs)}
    c.execute('INSERT OR IGNORE INTO devices(ip,first_seen) VALUES(?,?)', (ip, now()))
    did = c.execute('SELECT id FROM devices WHERE ip=?', (ip,)).fetchone()[0]
    cur = c.execute('INSERT INTO results(scan_id,device_id,created,ip,hostname,platform,model,serial,uptime,version,score,warn,nprob,details,config)'
                    ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (scan_id, did, now(), ip, host, plat, v['model'], v['serial'], v['uptime'], v['version'] or ver,
                     checks.total(res), raw.get('warn', ''), len(probs), json.dumps(res), cfg))
    rid = cur.lastrowid
    c.executemany('INSERT INTO ifaces VALUES(?,?,?,?,?,?,?,?,?,?)',
                  [(rid, i['name'], i['descr'], i['status'], i['vlan'], i['duplex'], i['speed'], i['ptype'],
                    probs.get(i['name'], ('', ''))[0],
                    (reasons.get(i['name']) or probs.get(i['name'], ('', ''))[1])) for i in ifs])
    c.executemany('INSERT INTO neighbors VALUES(?,?,?,?,?,?,?)',
                  [(rid, n['local_if'], n['rhost'], n['rip'], n['rif'], n['rplat'], n['caps']) for n in cdp])
    c.executemany('INSERT INTO vlans VALUES(?,?,?,?,?)', [(rid, x['vid'], x['name'], x['status'], x['ports']) for x in parse_vlans(raw.get('vlan', ''))])
    # uplink = port toward another switch/router (CDP caps) or a port-channel
    up = {n['local_if'] for n in cdp if re.search(r'Switch|Router', n['caps'])}
    cnt = {}
    for m in macs: cnt[m['port']] = cnt.get(m['port'], 0) + 1
    c.executemany('INSERT INTO macs VALUES(?,?,?,?,?,?)',
                  [(rid, m['mac'], m['vlan'], m['port'], int(m['port'] in up or m['port'].startswith('Po')), cnt[m['port']]) for m in macs])
    c.executemany('INSERT INTO arps VALUES(?,?,?,?)', [(rid, a['ip'], a['mac'], a['iface']) for a in parse_arp(raw.get('arp', ''))])
    c.executemany('INSERT INTO counters VALUES(?,?,?,?,?,?,?,?,?)',
                  [(rid, x['name'], x['in_pkts'], x['out_pkts'], x['in_errors'], x['crc'], x['out_errors'],
                    x['out_drops'], x['queue_drops']) for x in parse_counters(raw.get('counters', ''))])
    c.execute('UPDATE devices SET hostname=?, last_ok=?, last_try=?, last_error=NULL, last_result_id=? WHERE id=?',
              (host, now(), now(), rid, did))
    prune(c, did, keep)
    return rid

def prune(c, did, keep):
    old = [r[0] for r in c.execute('SELECT id FROM results WHERE device_id=? ORDER BY id DESC LIMIT -1 OFFSET ?', (did, keep))]
    for rid in old:
        for t in CHILD: c.execute(f'DELETE FROM {t} WHERE result_id=?', (rid,))
        c.execute('DELETE FROM results WHERE id=?', (rid,))

# ---------------- queries (always against the latest snapshot of each device unless hist=True)
def devices(c):
    return c.execute('''SELECT d.*, r.score, r.platform, r.model, r.version, r.serial, r.nprob
        FROM devices d LEFT JOIN results r ON r.id=d.last_result_id ORDER BY r.score IS NULL, r.score''').fetchall()

def problems(c):
    rows = c.execute('''SELECT d.id did, d.hostname, d.ip, i.name, i.descr, i.status, i.problem, i.reason, r.created, i.result_id
        FROM ifaces i JOIN devices d ON d.last_result_id=i.result_id JOIN results r ON r.id=i.result_id
        WHERE i.problem!='' ORDER BY i.problem, d.hostname, i.name''').fetchall()
    cache, out = {}, []
    for r in rows:
        if r['result_id'] not in cache: cache[r['result_id']] = link_map(c, r['result_id'])
        a = cache[r['result_id']].get(r['name']) or {}
        out.append(dict(r, grade=a.get('grade', '-'), loss=a.get('loss_pct')))
    return out

IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def search(c, q, hist=False, limit=300):
    q = q.strip().lower()
    if not q: return []
    hexq = re.sub(r'[^0-9a-f]', '', q)
    if IP_RE.match(q):
        macs = {r[0] for r in c.execute('SELECT mac FROM arps WHERE ip=? AND result_id IN (SELECT last_result_id FROM devices)', (q,))}
        if not macs: return []
        cond, arg = f"m.mac IN ({','.join('?'*len(macs))})", list(macs)
    elif len(hexq) == 12 and re.fullmatch(r'[0-9a-f:.\-]+', q):
        cond, arg = 'm.mac=?', [norm_mac(q)]
    else:
        ips = [r[0] for r in c.execute('SELECT DISTINCT mac FROM arps WHERE ip LIKE ? AND result_id IN (SELECT last_result_id FROM devices)', (f'%{q}%',))]
        cond = '(m.mac LIKE ?' + (f" OR m.mac IN ({','.join('?'*len(ips))})" if ips else '') + ')'
        arg = [f'%{q}%'] + ips
    join = 'JOIN devices d ON d.id=r.device_id' + ('' if hist else ' AND d.last_result_id=r.id')
    rows = c.execute(f'''SELECT m.mac, m.vlan, m.port, m.uplink, m.port_macs, d.id did, d.hostname, d.ip swip, r.created,
          i.descr, i.status, i.problem,
          (SELECT group_concat(DISTINCT a.ip) FROM arps a WHERE a.mac=m.mac AND a.result_id IN (SELECT last_result_id FROM devices)) ips
        FROM macs m JOIN results r ON r.id=m.result_id {join}
        LEFT JOIN ifaces i ON i.result_id=m.result_id AND i.name=m.port
        WHERE {cond} ORDER BY m.mac, m.uplink, m.port_macs, r.created DESC LIMIT ?''', arg + [limit]).fetchall()
    return rows

def link_map(c, rid):
    """port name -> link assessment for one result."""
    from core import linkquality as lq
    out = {}
    if not rid: return out
    for r in c.execute('SELECT name, in_pkts, out_pkts, in_errors, crc, out_errors, out_drops, queue_drops FROM counters WHERE result_id=?', (rid,)):
        out[r[0]] = lq.assess(dict(zip(['name','in_pkts','out_pkts','in_errors','crc','out_errors','out_drops','queue_drops'], r)))
    return out

def device_detail(c, did):
    d = c.execute('SELECT * FROM devices WHERE id=?', (did,)).fetchone()
    if not d: return None
    rid = d['last_result_id']
    g = lambda sql: c.execute(sql, (rid,)).fetchall() if rid else []
    return dict(d=d,
        hist=c.execute('SELECT id,created,score,version,nprob,warn FROM results WHERE device_id=? ORDER BY id DESC', (did,)).fetchall(),
        ifs=g("SELECT * FROM ifaces WHERE result_id=? ORDER BY problem='' , rowid"),
        lq=link_map(c, rid),
        nbr=g('SELECT * FROM neighbors WHERE result_id=? ORDER BY local_if'),
        vl=g('SELECT * FROM vlans WHERE result_id=? ORDER BY vid'),
        last=c.execute('SELECT * FROM results WHERE id=?', (rid,)).fetchone() if rid else None)


def vlan_list(c):
    return c.execute('''SELECT v.vid, group_concat(DISTINCT v.name) names, count(DISTINCT d.id) nsw,
        (SELECT count(DISTINCT m.mac) FROM macs m JOIN devices d2 ON d2.last_result_id=m.result_id
          WHERE m.vlan=CAST(v.vid AS TEXT) AND m.uplink=0) nodes
        FROM vlans v JOIN devices d ON d.last_result_id=v.result_id GROUP BY v.vid ORDER BY v.vid''').fetchall()

def vlan_detail(c, vid):
    sw = c.execute('''SELECT d.id did, d.hostname, d.ip, v.name, v.status, v.ports,
        (SELECT count(*) FROM macs m WHERE m.result_id=v.result_id AND m.vlan=? AND m.uplink=0) nodes
        FROM vlans v JOIN devices d ON d.last_result_id=v.result_id WHERE v.vid=? ORDER BY d.hostname''', (str(vid), vid)).fetchall()
    nodes = c.execute('''SELECT m.mac, m.port, m.uplink, d.id did, d.hostname, d.ip swip, i.descr, i.status, i.problem,
        (SELECT group_concat(DISTINCT a.ip) FROM arps a WHERE a.mac=m.mac AND a.result_id IN (SELECT last_result_id FROM devices)) ips
        FROM macs m JOIN devices d ON d.last_result_id=m.result_id
        LEFT JOIN ifaces i ON i.result_id=m.result_id AND i.name=m.port
        WHERE m.vlan=? ORDER BY m.uplink, d.hostname, m.port''', (str(vid),)).fetchall()
    return sw, nodes

# ---------------- MACs (latest snapshot per device) and link quality
def _latest(c):
    return c.execute('SELECT r.id, r.ip, COALESCE(r.hostname, r.ip) FROM devices d JOIN results r ON r.id=d.last_result_id WHERE d.last_result_id IS NOT NULL').fetchall()

_GUESS = [('Cisco', 'Network device'), ('Ubiquiti', 'Network device'), ('MikroTik', 'Network device'), ('Juniper', 'Network device'),
          ('Aruba', 'Network device'), ('Hewlett', 'Server / printer'), ('Dell', 'Server / PC'), ('Lenovo', 'PC / laptop'),
          ('Apple', 'Mac / iOS device'), ('Samsung', 'Phone / TV'), ('Xiaomi', 'Phone'), ('VMware', 'Virtual machine'),
          ('Microsoft', 'PC / server'), ('Intel', 'PC / laptop'), ('Realtek', 'PC / device'), ('Raspberry', 'Single-board computer')]

def guess(vendor, platform=''):
    """Rough device-type guess from CDP platform first, then vendor. A guess, not a fact."""
    if platform: return platform
    for k, t in _GUESS:
        if k.lower() in (vendor or '').lower(): return t
    return 'Unknown'

def mac_list(c):
    from core import oui
    rows = []
    for rid, ip, host in _latest(c):
        lq_ = link_map(c, rid)
        cdp = {n[0]: (n[1], n[2]) for n in c.execute('SELECT local_if, rhost, rplat FROM neighbors WHERE result_id=?', (rid,))}
        arp = {a[0]: a[1] for a in c.execute('SELECT mac, ip FROM arps WHERE result_id=?', (rid,))}
        for mac, vlan, port, up in c.execute('SELECT mac, vlan, port, uplink FROM macs WHERE result_id=?', (rid,)):
            v = oui.vendor(mac)
            nb = cdp.get(port, (None, None))
            node = nb[0] or ''
            rows.append(dict(mac=mac, vendor=v or 'Unknown', badge=oui.badge(v), vlan=vlan, switch=host, guess=guess(v, nb[1] if nb else ''), grade=(lq_.get(port) or {}).get('grade', '-'),
                             sw_ip=ip, port=port, node=node or f'{host} {port}', ip=arp.get(mac, ''), uplink=up))
    return rows

def link_list(c):
    from core import linkquality as lq
    rows = []
    for rid, ip, host in _latest(c):
        for r in c.execute('SELECT name, in_pkts, out_pkts, in_errors, crc, out_errors, out_drops, queue_drops FROM counters WHERE result_id=?', (rid,)):
            a = lq.assess(dict(zip(['name','in_pkts','out_pkts','in_errors','crc','out_errors','out_drops','queue_drops'], r)))
            rows.append(dict(switch=host, sw_ip=ip, port=r[0], total=a['total'], errors=a['errors'],
                             loss=a['loss_pct'], grade=a['grade']))
    order = {'Poor': 0, 'Fair': 1, 'Good': 2, 'Excellent': 3, 'Too low to judge': 4}
    return sorted(rows, key=lambda x: (order[x['grade']], x['switch'], x['port']))
