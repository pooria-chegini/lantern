"""Hardening checks. Each check -> dict(id,cat,title,weight,score 0..1|None(N/A),detail,fix)."""
import re

PHYS = re.compile(r'^interface (Gigabit|TenGigabit|FastEthernet|FortyGigabit|TwentyFiveGig|HundredGig|TwoGigabit|FiveGigabit)', re.I)

def parse_blocks(cfg):
    blocks, cur = [], None
    for ln in cfg.splitlines():
        if not ln.strip() or ln.startswith('!'):
            cur = None if ln.startswith('!') else cur
            continue
        if ln[0] != ' ':
            cur = (ln.strip(), [])
            blocks.append(cur)
        elif cur:
            cur[1].append(ln.strip())
    return blocks

def detect(cfg):
    m = re.search(r'^hostname (\S+)', cfg, re.M)
    host = m.group(1) if m else 'unknown'
    ver = (re.search(r'^version (\S+)', cfg, re.M) or [None, ''])[1]
    m = (re.search(r'^! Chassis type: (\S+)', cfg, re.M) or re.search(r'^switch \d+ provision (\S+)', cfg, re.M)
         or re.search(r'^! PID: (\S+)', cfg, re.M) or re.search(r'^license boot level (\S+)', cfg, re.M))
    t = m.group(1).upper() if m else host.upper()
    if '2960' in t: plat = '2960X'
    elif re.search(r'C?9[2-3]\d\d', t): plat = '9200'
    elif re.search(r'3850|3650', t): plat = '3850'
    elif re.search(r'45\d\d|C4500|CAT4500', t): plat = '4500'
    else: plat = 'unknown'
    return host, plat, ver

def R(id, cat, title, w, score, detail='', fix=''):
    return dict(id=id, cat=cat, title=title, weight=w,
                score=None if score is None else max(0.0, min(1.0, score)),
                detail=detail, fix=fix)

def audit(cfg, platform='unknown', min_versions=None):
    min_versions = min_versions or {}
    B = parse_blocks(cfg)
    has = lambda p: re.search(p, cfg, re.M | re.I) is not None
    vty = [l for h, l in B if h.startswith('line vty')]
    con = [l for h, l in B if h.startswith('line con')]
    ifs = [(h, l) for h, l in B if PHYS.match(h)]
    l2 = [(h, l) for h, l in ifs if 'no switchport' not in l and not any(x.startswith('ip address') for x in l)]
    access = [(h, l) for h, l in l2 if 'switchport mode access' in l]
    trunk = [(h, l) for h, l in l2 if 'switchport mode trunk' in l]
    nm = lambda lst: ', '.join(h.split()[1] for h, _ in lst[:12]) + (' ...' if len(lst) > 12 else '')
    res = []
    M, P, L, S, T = 'Management & Access', 'Management Protocols', 'Layer 2', 'Services', 'Maintenance'

    # ---- Management 30
    bad = [l for l in vty if not any(re.match(r'transport input ssh$', x) for x in l)]
    res.append(R('telnet', M, 'Telnet disabled / SSH only', 6, 0 if bad else 1,
        f'{len(bad)} of {len(vty)} VTY blocks allow telnet or have no transport limit', 'line vty 0 15\n transport input ssh'))
    res.append(R('http', M, 'HTTP server disabled', 4, 0 if has(r'^ip http server') else 1, '',
        'no ip http server\nip http secure-server   ! only if required\nip http authentication aaa'))
    aaa = has(r'^aaa new-model') and has(r'^aaa authentication login') and has(r'^(tacacs|radius)')
    fb = has(r'^aaa authentication login .*\blocal\b')
    res.append(R('aaa', M, 'AAA (TACACS+/RADIUS) with local fallback', 6, (0.7 if aaa else 0) + (0.3 if aaa and fb else 0),
        f'aaa={aaa} local-fallback={fb}',
        'aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting exec default start-stop group tacacs+'))
    p7 = re.findall(r'^(?:enable password|username \S+ .*password [07]|\s*password [07]) ', cfg, re.M)
    sec = has(r'^enable (secret|algorithm-type)')
    s5 = len(re.findall(r'secret 5', cfg))
    sc = (0.4 if sec else 0) + (0.6 if not p7 else 0)
    res.append(R('secret', M, 'Secret only (no password 7/0)', 5, sc,
        f'{len(p7)} password 7/0 entries; secret 5 (weak): {s5}',
        'enable algorithm-type scrypt secret <PASS>\nusername <U> privilege 15 algorithm-type scrypt secret <PASS>\nno enable password\n! then remove password lines with: no username <U> password ...'))
    ac = [l for l in vty if not any(x.startswith('access-class') for x in l)]
    res.append(R('vty_acl', M, 'access-class on VTY', 4, 0 if (ac or not vty) else 1,
        f'{len(ac)} VTY blocks without ACL',
        'ip access-list standard MGMT\n permit <MGMT-SUBNET> <WILDCARD>\nline vty 0 15\n access-class MGMT in'))
    nt = [l for l in vty + con if not any(re.match(r'exec-timeout [1-9]|exec-timeout 0 [1-9]', x) for x in l)]
    res.append(R('timeout', M, 'exec-timeout on console and VTY', 3, 0 if nt else 1, f'{len(nt)} blocks without timeout',
        'line con 0\n exec-timeout 5 0\nline vty 0 15\n exec-timeout 5 0'))
    res.append(R('loginblock', M, 'login block-for', 2, 1 if has(r'^login block-for') else 0, '',
        'login block-for 120 attempts 5 within 60\nlogin on-failure log\nlogin on-success log'))

    # ---- Protocols 15
    comm = len(re.findall(r'^snmp-server community', cfg, re.M))
    v3 = has(r'^snmp-server (group \S+ v3 priv|user )')
    sc = 1 if (not comm and (v3 or not has(r'^snmp-server'))) else (0.3 if v3 else 0)
    res.append(R('snmp', P, 'SNMPv3 auth+priv, no v1/v2c', 6, sc, f'{comm} community strings, v3={v3}',
        'no snmp-server community <STR>\nsnmp-server group NMS v3 priv\nsnmp-server user nms NMS v3 auth sha <A> priv aes 128 <P>'))
    ssh2 = has(r'^ip ssh version 2')
    alg = re.findall(r'^ip ssh server algorithm .*', cfg, re.M)
    weak = any(re.search(r'3des|hmac-sha1\b|cbc', a) for a in alg)
    sc = (0.5 if ssh2 else 0) + (0.5 if alg and not weak else 0)
    res.append(R('sshalg', P, 'SSH v2 and strong algorithms', 4, sc, f'v2={ssh2} custom-alg={bool(alg)} weak={weak}',
        'ip ssh version 2\nip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr\nip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512\ncrypto key generate rsa modulus 4096'))
    ntp = has(r'^ntp server')
    res.append(R('ntp', P, 'NTP with authentication', 3, (0.3 if ntp else 0) + (0.7 if has(r'^ntp authenticate') and has(r'^ntp server .* key') else 0), '',
        'ntp authentication-key 1 sha1 <KEY>\nntp authenticate\nntp trusted-key 1\nntp server <IP> key 1'))
    res.append(R('syslog', P, 'Central syslog', 2, 1 if has(r'^logging (host )?\d') else 0, '',
        'logging host <SYSLOG-IP>\nlogging trap informational'))

    # ---- L2 30
    def ratio(lst, test):
        return (sum(1 for h, l in lst if test(l)) / len(lst)) if lst else None
    pf = [(h, l) for h, l in access if 'spanning-tree portfast' in l]
    if has(r'^spanning-tree portfast bpduguard default'): sc, d = 1, 'global default'
    else:
        sc = ratio(pf, lambda l: 'spanning-tree bpduguard enable' in l); d = f'{len(pf)} portfast ports'
        if sc is None: sc = 0
    res.append(R('bpdu', L, 'BPDU Guard', 5, sc, d, 'spanning-tree portfast bpduguard default\n! or per port: spanning-tree bpduguard enable'))
    sc = ratio(access, lambda l: any(re.match(r'switchport port-security$|authentication port-control auto|dot1x pae authenticator', x) for x in l))
    res.append(R('l2auth', L, 'Port-Security or 802.1X on access ports', 6, sc if sc is not None else 0,
        f'{len(access)} access ports',
        'interface range <PORTS>\n switchport port-security\n switchport port-security maximum 2\n switchport port-security violation restrict\n ! or 802.1X with authentication port-control auto'))
    res.append(R('dhcpsn', L, 'DHCP Snooping', 6, (0.5 if has(r'^ip dhcp snooping$') else 0) + (0.5 if has(r'^ip dhcp snooping vlan') else 0), '',
        'ip dhcp snooping\nip dhcp snooping vlan <VLANS>\n! on uplinks: ip dhcp snooping trust'))
    res.append(R('dai', L, 'Dynamic ARP Inspection', 5, 1 if has(r'^ip arp inspection vlan') else 0, '',
        'ip arp inspection vlan <VLANS>\n! on uplinks: ip arp inspection trust'))
    unused = [(h, l) for h, l in l2 if 'shutdown' not in l and 'switchport mode trunk' not in l
              and not any(re.match(r'switchport access vlan (?!1$)\d+', x) for x in l) and not any('channel-group' in x for x in l)]
    sc = 1 - (len(unused) / len(l2)) if l2 else None
    res.append(R('unused', L, 'Unused ports not on VLAN 1 and not enabled', 4, sc, f'{len(unused)} ports: {nm(unused)}',
        'interface range <PORTS>\n description UNUSED\n switchport access vlan 999\n switchport mode access\n shutdown'))
    sw = access + trunk
    sc = ratio(sw, lambda l: 'switchport nonegotiate' in l)
    res.append(R('nonego', L, 'switchport nonegotiate', 2, sc, f'{len(sw)} ports', 'interface range <PORTS>\n switchport nonegotiate'))
    res.append(R('vtp', L, 'VTP transparent/off', 2, 1 if has(r'^vtp mode (transparent|off)') else 0,
        'VTP server/client can propagate VLANs', 'vtp mode transparent'))

    # ---- Services 15
    items = [not has(r'^service pad'), has(r'^no ip source-route'), has(r'^no ip bootp server'), not has(r'^service config')]
    res.append(R('svc', S, 'Insecure services disabled', 4, sum(items) / 4,
        'pad/source-route/bootp/config', 'no service pad\nno ip source-route\nno ip bootp server\nno service config'))
    if has(r'^no cdp run'): sc = 1
    else:
        sc = ratio(access, lambda l: 'no cdp enable' in l) or 0
    res.append(R('cdp', S, 'CDP disabled on user ports', 3, sc, '', 'interface range <ACCESS-PORTS>\n no cdp enable\n no lldp transmit\n no lldp receive'))
    res.append(R('dns', S, 'no ip domain-lookup', 1, 1 if has(r'^no ip domain[- ]lookup') else 0, '', 'no ip domain-lookup'))
    if platform == '2960X': copp = None
    else: copp = 1 if has(r'^control-plane') and has(r'^\s*service-policy input') else 0
    res.append(R('copp', S, 'CoPP', 4, copp, 'Not supported on 2960X' if copp is None else '',
        'ip access-list extended COPP-MGMT\n permit tcp <MGMT> any eq 22\nclass-map match-all CM-MGMT\n match access-group name COPP-MGMT\npolicy-map PM-COPP\n class CM-MGMT\n  police 64000 conform-action transmit exceed-action drop\ncontrol-plane\n service-policy input PM-COPP'))
    res.append(R('banner', S, 'Login banner', 1, 1 if has(r'^banner (login|motd)') else 0, '',
        'banner login ^\nAuthorized access only. Activity is logged.\n^'))
    res.append(R('ts', S, 'Timestamps and buffered logging', 2, (0.5 if has(r'^service timestamps log datetime') else 0) + (0.5 if has(r'^logging buffered') else 0), '',
        'service timestamps log datetime msec localtime show-timezone\nservice timestamps debug datetime msec\nlogging buffered 64000'))

    # ---- Maintenance 10
    cur = (re.search(r'^version (\S+)', cfg, re.M) or [0, ''])[1]
    mv = min_versions.get(platform)
    res.append(R('ios', T, 'Secure IOS version', 5, None if not mv else (1 if cur >= mv else 0),
        f'Current version {cur}' + ('' if mv else ' (minimum version not set in settings → N/A)'), 'Upgrade to the latest Cisco Gold/Suggested release'))
    res.append(R('backup', T, 'Automatic backup', 3, 1, 'This tool keeps saved copies of the config', ''))
    res.append(R('archive', T, 'Config Archive', 2, 1 if has(r'^archive') else 0, '',
        'archive\n path flash:backup-\n write-memory\n maximum 10'))
    return res

def total(results):
    ap = [r for r in results if r['score'] is not None]
    w = sum(r['weight'] for r in ap)
    return round(100 * sum(r['weight'] * r['score'] for r in ap) / w, 1) if w else 0.0
