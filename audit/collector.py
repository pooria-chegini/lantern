import re, socket

def ssh_open(ip, port=22, t=3):
    try:
        with socket.create_connection((ip, port), timeout=t): return True
    except OSError: return False

CMDS = [('config', 'show running-config', 180), ('version', 'show version', 60),
        ('ifs', 'show interfaces status', 60), ('errdis', 'show interfaces status err-disabled', 60),
        ('cdp', 'show cdp neighbors detail', 90), ('vlan', 'show vlan brief', 60),
        ('mac', 'show mac address-table dynamic', 180), ('arp', 'show ip arp', 120),
        ('counters', 'show interfaces', 180)]

def _legacy():
    """enable old kex/cipher/hostkey algorithms for old IOS (global, process-wide)."""
    import paramiko
    T = paramiko.Transport
    def add(attr, extra):
        cur = tuple(getattr(T, attr, ()))
        known = set(getattr(T, {'_preferred_kex': '_kex_info', '_preferred_ciphers': '_cipher_info',
                                '_preferred_macs': '_mac_info'}.get(attr, attr), {}) or [])
        setattr(T, attr, cur + tuple(x for x in extra if x not in cur and (not known or x in known)))
    add('_preferred_kex', ('diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1',
                           'diffie-hellman-group1-sha1'))
    add('_preferred_ciphers', ('aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'))
    add('_preferred_macs', ('hmac-sha1', 'hmac-sha1-96'))
    add('_preferred_keys', ('ssh-rsa', 'ssh-dss'))

_BAD = ('kex', 'no matching', 'incompatible ssh', 'cipher', 'host key', 'key exchange', 'negotiat')

def _connect(CH, dev):
    try:
        return CH(**dev)
    except Exception as e:
        if not any(w in str(e).lower() for w in _BAD): raise
    _legacy()
    # old IOS only offers ssh-rsa (sha1) host keys
    dev = dict(dev, disabled_algorithms=dict(pubkeys=['rsa-sha2-256', 'rsa-sha2-512']))
    return CH(**dev)

def fetch(ip, user, pw, enable=''):
    """returns dict name->output. running-config failure is fatal, the rest are best-effort."""
    from netmiko import ConnectHandler
    dev = dict(device_type='cisco_ios', host=ip, username=user, password=pw, secret=enable,
               timeout=30, conn_timeout=15, auth_timeout=25, banner_timeout=20)
    c = _connect(ConnectHandler, dev)
    out, warn = {}, []
    try:
        if enable: c.enable()
        for key, cmd, to in CMDS:
            try:
                out[key] = c.send_command(cmd, read_timeout=to)
                if key != 'config' and out[key].lstrip().startswith('%'):
                    warn.append(f'{cmd}: {out[key].strip()[:60]}'); out[key] = ''
            except Exception as e:
                if key == 'config': raise
                out[key] = ''; warn.append(f'{cmd}: {str(e)[:60]}')
    finally:
        c.disconnect()
    out['warn'] = '; '.join(warn)
    return out

def split_configs(text):
    L = text.splitlines()
    for pat in (r'^(Current configuration|Building configuration)', r'^version \d'):
        idx = [i for i, l in enumerate(L) if re.match(pat, l)]
        if len(idx) > 1:
            if pat.startswith('^version'):
                for k, v in enumerate(idx):
                    lo = idx[k-1] if k else 0
                    ch = [i for i in range(lo, v) if L[i].startswith('! Chassis type')]
                    if ch: idx[k] = ch[-1]
            idx.append(len(L))
            return ['\n'.join(L[a:b]) for a, b in zip(idx, idx[1:])]
    return [text]
