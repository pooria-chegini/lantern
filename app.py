import os, json, sqlite3, threading, ipaddress, secrets, csv, io, re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, session, redirect, url_for, render_template, abort, Response, flash
from werkzeug.security import check_password_hash, generate_password_hash
import settings
from audit import checks, collector, inventory
from core import risk

os.makedirs(settings.DATA_DIR, exist_ok=True)
DB = os.path.join(settings.DATA_DIR, 'audit.db')
app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
app.config.update(SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') == '1',
                  MAX_CONTENT_LENGTH=20 * 1024 * 1024)

from contextlib import contextmanager
@contextmanager
def db():
    c = sqlite3.connect(DB, timeout=30); c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback(); raise
    finally:
        c.close()

@app.route('/favicon.ico')
def favicon_ico():
    return redirect('/static/favicon.svg', 301)

def init():
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript(inventory.SCHEMA + '\nCREATE TABLE IF NOT EXISTS scan_groups(id INTEGER PRIMARY KEY, name TEXT UNIQUE, targets TEXT);')
    for ext in ('', '-wal', '-shm'):
        try: os.chmod(DB + ext, 0o600)
        except OSError: pass
init()

# ---------- auth / csrf
@app.before_request
def guard():
    if request.endpoint in ('login', 'static'): return
    if not session.get('u'): return redirect(url_for('login'))
    if request.method == 'POST' and not secrets.compare_digest(request.form.get('csrf', ''), session.get('csrf', 'x')):
        abort(400)

@app.context_processor
def inj():
    session.setdefault('csrf', secrets.token_hex(16))
    return dict(csrf=session['csrf'], github_url=settings.GITHUB_URL, app_name=settings.APP_NAME)

@app.template_filter('color')
def color(s):
    s = s or 0
    return '#1a9850' if s >= 90 else '#91cf60' if s >= 75 else '#fc8d59' if s >= 50 else '#d73027'

def admin_hash():
    path = os.path.join(settings.DATA_DIR, 'admin.hash')
    if os.path.exists(path):
        with open(path) as f: return f.read().strip()
    return os.environ.get('ADMIN_PASS_HASH', '')

@app.route('/password', methods=['POST'])
def password():
    cur, new, cf = request.form.get('current', ''), request.form.get('new', ''), request.form.get('confirm', '')
    if not check_password_hash(admin_hash(), cur): flash('Current password is wrong')
    elif len(new) < 8: flash('New password must be at least 8 characters')
    elif new != cf: flash('Passwords do not match')
    else:
        path = os.path.join(settings.DATA_DIR, 'admin.hash')
        with open(path, 'w') as f: f.write(generate_password_hash(new))
        os.chmod(path, 0o600); flash('Password changed.')
    return redirect('/')

@app.route('/offline')
def offline():
    return render_template('offline.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ok = request.form.get('u') == os.environ.get('ADMIN_USER', 'admin') and \
             check_password_hash(admin_hash(), request.form.get('p', ''))
        if ok:
            session.clear(); session['u'] = 1; session['csrf'] = secrets.token_hex(16)
            return redirect('/')
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear(); return redirect(url_for('login'))

# ---------- scanning
def parse_targets(text):
    hosts = []
    for t in re.split(r'[,\s]+', text.strip()):
        if not t: continue
        n = ipaddress.ip_network(t, strict=False)
        if not (n.is_private):
            raise ValueError(f'{t} is not a private range')
        if n.num_addresses > 4096: raise ValueError(f'{t} is too large')
        hosts += [str(n.network_address)] if n.num_addresses == 1 else [str(h) for h in n.hosts()]
    return list(dict.fromkeys(hosts))

def store_file(scan_id, cfg):
    host, plat, ver = checks.detect(cfg)
    res = checks.audit(cfg, plat, settings.MIN_VERSIONS)
    with db() as c:
        c.execute('INSERT INTO results(scan_id,created,ip,hostname,platform,version,score,details,config) VALUES(?,?,?,?,?,?,?,?,?)',
                  (scan_id, inventory.now(), 'file', host, plat, ver, checks.total(res), json.dumps(res), cfg))

def finish(scan_id):
    with db() as c:
        avg = c.execute('SELECT AVG(score) FROM results WHERE scan_id=? AND score IS NOT NULL', (scan_id,)).fetchone()[0]
        c.execute("UPDATE scans SET status='done', avg=? WHERE id=?", (avg, scan_id))

def work(scan_id, ip, user, pw, en):
    try:
        if not collector.ssh_open(ip): return
        with db() as c: c.execute('UPDATE scans SET found=found+1 WHERE id=?', (scan_id,))
        raw = collector.fetch(ip, user, pw, en)
        with db() as c: inventory.ingest(c, scan_id, ip, raw, settings.MIN_VERSIONS, settings.KEEP_SNAPSHOTS)
    except Exception as e:
        with db() as c:
            inventory.mark_failed(c, ip, str(e)[:300])
            c.execute('INSERT INTO results(scan_id,created,ip,error,details) VALUES(?,?,?,?,?)', (scan_id, inventory.now(), ip, str(e)[:300], '[]'))
    finally:
        with db() as c: c.execute('UPDATE scans SET done=done+1 WHERE id=?', (scan_id,))

def run(scan_id, groups):
    """groups = [(hosts, user, pw, enable), ...] ; credentials live only in memory"""
    with ThreadPoolExecutor(settings.WORKERS) as ex:
        for hosts, u, p, e in groups:
            for h in hosts: ex.submit(work, scan_id, h, u, p, e)
    finish(scan_id)

def new_scan(label, total):
    with db() as c:
        cur = c.execute('INSERT INTO scans(created,targets,status,total) VALUES(?,?,?,?)',
                        (datetime.now().strftime('%Y-%m-%d %H:%M'), label, 'running', total))
        return cur.lastrowid

@app.route('/')
def index():
    with db() as c:
        scans = c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 30').fetchall()
        groups = c.execute('SELECT * FROM scan_groups ORDER BY name').fetchall()
    return render_template('index.html', scans=scans, groups=groups)

@app.route('/groups/add', methods=['POST'])
def group_add():
    name = request.form.get('name', '').strip()[:60]
    targets = request.form.get('targets', '').strip()
    try:
        if not name: raise ValueError('group name is required')
        parse_targets(targets)
    except Exception as e:
        flash(f'Invalid group: {e}'); return redirect('/')
    with db() as c:
        try: c.execute('INSERT INTO scan_groups(name,targets) VALUES(?,?)', (name, targets))
        except sqlite3.IntegrityError: flash('A group with this name already exists'); return redirect('/')
    flash(f'Group "{name}" added.')
    return redirect('/')

@app.route('/group/<int:gid>/delete', methods=['POST'])
def group_delete(gid):
    with db() as c: c.execute('DELETE FROM scan_groups WHERE id=?', (gid,))
    flash('Group removed.')
    return redirect('/')

@app.route('/scan', methods=['POST'])
def scan():
    ids = [int(x) for x in request.form.getlist('gid') if x.isdigit()]
    user, pw, en = request.form.get('user', ''), request.form.get('pw', ''), request.form.get('en', '')
    if not ids: flash('Select at least one group'); return redirect('/')
    if not (user and pw): flash('SSH username and password are required'); return redirect('/')
    with db() as c:
        rows = c.execute(f"SELECT id,name,targets FROM scan_groups WHERE id IN ({','.join('?'*len(ids))}) ORDER BY id", ids).fetchall()
    groups, seen = [], set()
    try:
        for r in rows:
            hosts = [h for h in parse_targets(r['targets']) if h not in seen]   # first group wins
            seen.update(hosts)
            groups.append((hosts, user, pw, en))
    except Exception as e:
        flash(f'Invalid target: {e}'); return redirect('/')
    total = len(seen)
    if not total: flash('No targets'); return redirect('/')
    if total > settings.MAX_HOSTS: flash(f'More than {settings.MAX_HOSTS} addresses'); return redirect('/')
    sid = new_scan(', '.join(r['name'] for r in rows)[:200], total)
    threading.Thread(target=run, args=(sid, groups), daemon=True).start()
    return redirect(url_for('scan_view', sid=sid))

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('cfgfile')
    if not f: return redirect('/')
    parts = collector.split_configs(f.read().decode('utf-8', 'ignore'))
    sid = new_scan('upload: ' + f.filename[:80], len(parts))
    for p in parts: store_file(sid, p)
    with db() as c: c.execute('UPDATE scans SET done=total, found=total WHERE id=?', (sid,))
    finish(sid)
    return redirect(url_for('scan_view', sid=sid))

@app.route('/scan/<int:sid>')
def scan_view(sid):
    with db() as c:
        s = c.execute('SELECT * FROM scans WHERE id=?', (sid,)).fetchone() or abort(404)
        rows = c.execute('SELECT id,ip,hostname,platform,version,score,error,nprob FROM results WHERE scan_id=? ORDER BY score IS NULL, score', (sid,)).fetchall()
    return render_template('scan.html', s=s, rows=rows)

@app.route('/scan/<int:sid>.csv')
def scan_csv(sid):
    with db() as c:
        rows = c.execute('SELECT ip,hostname,platform,version,score,error FROM results WHERE scan_id=?', (sid,)).fetchall()
    o = io.StringIO(); w = csv.writer(o); w.writerow(['ip', 'hostname', 'platform', 'version', 'score', 'error'])
    for r in rows: w.writerow(list(r))
    return Response(o.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=scan{sid}.csv'})

def _stat(c, did):
    if not did: return {}
    return {r['check_id']: r['status'] for r in c.execute('SELECT check_id,status FROM check_status WHERE device_id=?', (did,))}

@app.route('/switch/<int:rid>')
def switch(rid):
    with db() as c:
        r = c.execute('SELECT * FROM results WHERE id=?', (rid,)).fetchone() or abort(404)
        st = _stat(c, r['device_id'])
    det = json.loads(r['details'])
    for d in det:
        d['sev'] = risk.severity(d['weight']); d['conf'] = risk.confidence(d['id']); d['st'] = st.get(d['id'], 'open')
    lost = sorted([d for d in det if d['score'] is not None and d['score'] < 1], key=lambda d: -d['weight'] * (1 - d['score']))
    fixes = '\n\n'.join(f"! --- {d['title']} (-{round(d['weight']*(1-d['score']),1)})\n{d['fix']}" for d in lost if d['fix'] and d['st'] not in ('false_positive', 'accepted_risk'))
    cats = {}
    for d in det:
        if d['score'] is None: continue
        a = cats.setdefault(d['cat'], [0, 0]); a[0] += d['weight'] * d['score']; a[1] += d['weight']
    return render_template('switch.html', r=r, det=det, lost=lost, fixes=fixes, statuses=risk.STATUSES,
                           eff=risk.effective(det, st), editable=bool(r['device_id']),
                           cats={k: round(100 * a / b) for k, (a, b) in cats.items()})

@app.route('/switch/<int:rid>/status', methods=['POST'])
def check_set_status(rid):
    cid, stt = request.form.get('check', ''), request.form.get('status', '')
    if stt not in dict(risk.STATUSES): abort(400)
    with db() as c:
        r = c.execute('SELECT device_id FROM results WHERE id=?', (rid,)).fetchone() or abort(404)
        if not r['device_id']: abort(400)
        c.execute('INSERT OR REPLACE INTO check_status VALUES(?,?,?,?,?)', (r['device_id'], cid, stt, request.form.get('note', '')[:200], inventory.now()))
    return redirect(url_for('switch', rid=rid))

@app.route('/switch/<int:rid>/reevaluate', methods=['POST'])
def reevaluate(rid):
    """Re-run the rules on the stored config (no switch contact)."""
    with db() as c:
        r = c.execute('SELECT config,platform FROM results WHERE id=?', (rid,)).fetchone() or abort(404)
        if not r['config']: flash('No stored config'); return redirect(url_for('switch', rid=rid))
        res = checks.audit(r['config'], r['platform'] or 'unknown', settings.MIN_VERSIONS)
        c.execute('UPDATE results SET details=?, score=? WHERE id=?', (json.dumps(res), checks.total(res), rid))
    flash('Re-evaluated with current rules.')
    return redirect(url_for('switch', rid=rid))

@app.route('/device/<int:did>/refresh', methods=['POST'])
def device_refresh(did):
    user, pw, en = request.form.get('user', ''), request.form.get('pw', ''), request.form.get('en', '')
    if not (user and pw): flash('SSH username and password are required'); return redirect(url_for('device_view', did=did))
    with db() as c:
        d = c.execute('SELECT ip FROM devices WHERE id=?', (did,)).fetchone() or abort(404)
    sid = new_scan('refresh ' + d['ip'], 1)
    threading.Thread(target=run, args=(sid, [([d['ip']], user, pw, en)]), daemon=True).start()
    return redirect(url_for('scan_view', sid=sid))

# ---------- inventory / history / search
@app.route('/devices')
def devices_view():
    with db() as c: return render_template('devices.html', devs=inventory.devices(c))

@app.route('/hardening')
def hardening():
    rows = []
    with db() as c:
        for d in inventory.devices(c):
            cats, open_n = {}, 0
            if d['last_result_id']:
                r = c.execute('SELECT details FROM results WHERE id=?', (d['last_result_id'],)).fetchone()
                try: det = json.loads(r['details'] or '[]')
                except ValueError: det = []
                st = _stat(c, d['id'])
                for x in det:
                    if x.get('score') is None: continue
                    a = cats.setdefault(x['cat'], [0, 0]); a[0] += x['weight'] * x['score']; a[1] += x['weight']
                    if x['score'] < 1 and st.get(x['id'], 'open') in ('open', 'in_progress'): open_n += 1
                eff = risk.effective(det, st) if det else None
            else: eff = None
            rows.append(dict(d=d, eff=eff, open=open_n, cats={k: round(100 * a / b) for k, (a, b) in cats.items() if b}))
    return render_template('hardening.html', rows=rows)

@app.route('/device/<int:did>')
def device_view(did):
    with db() as c: x = inventory.device_detail(c, did)
    if not x: abort(404)
    spark, imp, reg = '', [], []
    h = x['hist']
    spark = risk.sparkline([r['score'] for r in reversed(h)])
    if len(h) >= 2:
        try:
            with db() as c:
                o, n = [json.loads(c.execute('SELECT details FROM results WHERE id=?', (i,)).fetchone()[0] or '[]') for i in (h[1]['id'], h[0]['id'])]
            imp, reg = risk.compare(o, n)
        except Exception:
            app.logger.exception('history compare failed')
    return render_template('device.html', spark=spark, imp=imp, reg=reg, **x)

@app.route('/device/<int:did>/delete', methods=['POST'])
def device_delete(did):
    with db() as c:
        rids = [r[0] for r in c.execute('SELECT id FROM results WHERE device_id=?', (did,))]
        for rid in rids:
            for t in inventory.CHILD: c.execute(f'DELETE FROM {t} WHERE result_id=?', (rid,))
        c.execute('DELETE FROM results WHERE device_id=?', (did,))
        c.execute('DELETE FROM check_status WHERE device_id=?', (did,))
        c.execute('DELETE FROM devices WHERE id=?', (did,))
    flash('Device deleted.')
    return redirect('/devices')

@app.route('/vlans')
def vlans_view():
    with db() as c: return render_template('vlans.html', rows=inventory.vlan_list(c))

@app.route('/vlan/<int:vid>')
def vlan_view(vid):
    with db() as c: sw, nodes = inventory.vlan_detail(c, vid)
    return render_template('vlan.html', vid=vid, sw=sw, nodes=nodes)

@app.route('/macs')
def macs_view():
    with db() as c: rows = inventory.mac_list(c)
    return render_template('macs.html', rows=rows)

@app.route('/links')
def links_view():
    with db() as c: rows = inventory.link_list(c)
    return render_template('links.html', rows=rows)

@app.route('/problems')
def problems_view():
    with db() as c:
        rows = inventory.problems(c)
        down = c.execute("SELECT * FROM devices WHERE last_error IS NOT NULL ORDER BY hostname").fetchall()
    return render_template('problems.html', rows=rows, down=down)

@app.route('/search')
def search_view():
    q, hist = request.args.get('q', ''), request.args.get('hist') == '1'
    with db() as c: rows = inventory.search(c, q, hist) if q else []
    return render_template('search.html', q=q, hist=hist, rows=rows)

@app.template_filter('score')
def score_fmt(s):
    return '—' if s is None else f'{float(s):.1f} / 100'
