#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETHUB TRACK  -  diagnóstico de rede com interface gráfica (tema escuro)

  * MTR ao vivo ......... traceroute + ping por salto (perda, latência, jitter)   [estilo WinMTR]
  * Monitor contínuo .... timeline por salto, alertas, histórico e relatório HTML  [estilo PingPlotter]
  * Qualidade ........... latência, jitter, perda e MOS para VoIP/vídeo
  * Tráfego ............. banda por interface, conexões ativas, captura de pacotes [estilo ntopng]
  * DNS, Relatórios e Configurações

Requisitos
  - Python 3.8+ com Tkinter (já vem no Python do Windows/macOS; no Linux: sudo apt install python3-tk)
  - Opcional: psutil  (pip install psutil)  -> banda e conexões
  - Opcional: scapy   (pip install scapy)   -> captura de pacotes (admin/root; no Windows, Npcap)

Executar:   python nethub_track.py
Gerar .exe: pip install pyinstaller  &&  pyinstaller --noconsole --onefile --name "NETHUB TRACK" nethub_track.py
"""
import os
import sys
import re
import csv
import json
import math
import time
import html
import queue
import socket
import shutil
import sqlite3
import platform
import threading
import subprocess
import webbrowser
import datetime
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter import font as tkfont
except ImportError:  # pragma: no cover
    print("Tkinter não encontrado. No Linux instale com: sudo apt install python3-tk")
    sys.exit(1)

APP_NAME = "NETHUB TRACK"
VERSION = "1.0"
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
CF = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW

HOME_DIR = os.path.join(os.path.expanduser("~"), ".nethub_track")
DB_PATH = os.path.join(HOME_DIR, "history.db")
CFG_PATH = os.path.join(HOME_DIR, "config.json")
EXPORT_DIR = os.path.join(os.path.expanduser("~"), "NETHUB_TRACK_Relatorios")
BLOCKS = "▁▂▃▄▅▆▇█"

DEFAULT_CFG = {
    "interval": 1.0, "timeout": 1.0, "max_hops": 30,
    "resolve_names": True, "save_history": True,
    "alert_loss": 10.0, "alert_latency": 150.0, "alert_window": 10,
    "alert_cooldown": 60, "alert_beep": True,
}

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS/SMB", 143: "IMAP",
    161: "SNMP", 162: "SNMP-trap", 179: "BGP", 389: "LDAP", 443: "HTTPS/QUIC", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-sub", 636: "LDAPS", 853: "DNS-TLS", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1723: "PPTP", 1883: "MQTT", 3306: "MySQL", 3389: "RDP",
    3478: "STUN/VoIP", 5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT-TLS", 9200: "Elasticsearch",
    27017: "MongoDB", 51820: "WireGuard", 500: "IPsec/IKE", 4500: "IPsec-NAT", 1900: "SSDP", 5353: "mDNS",
}


# ============================================================================
#  MOTOR (sem interface)
# ============================================================================
def load_cfg():
    cfg = dict(DEFAULT_CFG)
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


def save_cfg(cfg):
    try:
        os.makedirs(HOME_DIR, exist_ok=True)
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False


def fmt_ms(v):
    if v is None:
        return "—"
    return f"{v:.0f}" if v >= 100 else f"{v:.1f}"


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_bits_rate(bytes_per_s):
    b = bytes_per_s * 8.0
    for unit in ("b/s", "Kb/s", "Mb/s", "Gb/s"):
        if b < 1000 or unit == "Gb/s":
            return f"{b:.0f} {unit}" if unit == "b/s" else f"{b:.2f} {unit}"
        b /= 1000


def ts_str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S")


class NameCache:
    """DNS reverso em segundo plano (nunca trava a interface)."""

    def __init__(self, workers=4):
        self.d, self.q, self.enabled = {}, queue.Queue(), True
        for _ in range(workers):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        while True:
            ip = self.q.get()
            try:
                self.d[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                self.d[ip] = ""

    def get(self, ip):
        if not self.enabled or not ip:
            return None
        if ip not in self.d:
            self.d[ip] = None
            self.q.put(ip)
        return self.d[ip] or None


NAMES = NameCache()


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


PING_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def ping_once(ip, timeout=1.0):
    """RTT em ms, ou None se não houve resposta. Usa o ping do sistema (sem root)."""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout + 3, creationflags=CF)
    except Exception:
        return None
    m = PING_RE.search(r.stdout or "")
    if not m:
        return None
    try:
        return float(m.group(1).replace(",", "."))
    except ValueError:
        return None


def discover_route(ip, max_hops=30, timeout=1.0, stop=None):
    """Lista [(n, ip|None)] até o destino; None se não existir ferramenta de traceroute."""
    if IS_WIN:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), ip]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(max(1, int(math.ceil(timeout)))), "-q", "1", ip]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(max_hops), ip]
    else:
        return None
    found, start = {}, time.time()
    limit = max_hops * (timeout + 1.5) + 15
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", creationflags=CF)
    except Exception:
        return None
    try:
        for line in p.stdout:
            if stop is not None and stop.is_set():
                break
            m = re.match(r"^\s*(\d+)\??:?\s+(.*)", line)
            if not m:
                continue
            n = int(m.group(1))
            ips = IP_RE.findall(m.group(2))
            addr = ips[0] if ips else None
            if n not in found or (found[n] is None and addr):
                found[n] = addr
            if addr == ip or time.time() - start > limit:
                break
    finally:
        try:
            p.kill()
        except Exception:
            pass
    route = sorted(found.items())
    while route and route[-1][1] is None:
        route.pop()
    if not route or route[-1][1] != ip:
        route.append((route[-1][0] + 1 if route else 1, ip))
    return route


class HopStats:
    def __init__(self, n, ip):
        self.n, self.ip = n, ip
        self.sent = self.recv = 0
        self.best = self.worst = self.last = None
        self.mean = self.m2 = 0.0
        self.hist = deque(maxlen=300)

    def add(self, rtt):
        self.sent += 1
        self.hist.append(rtt)
        self.last = rtt
        if rtt is None:
            return
        self.recv += 1
        self.best = rtt if self.best is None else min(self.best, rtt)
        self.worst = rtt if self.worst is None else max(self.worst, rtt)
        d = rtt - self.mean
        self.mean += d / self.recv
        self.m2 += d * (rtt - self.mean)

    @property
    def loss(self):
        return 100.0 * (self.sent - self.recv) / self.sent if self.sent else 0.0

    @property
    def avg(self):
        return self.mean if self.recv else None

    @property
    def jitter(self):
        return math.sqrt(self.m2 / (self.recv - 1)) if self.recv > 1 else 0.0


def probe_round(hops, pool, timeout):
    futs = [(h, pool.submit(ping_once, h.ip, timeout)) for h in hops if h.ip]
    out = []
    for h, f in futs:
        rtt = f.result()
        h.add(rtt)
        out.append((h, rtt))
    return out


def diagnose(hops, rounds):
    """Retorna [(nivel, texto)] com nivel em ok|warn|bad|info."""
    live = [h for h in hops if h.ip and h.sent >= 5]
    if not live or rounds < 5:
        return [("info", "Coletando dados… aguarde ao menos 5 rodadas para o diagnóstico.")]
    msgs, chain = [], None
    for i, h in enumerate(live):
        if h.loss >= 5 and all(x.loss >= 5 for x in live[i:]):
            chain = h
            break
    if chain is not None:
        if chain is live[-1] and len(live) > 1:
            msgs.append(("warn", f"Perda de {chain.loss:.0f}% só no destino ({chain.ip}): ele pode estar limitando "
                                 f"ICMP ou há instabilidade no último trecho."))
        else:
            msgs.append(("bad", f"Perda de {chain.loss:.0f}% começa no salto {chain.n} ({chain.ip}) e continua até o "
                                f"destino: problema provável nesse salto ou no enlace logo antes."))
    elif any(h.loss >= 5 for h in live):
        msgs.append(("info", "Há perda em salto intermediário que NÃO chega ao destino: em geral é só limitação de "
                             "resposta ICMP do roteador, não perda real."))
    best_jump, at, prev = 0.0, None, None
    for h in live:
        if h.avg is not None and prev is not None:
            if h.avg - prev.avg > best_jump:
                best_jump, at = h.avg - prev.avg, (prev, h)
        if h.avg is not None:
            prev = h
    dest = live[-1]
    if at and best_jump >= 50 and dest.avg is not None and dest.avg >= at[1].avg * 0.8:
        msgs.append(("warn", f"Latência sobe ~{best_jump:.0f} ms entre o salto {at[0].n} e o {at[1].n} "
                             f"({at[1].ip}) e se mantém até o destino."))
    if dest.jitter >= 30:
        msgs.append(("warn", f"Jitter alto no destino ({dest.jitter:.0f} ms): ruim para VoIP e vídeo."))
    if not msgs:
        msgs.append(("ok", "Nenhum problema evidente até agora."))
    return msgs


def check_alerts(dest, cfg, state, conn, target):
    win = list(dest.hist)[-int(cfg["alert_window"]):]
    if len(win) < int(cfg["alert_window"]):
        return None
    loss = 100.0 * win.count(None) / len(win)
    vals = [x for x in win if x is not None]
    avg = sum(vals) / len(vals) if vals else None
    msg = None
    if loss >= cfg["alert_loss"]:
        msg = f"Perda de {loss:.0f}% nas últimas {len(win)} amostras do destino"
    elif avg is not None and avg >= cfg["alert_latency"]:
        msg = f"Latência média de {avg:.0f} ms nas últimas {len(win)} amostras do destino"
    if msg and time.time() - state["last"] >= cfg["alert_cooldown"]:
        state["last"] = time.time()
        if conn is not None:
            conn.execute("INSERT INTO alerts VALUES (?,?,?)", (time.time(), target, msg))
            conn.commit()
        return msg
    return None


# ---------------- histórico / relatórios ----------------
def db_connect():
    os.makedirs(HOME_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS samples (ts REAL, target TEXT, hop INTEGER, ip TEXT, rtt REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS alerts (ts REAL, target TEXT, msg TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples ON samples(target, ts)")
    conn.commit()
    return conn


def series_stats(pts):
    vals = sorted(r for _, r in pts if r is not None)
    sent = len(pts)
    if not vals:
        return dict(sent=sent, loss=100.0 if sent else 0.0, avg=None, mn=None, mx=None, p95=None, jit=None)
    avg = sum(vals) / len(vals)
    jit = math.sqrt(sum((v - avg) ** 2 for v in vals) / (len(vals) - 1)) if len(vals) > 1 else 0.0
    return dict(sent=sent, loss=100.0 * (sent - len(vals)) / sent, avg=avg, mn=vals[0], mx=vals[-1],
                p95=vals[min(len(vals) - 1, int(len(vals) * 0.95))], jit=jit)


def svg_chart(pts, t0, t1, w=900, h=120, ymax=None):
    pl, pr, pt, pb = 50, 8, 8, 14
    ok = sorted(r for _, r in pts if r is not None)
    if ymax is None:
        ymax = max(50.0, (ok[min(len(ok) - 1, int(len(ok) * 0.99))] * 1.15) if ok else 50.0)
    span = (t1 - t0) or 1.0
    pw, ph = w - pl - pr, h - pt - pb
    bucket = max(1, math.ceil(len(pts) / pw))
    line, loss_x = [], []
    for i in range(0, len(pts), bucket):
        chunk = pts[i:i + bucket]
        x = pl + (chunk[len(chunk) // 2][0] - t0) / span * pw
        vals = [r for _, r in chunk if r is not None]
        if any(r is None for _, r in chunk):
            loss_x.append(x)
        if vals:
            line.append((x, pt + ph - min(max(vals), ymax) / ymax * ph))
    s = [f"<svg viewBox='0 0 {w} {h}' width='100%' xmlns='http://www.w3.org/2000/svg'>",
         f"<rect x='{pl}' y='{pt}' width='{pw}' height='{ph}' fill='#0f1830' stroke='#243252'/>",
         f"<text x='{pl - 6}' y='{pt + 9}' text-anchor='end' font-size='10' fill='#8e9cc0'>{ymax:.0f} ms</text>",
         f"<text x='{pl - 6}' y='{pt + ph}' text-anchor='end' font-size='10' fill='#8e9cc0'>0</text>"]
    for x in loss_x:
        s.append(f"<line x1='{x:.1f}' y1='{pt}' x2='{x:.1f}' y2='{pt + ph}' stroke='#fb7185' stroke-opacity='.5'/>")
    if len(line) > 1:
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in line)
        s.append(f"<polygon points='{line[0][0]:.1f},{pt + ph} {poly} {line[-1][0]:.1f},{pt + ph}' "
                 f"fill='#38bdf8' fill-opacity='.13'/>")
        s.append(f"<polyline points='{poly}' fill='none' stroke='#38bdf8' stroke-width='1.4'/>")
    s.append("</svg>")
    return "".join(s)


def generate_report(conn, target, since):
    rows = conn.execute("SELECT ts,hop,ip,rtt FROM samples WHERE target=? AND ts>=? ORDER BY ts",
                        (target, since)).fetchall()
    if not rows:
        return None
    hops = {}
    for ts, hop, ip, rtt in rows:
        d = hops.setdefault(hop, {"ip": ip, "pts": []})
        d["ip"] = ip or d["ip"]
        d["pts"].append((ts, rtt))
    t0, t1 = rows[0][0], rows[-1][0]
    alerts = conn.execute("SELECT ts,msg FROM alerts WHERE target=? AND ts>=? ORDER BY ts DESC LIMIT 100",
                          (target, since)).fetchall()
    dest_n = max(hops)
    ds = series_stats(hops[dest_n]["pts"])
    f = lambda v: "—" if v is None else f"{v:.1f}"
    trs, charts = [], []
    for n in sorted(hops):
        st = series_stats(hops[n]["pts"])
        ip = hops[n]["ip"]
        name = NAMES.get(ip) or ""
        cls = "bad" if st["loss"] >= 5 else ("warn" if st["loss"] > 0 else "")
        trs.append(f"<tr class='{cls}'><td>{n}</td><td>{html.escape(ip or '')}</td><td>{html.escape(name)}</td>"
                   f"<td>{st['loss']:.1f}%</td><td>{st['sent']}</td><td>{f(st['mn'])}</td><td>{f(st['avg'])}</td>"
                   f"<td>{f(st['p95'])}</td><td>{f(st['mx'])}</td><td>{f(st['jit'])}</td></tr>")
        charts.append(f"<h3>Salto {n} <span>{html.escape(ip or '')} {html.escape(name)}</span></h3>"
                      f"{svg_chart(hops[n]['pts'], t0, t1)}")
    al = "".join(f"<li><b>{ts_str(t)}</b> {html.escape(m)}</li>" for t, m in alerts) or "<li>Nenhum alerta no período.</li>"
    doc = f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NETHUB TRACK · {html.escape(target)}</title>
<style>
:root{{color-scheme:dark;font-family:'Segoe UI',system-ui,Roboto,sans-serif}}
body{{background:#0a0f1e;color:#e8eefc;max-width:1000px;margin:0 auto;padding:2rem 1rem;line-height:1.5}}
h1{{margin:.2rem 0}} h1 b{{color:#38bdf8}} h2{{margin-top:2rem;font-size:1rem;letter-spacing:.08em;color:#8e9cc0;text-transform:uppercase}}
h3{{margin:1.2rem 0 .3rem;font-size:.95rem}} h3 span{{color:#8e9cc0;font-weight:400}}
.sub{{color:#8e9cc0}} table{{border-collapse:collapse;width:100%;font-size:.88rem;background:#121a30}}
th,td{{border:1px solid #243252;padding:.4rem .6rem;text-align:right}} th{{background:#182340;color:#8e9cc0}}
td:nth-child(2),td:nth-child(3),th:nth-child(2),th:nth-child(3){{text-align:left}}
tr.warn td{{background:#fbbf2418;color:#fbbf24}} tr.bad td{{background:#fb718522;color:#fb7185}}
.cards{{display:flex;gap:.8rem;flex-wrap:wrap}}
.card{{background:#121a30;border:1px solid #243252;border-left:3px solid #38bdf8;border-radius:6px;padding:.6rem 1rem;min-width:140px}}
.card small{{color:#8e9cc0;text-transform:uppercase;font-size:.7rem;letter-spacing:.06em}} .card b{{display:block;font-size:1.5rem}}
.scroll{{overflow-x:auto}} ul{{padding-left:1.2rem}} li{{margin:.2rem 0}}
</style>
<h1>NETHUB <b>TRACK</b></h1>
<div class="sub">Relatório de rede para <b>{html.escape(target)}</b> · {ts_str(t0)} até {ts_str(t1)} · gerado em {ts_str(time.time())}</div>
<h2>Resumo do destino (salto {dest_n})</h2>
<div class="cards">
<div class="card"><small>Perda</small><b>{ds['loss']:.1f}%</b></div>
<div class="card"><small>Latência média</small><b>{f(ds['avg'])} ms</b></div>
<div class="card"><small>Percentil 95</small><b>{f(ds['p95'])} ms</b></div>
<div class="card"><small>Máxima</small><b>{f(ds['mx'])} ms</b></div>
<div class="card"><small>Jitter</small><b>{f(ds['jit'])} ms</b></div>
<div class="card"><small>Amostras</small><b>{ds['sent']}</b></div>
</div>
<h2>Saltos</h2><div class="scroll"><table>
<tr><th>#</th><th>IP</th><th>Nome</th><th>Perda</th><th>Amostras</th><th>Mín</th><th>Média</th><th>P95</th><th>Máx</th><th>Jitter</th></tr>
{''.join(trs)}</table></div>
<p class="sub">Perda em salto intermediário que não aparece nos saltos seguintes costuma ser só limitação de ICMP do roteador.</p>
<h2>Timeline por salto</h2><p class="sub">Linha azul = latência · faixas vermelhas = perda de pacotes.</p>
{''.join(charts)}
<h2>Alertas</h2><ul>{al}</ul>
</html>"""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    path = os.path.join(EXPORT_DIR, f"relatorio_{safe}_{datetime.datetime.now():%Y%m%d_%H%M%S}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def export_snapshot(hops, target, rounds, path):
    ext = os.path.splitext(path)[1].lower()
    cols = ["Salto", "Host", "IP", "Perda%", "Enviados", "Recebidos", "Melhor", "Média", "Pior", "Último", "Jitter"]
    rows = []
    for h in hops:
        rows.append([h.n, (NAMES.get(h.ip) or "") if h.ip else "(sem resposta)", h.ip or "", f"{h.loss:.1f}",
                     h.sent, h.recv, fmt_ms(h.best), fmt_ms(h.avg), fmt_ms(h.worst), fmt_ms(h.last),
                     fmt_ms(h.jitter) if h.recv > 1 else "—"])
    if ext == ".csv":
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(cols)
            w.writerows(rows)
    elif ext in (".html", ".htm"):
        trs = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
        ths = "".join(f"<th>{c}</th>" for c in cols)
        with open(path, "w", encoding="utf-8") as f:
            f.write("<!doctype html><meta charset='utf-8'><title>MTR</title><style>"
                    "body{font-family:Segoe UI,system-ui;margin:2rem;background:#0a0f1e;color:#e8eefc}"
                    "table{border-collapse:collapse}td,th{border:1px solid #243252;padding:.35rem .7rem;text-align:right}"
                    "th{background:#182340;color:#8e9cc0}td:nth-child(2),td:nth-child(3){text-align:left}</style>"
                    f"<h2>NETHUB TRACK · MTR para {html.escape(target)}</h2><p>{ts_str(time.time())} · {rounds} rodadas</p>"
                    f"<table><tr>{ths}</tr>{trs}</table>")
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"NETHUB TRACK - MTR para {target} - {ts_str(time.time())} - {rounds} rodadas\n\n")
            f.write(f"{'#':>3} {'Host':<40} {'Perda%':>7} {'Env':>5} {'Rec':>5} {'Melhor':>7} {'Média':>7} {'Pior':>7} {'Últ':>7}\n")
            for r in rows:
                f.write(f"{r[0]:>3} {(r[1] or r[2]):<40.40} {r[3]:>7} {r[4]:>5} {r[5]:>5} {r[6]:>7} {r[7]:>7} {r[8]:>7} {r[9]:>7}\n")


def estimate_mos(avg, jitter, loss):
    eff = avg + jitter * 2 + 10
    r = 93.2 - eff / 40 if eff < 160 else 93.2 - (eff - 120) / 10
    r = max(0.0, min(100.0, r - loss * 2.5))
    return max(1.0, min(4.5, 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)))


def mos_verdict(mos):
    if mos >= 4.3: return "Excelente", "ok"
    if mos >= 4.0: return "Boa", "ok"
    if mos >= 3.6: return "Aceitável", "warn"
    if mos >= 3.1: return "Ruim", "bad"
    return "Muito ruim", "bad"


# ---------------- tráfego ----------------
def get_psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def get_scapy():
    try:
        import scapy.all as sc
        return sc
    except Exception:
        return None


def read_counters():
    ps = get_psutil()
    if ps:
        return {k: (v.bytes_recv, v.bytes_sent) for k, v in ps.net_io_counters(pernic=True).items()}
    if os.path.exists("/proc/net/dev"):
        d = {}
        with open("/proc/net/dev") as f:
            for line in list(f)[2:]:
                name, data = line.split(":", 1)
                p = data.split()
                d[name.strip()] = (int(p[0]), int(p[8]))
        return d
    return None


def l7_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return str(port)


def is_admin():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def local_ips():
    ips = {"127.0.0.1"}
    ps = get_psutil()
    if ps:
        for addrs in ps.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET:
                    ips.add(a.address)
    else:
        try:
            ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
        except Exception:
            pass
    return ips


# ============================================================================
#  TEMA E COMPONENTES VISUAIS
# ============================================================================
class P:  # paleta: azul-noite com acentos ciano/violeta e texto de alto contraste
    bg = "#0a0f1e"
    side = "#0c1326"
    panel = "#121a30"
    panel2 = "#182340"
    line = "#243252"
    line2 = "#33466f"
    text = "#e8eefc"
    muted = "#9aa8cc"
    dim = "#62709a"
    accent = "#38bdf8"
    accent_dark = "#0e3b58"
    accent2 = "#a78bfa"
    ok = "#34d399"
    warn = "#fbbf24"
    bad = "#fb7185"


LEVEL_COLOR = {"ok": P.ok, "warn": P.warn, "bad": P.bad, "info": P.accent, "none": P.dim}
_FONTS = {"ui": "TkDefaultFont", "mono": "TkFixedFont"}


def init_fonts():
    fams = set(tkfont.families())
    for k, cands in (("ui", ("Segoe UI", "SF Pro Text", "Inter", "Ubuntu", "DejaVu Sans", "Helvetica")),
                     ("mono", ("Cascadia Mono", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New"))):
        for c in cands:
            if c in fams:
                _FONTS[k] = c
                break


def F(size=10, bold=False, mono=False):
    return (_FONTS["mono" if mono else "ui"], size, "bold" if bold else "normal")


def blend(a, b, t):
    ar, ag, ab = int(a[1:3], 16), int(a[3:5], 16), int(a[5:7], 16)
    br, bg_, bb = int(b[1:3], 16), int(b[3:5], 16), int(b[5:7], 16)
    return "#%02x%02x%02x" % (int(ar + (br - ar) * t), int(ag + (bg_ - ag) * t), int(ab + (bb - ab) * t))


def nice_ceil(v):
    if v <= 0:
        return 10.0
    e = 10 ** math.floor(math.log10(v))
    m = v / e
    for k in (1, 2, 2.5, 5, 10):
        if m <= k:
            return k * e
    return 10 * e


def spark_text(hist, width=28):
    items = list(hist)[-width:]
    vals = [v for v in items if v is not None]
    scale = max(100.0, max(vals)) if vals else 100.0
    return "".join("×" if v is None else BLOCKS[min(7, int(v / scale * 8))] for v in items)


def setup_style(root, scale):
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=P.panel, foreground=P.text, fieldbackground=P.panel, bordercolor=P.line)
    st.configure("Treeview", background=P.panel, fieldbackground=P.panel, foreground=P.text, borderwidth=0,
                 rowheight=int(27 * scale), font=F(10, mono=True))
    st.configure("Treeview.Heading", background=P.panel2, foreground=P.muted, relief="flat", borderwidth=0,
                 font=F(9, True), padding=(8, 7))
    st.map("Treeview", background=[("selected", P.accent_dark)], foreground=[("selected", "#ffffff")])
    st.map("Treeview.Heading", background=[("active", P.line)])
    st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    for o in ("Vertical", "Horizontal"):
        st.configure(f"{o}.TScrollbar", background=P.line, troughcolor=P.panel, bordercolor=P.panel,
                     arrowcolor=P.muted, lightcolor=P.line, darkcolor=P.line, relief="flat", gripcount=0,
                     arrowsize=int(12 * scale))
        st.map(f"{o}.TScrollbar", background=[("active", P.line2)])
    st.configure("Dark.TCombobox", fieldbackground=P.panel2, background=P.panel2, foreground=P.text,
                 arrowcolor=P.accent, bordercolor=P.line, lightcolor=P.panel2, darkcolor=P.panel2,
                 selectbackground=P.panel2, selectforeground=P.text, padding=6)
    st.map("Dark.TCombobox", fieldbackground=[("readonly", P.panel2)], foreground=[("readonly", P.text)],
           selectbackground=[("readonly", P.panel2)], bordercolor=[("focus", P.accent)])
    st.configure("Dark.Horizontal.TProgressbar", troughcolor=P.panel2, background=P.accent, bordercolor=P.panel2,
                 lightcolor=P.accent, darkcolor=P.accent, thickness=int(8 * scale))
    root.option_add("*TCombobox*Listbox.background", P.panel2)
    root.option_add("*TCombobox*Listbox.foreground", P.text)
    root.option_add("*TCombobox*Listbox.selectBackground", P.accent_dark)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
    root.option_add("*TCombobox*Listbox.font", F(10))


class Btn(tk.Label):
    KINDS = {"primary": (P.accent, "#04202e", "#6fd0fb"), "ghost": (P.panel2, P.text, P.line2),
             "danger": ("#4a1d2c", "#ffd3dc", "#6b2a3e")}

    def __init__(self, parent, text, command=None, kind="primary", **kw):
        self.kind, self.command, self.enabled = kind, command, True
        bg, fg, _ = self.KINDS[kind]
        super().__init__(parent, text=text, bg=bg, fg=fg, font=F(10, True), padx=18, pady=8, cursor="hand2", **kw)
        self.bind("<Enter>", lambda e: self._paint(True))
        self.bind("<Leave>", lambda e: self._paint(False))
        self.bind("<Button-1>", lambda e: self.command() if (self.enabled and self.command) else None)

    def _paint(self, hover):
        bg, fg, hov = self.KINDS[self.kind]
        if not self.enabled:
            self.config(bg=P.panel2, fg=P.dim, cursor="arrow")
        else:
            self.config(bg=hov if hover else bg, fg=fg, cursor="hand2")

    def set(self, text=None, kind=None, enabled=None):
        if text is not None:
            self.config(text=text)
        if kind is not None:
            self.kind = kind
        if enabled is not None:
            self.enabled = enabled
        self._paint(False)


class Field(tk.Frame):
    def __init__(self, parent, value="", width=24):
        super().__init__(parent, bg=P.line, padx=1, pady=1)
        self.e = tk.Entry(self, bg=P.panel2, fg=P.text, insertbackground=P.accent, relief="flat", font=F(11),
                          width=width, highlightthickness=0, selectbackground=P.accent_dark, selectforeground="#fff")
        self.e.pack(ipady=6, ipadx=6)
        self.e.insert(0, str(value))
        self.e.bind("<FocusIn>", lambda e: self.config(bg=P.accent))
        self.e.bind("<FocusOut>", lambda e: self.config(bg=P.line))

    def get(self):
        return self.e.get().strip()

    def set(self, v):
        self.e.delete(0, "end")
        self.e.insert(0, str(v))


class Combo(ttk.Combobox):
    def __init__(self, parent, values, value=None, width=14):
        super().__init__(parent, values=values, state="readonly", style="Dark.TCombobox", width=width, font=F(10))
        self.set(value if value is not None else values[0])


class Toggle(tk.Label):
    def __init__(self, parent, value=False):
        super().__init__(parent, font=F(10, True), cursor="hand2", padx=12, pady=5)
        self.value = bool(value)
        self.bind("<Button-1>", lambda e: self.set(not self.value))
        self.set(self.value)

    def set(self, v):
        self.value = bool(v)
        self.config(text="●  Ligado" if v else "○  Desligado", bg=P.accent_dark if v else P.panel2,
                    fg=P.accent if v else P.muted)

    def get(self):
        return self.value


class Card(tk.Frame):
    def __init__(self, parent, title, accent=P.accent):
        super().__init__(parent, bg=P.panel, highlightbackground=P.line, highlightthickness=1)
        self.bar = tk.Frame(self, bg=accent, width=3)
        self.bar.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=P.panel)
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=10)
        tk.Label(inner, text=title.upper(), bg=P.panel, fg=P.muted, font=F(8, True)).pack(anchor="w")
        self.v = tk.Label(inner, text="—", bg=P.panel, fg=P.text, font=F(19, True))
        self.v.pack(anchor="w")
        self.s = tk.Label(inner, text=" ", bg=P.panel, fg=P.dim, font=F(8))
        self.s.pack(anchor="w")

    def set(self, value, level=None, sub=None):
        col = LEVEL_COLOR.get(level, P.text) if level else P.text
        self.v.config(text=value, fg=col)
        self.bar.config(bg=LEVEL_COLOR.get(level, P.accent) if level else P.accent)
        if sub is not None:
            self.s.config(text=sub or " ")


class Panel(tk.Frame):
    def __init__(self, parent, title=None):
        super().__init__(parent, bg=P.panel, highlightbackground=P.line, highlightthickness=1)
        self.hdr = None
        if title:
            self.hdr = tk.Frame(self, bg=P.panel)
            self.hdr.pack(fill="x", padx=14, pady=(10, 2))
            tk.Label(self.hdr, text=title.upper(), font=F(8, True), fg=P.muted, bg=P.panel).pack(side="left")
        self.body = tk.Frame(self, bg=P.panel)
        self.body.pack(fill="both", expand=True, padx=1, pady=(4, 1))


class ListPanel(tk.Frame):
    """Lista de mensagens com marcador colorido por nível."""

    def __init__(self, parent, empty="Sem itens", wrap=330):
        super().__init__(parent, bg=P.panel)
        self.empty, self.wrap, self._sig = empty, wrap, None
        self.set([])

    def set(self, items):
        sig = tuple(items)
        if sig == self._sig:
            return
        self._sig = sig
        for w in self.winfo_children():
            w.destroy()
        if not items:
            tk.Label(self, text=self.empty, bg=P.panel, fg=P.dim, font=F(9), anchor="w").pack(fill="x", padx=14, pady=4)
        for lvl, txt in items:
            row = tk.Frame(self, bg=P.panel)
            row.pack(fill="x", padx=14, pady=3)
            tk.Label(row, text="●", fg=LEVEL_COLOR.get(lvl, P.accent), bg=P.panel, font=F(8)).pack(side="left", anchor="n", pady=3)
            tk.Label(row, text=txt, fg=P.text, bg=P.panel, font=F(9), justify="left", anchor="w",
                     wraplength=self.wrap).pack(side="left", padx=(8, 0), fill="x")


def make_tree(parent, cols, height=8):
    """cols: (id, titulo, largura, ancoragem[, stretch])"""
    wrap = tk.Frame(parent, bg=P.panel)
    tree = ttk.Treeview(wrap, columns=[c[0] for c in cols], show="headings", height=height, selectmode="browse")
    for c in cols:
        cid, text, w, anc = c[:4]
        tree.heading(cid, text=text, anchor=anc)
        tree.column(cid, width=w, minwidth=40, anchor=anc, stretch=(len(c) > 4 and c[4]))
    sb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tree.tag_configure("ok", foreground=P.text)
    tree.tag_configure("warn", foreground=P.warn)
    tree.tag_configure("bad", foreground=P.bad)
    tree.tag_configure("none", foreground=P.dim)
    tree.tag_configure("odd", background=blend(P.panel, P.panel2, 0.55))
    return wrap, tree


def sync_tree(tree, rows):
    """Atualiza a tabela no lugar (sem perder rolagem/seleção). rows: [(iid, values, tags)]"""
    want = {r[0] for r in rows}
    have = set(tree.get_children())
    for iid in have - want:
        tree.delete(iid)
    for i, (iid, vals, tags) in enumerate(rows):
        tags = tuple(tags) + (("odd",) if i % 2 else ())
        if iid in have:
            tree.item(iid, values=vals, tags=tags)
            if tree.index(iid) != i:
                tree.move(iid, "", i)
        else:
            tree.insert("", i, iid=iid, values=vals, tags=tags)


class LineChart(tk.Canvas):
    """Gráfico de linhas com área, grade, marcas de perda e dica ao passar o mouse."""

    def __init__(self, parent, height=200, mini=False, y_fmt=None, bg=None):
        self.bgc = bg or P.panel
        super().__init__(parent, bg=self.bgc, highlightthickness=0, height=height)
        self.mini, self.y_fmt = mini, y_fmt or (lambda v: f"{v:.0f}")
        self.series, self.ymax, self.title, self._xs = [], None, "", []
        self._pl = self._pr = self._pt = self._pb = 0
        self.bind("<Configure>", lambda e: self.redraw())
        self.bind("<Motion>", self._hover)
        self.bind("<Leave>", lambda e: self.delete("hover"))

    def set(self, series, ymax=None, title=None):
        self.series, self.ymax = series, ymax
        if title is not None:
            self.title = title
        self.redraw()

    def redraw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 20 or h < 20:
            return
        m = self.mini
        pl, pr, pt, pb = (6, 6, 6, 6) if m else (58, 16, 30, 22)
        self._pl, self._pr, self._pt, self._pb = pl, pr, pt, pb
        n = max([len(s["values"]) for s in self.series] + [0])
        vals = [v for s in self.series for v in s["values"] if v is not None]
        ymax = self.ymax or nice_ceil((max(vals) if vals else 10) * 1.12)
        pw, ph = w - pl - pr, h - pt - pb
        base = pt + ph
        if not m:
            for i in range(5):
                y = base - ph * i / 4
                self.create_line(pl, y, w - pr, y, fill=P.line if i else P.line2)
                self.create_text(pl - 8, y, text=self.y_fmt(ymax * i / 4), anchor="e", fill=P.dim, font=F(8))
            if self.title:
                self.create_text(pl, 14, text=self.title, anchor="w", fill=P.muted, font=F(9, True))
        self._xs = [pl + (i / max(n - 1, 1)) * pw for i in range(n)]
        if n == 0:
            if not m:
                self.create_text(w / 2, h / 2, text="Aguardando dados…", fill=P.dim, font=F(10))
            return
        for s in self.series:
            vs, col = s["values"], s["color"]
            off = n - len(vs)
            seg = []

            def flush():
                if len(seg) > 1:
                    flat = [c for p in seg for c in p]
                    if s.get("fill", True):
                        self.create_polygon([seg[0][0], base] + flat + [seg[-1][0], base],
                                            fill=blend(self.bgc, col, 0.16), outline="")
                    self.create_line(*flat, fill=col, width=2 if not m else 1.6, joinstyle="round")
                elif len(seg) == 1:
                    x, y = seg[0]
                    self.create_oval(x - 2, y - 2, x + 2, y + 2, fill=col, outline="")
                seg.clear()

            for i, v in enumerate(vs):
                x = self._xs[i + off]
                if v is None:
                    flush()
                    if s.get("loss"):
                        self.create_rectangle(x - 1.5, base - 16, x + 1.5, base, fill=P.bad, outline="")
                else:
                    seg.append((x, base - min(v, ymax) / ymax * ph))
            last = seg[-1] if seg else None
            flush()
            if last and not m:
                self.create_oval(last[0] - 4, last[1] - 4, last[0] + 4, last[1] + 4, fill=col, outline=self.bgc, width=2)

    def _hover(self, e):
        self.delete("hover")
        n, w, h = len(self._xs), self.winfo_width(), self.winfo_height()
        if self.mini or n == 0 or not (self._pl <= e.x <= w - self._pr):
            return
        pw = max(1, w - self._pl - self._pr)
        i = min(n - 1, max(0, round((e.x - self._pl) / pw * (n - 1)))) if n > 1 else 0
        x = self._xs[i]
        self.create_line(x, self._pt, x, h - self._pb, fill=P.dim, dash=(3, 3), tags="hover")
        lines = []
        for s in self.series:
            vs = s["values"]
            j = i - (n - len(vs))
            if 0 <= j < len(vs):
                v = vs[j]
                lines.append((s["color"], (s.get("name", "") + "  " if s.get("name") else "") +
                              (self.y_fmt(v) if v is not None else "perda")))
        if not lines:
            return
        y0, tx = self._pt + 4, x + 12
        ids = []
        for k, (col, txt) in enumerate(lines):
            ids.append(self.create_text(tx + 8, y0 + 6 + k * 16, text=txt, anchor="w", fill=P.text, font=F(9, True), tags="hover"))
        bx = self.bbox(*ids)
        if bx[2] + 8 > w:
            shift = (bx[2] - bx[0]) + 32
            for t in ids:
                self.move(t, -shift, 0)
            bx = self.bbox(*ids)
        r = self.create_rectangle(bx[0] - 8, bx[1] - 4, bx[2] + 6, bx[3] + 4, fill=P.panel2, outline=P.line2, tags="hover")
        self.tag_lower(r, ids[0])
        for k, (col, _) in enumerate(lines):
            self.create_oval(bx[0] - 3, y0 + 2 + k * 16, bx[0] + 3, y0 + 8 + k * 16, fill=col, outline="", tags="hover")


class Gauge(tk.Canvas):
    def __init__(self, parent, size=230):
        super().__init__(parent, bg=P.panel, highlightthickness=0, width=size, height=int(size * 0.66))
        self.size = size
        self.set(None, "", "none")

    def set(self, mos, verdict, level):
        self.delete("all")
        s = self.size
        pad = 22
        box = (pad, pad, s - pad, s - pad)
        self.create_arc(*box, start=180, extent=-180, style="arc", outline=P.line, width=16)
        col = LEVEL_COLOR.get(level, P.dim)
        if mos is not None:
            frac = max(0.0, min(1.0, (mos - 1) / 3.5))
            self.create_arc(*box, start=180, extent=-180 * frac, style="arc", outline=col, width=16)
        cx, cy = s / 2, s / 2 - 6
        self.create_text(cx, cy - 18, text=f"{mos:.2f}" if mos is not None else "—", fill=P.text, font=F(26, True))
        self.create_text(cx, cy + 14, text=verdict or "MOS estimado", fill=col if mos is not None else P.dim, font=F(11, True))
        self.create_text(pad + 8, s - pad + 8, text="1", fill=P.dim, font=F(8))
        self.create_text(s - pad - 8, s - pad + 8, text="4.5", fill=P.dim, font=F(8))


class BarList(tk.Canvas):
    def __init__(self, parent, row_h=30, color=P.accent):
        super().__init__(parent, bg=P.panel, highlightthickness=0, height=row_h)
        self.row_h, self.color, self.items = row_h, color, []
        self.bind("<Configure>", lambda e: self.redraw())

    def set(self, items):
        self.items = items
        self.config(height=max(self.row_h, self.row_h * len(items)))
        self.redraw()

    def redraw(self):
        self.delete("all")
        w = self.winfo_width()
        if w < 50:
            return
        lw, rw = 170, 110
        for i, (label, frac, right) in enumerate(self.items):
            y = i * self.row_h + self.row_h / 2
            self.create_text(14, y, text=label, anchor="w", fill=P.text, font=F(9))
            x0, x1 = lw, w - rw
            self.create_rectangle(x0, y - 5, x1, y + 5, fill=P.panel2, outline="")
            if frac > 0:
                self.create_rectangle(x0, y - 5, x0 + max(3, (x1 - x0) * min(1, frac)), y + 5, fill=self.color, outline="")
            self.create_text(w - 14, y, text=right, anchor="e", fill=P.muted, font=F(9, mono=True))


# ============================================================================
#  PÁGINAS
# ============================================================================
PADX = 28


class Page(tk.Frame):
    def __init__(self, app):
        super().__init__(app.content, bg=P.bg)
        self.app = app
        self.q = queue.Queue()

    def header(self, title, subtitle):
        f = tk.Frame(self, bg=P.bg)
        f.pack(fill="x", padx=PADX, pady=(22, 14))
        left = tk.Frame(f, bg=P.bg)
        left.pack(side="left")
        tk.Label(left, text=title, font=F(21, True), fg=P.text, bg=P.bg).pack(anchor="w")
        tk.Label(left, text=subtitle, font=F(10), fg=P.muted, bg=P.bg).pack(anchor="w", pady=(2, 0))
        right = tk.Frame(f, bg=P.bg)
        right.pack(side="right")
        return right

    def label(self, parent, text, **kw):
        return tk.Label(parent, text=text, bg=kw.pop("bg", P.bg), fg=kw.pop("fg", P.muted), font=kw.pop("font", F(9, True)), **kw)

    def on_show(self): pass
    def on_hide(self): pass
    def shutdown(self): pass
    def visible(self): return self.winfo_ismapped()


def grid_cards(parent, specs):
    """specs: [(chave, titulo, cor)] -> dict de Cards em uma linha uniforme."""
    row = tk.Frame(parent, bg=P.bg)
    row.pack(fill="x", padx=PADX, pady=(0, 14))
    out = {}
    for i, (key, title, col) in enumerate(specs):
        row.grid_columnconfigure(i, weight=1, uniform="c")
        c = Card(row, title, col)
        c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
        out[key] = c
    return out


# ----------------------------------------------------------------------------
#  MTR ao vivo  /  Monitor contínuo
# ----------------------------------------------------------------------------
class TracePage(Page):
    COLS = [("n", "#", 44, "center"), ("host", "Host", 230, "w", True), ("ip", "IP", 120, "w"),
            ("loss", "Perda %", 74, "e"), ("sent", "Env", 56, "e"), ("recv", "Rec", 56, "e"),
            ("best", "Melhor", 70, "e"), ("avg", "Média", 70, "e"), ("worst", "Pior", 70, "e"),
            ("last", "Últ", 64, "e"), ("jit", "Jitter", 64, "e"), ("tl", "Timeline  (× = perda)", 250, "w")]

    def __init__(self, app, mode):
        super().__init__(app)
        self.mode = mode
        self.hops, self.ip, self.rounds, self.t_start = [], None, 0, 0.0
        self.running, self.stop_evt, self.sel, self.target_run = False, None, None, ""
        self._alert_items, self._diag_sig = [], None
        mtr = mode == "mtr"
        act = self.header("MTR ao vivo" if mtr else "Monitor contínuo",
                          "Traceroute + ping em cada salto, com perda, latência e jitter em tempo real." if mtr else
                          "Monitora cada salto continuamente, grava o histórico e dispara alertas.")
        self.status = tk.Label(act, text="Pronto", font=F(10), fg=P.muted, bg=P.bg)
        self.status.pack(side="right")

        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 14))
        self.label(ctl, "DESTINO").pack(side="left", padx=(0, 10))
        self.target = Field(ctl, "8.8.8.8", width=30)
        self.target.pack(side="left")
        self.target.e.bind("<Return>", lambda e: self.toggle())
        self.btn = Btn(ctl, "▶  Iniciar", self.toggle)
        self.btn.pack(side="left", padx=12)
        self.btn2 = Btn(ctl, "Exportar resultado" if mtr else "Gerar relatório", self.export if mtr else self.report, kind="ghost")
        self.btn2.pack(side="left")

        self.cards = grid_cards(self, [("loss", "Perda no destino", P.ok), ("avg", "Latência média", P.accent),
                                       ("jit", "Jitter", P.accent2), ("hops", "Saltos", P.dim), ("rounds", "Rodadas", P.dim)])

        main = tk.Frame(self, bg=P.bg)
        main.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        main.grid_rowconfigure(0, weight=3)
        main.grid_rowconfigure(1, weight=2, minsize=230)
        main.grid_columnconfigure(0, weight=1)

        tp = Panel(main, "Saltos até o destino")
        tp.grid(row=0, column=0, sticky="nsew", pady=(0, 12))
        wrap, self.tree = make_tree(tp.body, self.COLS, height=7)
        wrap.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        bottom = tk.Frame(main, bg=P.bg)
        bottom.grid(row=1, column=0, sticky="nsew")
        bottom.grid_rowconfigure(0, weight=1)
        bottom.grid_columnconfigure(0, weight=1)
        cp = Panel(bottom, "Timeline do salto selecionado  (clique numa linha da tabela)")
        cp.grid(row=0, column=0, sticky="nsew")
        self.chart = LineChart(cp.body, y_fmt=lambda v: f"{v:.0f} ms")
        self.chart.pack(fill="both", expand=True, padx=6, pady=4)
        side = tk.Frame(bottom, bg=P.bg, width=370)
        side.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        side.grid_propagate(False)
        dp = Panel(side, "Diagnóstico automático")
        dp.pack(fill="both", expand=True)
        self.diag = ListPanel(dp.body, "Inicie para ver o diagnóstico.", wrap=310)
        self.diag.pack(fill="x", pady=(2, 8))
        if not mtr:
            ap = Panel(side, "Alertas")
            ap.pack(fill="both", expand=True, pady=(12, 0))
            self.alerts = ListPanel(ap.body, "Nenhum alerta disparado.", wrap=310)
            self.alerts.pack(fill="x", pady=(2, 8))
        self._pump()

    # ---- ações ----
    def launch(self, target):
        self.target.set(target)
        if not self.running:
            self.toggle()

    def toggle(self):
        if self.running:
            self.stop_evt.set()
            self.btn.set("Parando…", enabled=False)
            return
        target = self.target.get()
        if not target:
            messagebox.showinfo(APP_NAME, "Informe um host ou IP de destino.")
            return
        self.hops, self.ip, self.rounds, self.sel = [], None, 0, None
        self.tree.delete(*self.tree.get_children())
        self.chart.set([], title="")
        self._alert_items = []
        self.t_start, self.target_run = time.time(), target
        self.stop_evt = threading.Event()
        self.running = True
        self.btn.set("■  Parar", kind="danger")
        self.status.config(text="Iniciando…", fg=P.accent)
        self.app.set_status(f"{'MTR' if self.mode == 'mtr' else 'Monitor'} em execução: {target}", P.accent)
        threading.Thread(target=self._work, args=(target, dict(self.app.cfg), self.stop_evt), daemon=True).start()

    def _work(self, target, cfg, stop):
        q = self.q
        pool = conn = None
        try:
            ip = resolve_host(target)
            if not ip:
                q.put(("error", f"Não foi possível resolver “{target}”."))
                return
            q.put(("status", f"Descobrindo a rota até {ip}…"))
            route = discover_route(ip, int(cfg["max_hops"]), cfg["timeout"], stop)
            if route is None:
                q.put(("error", "Nenhuma ferramenta de traceroute encontrada (tracert / traceroute / tracepath)."))
                return
            if stop.is_set():
                return
            hops = [HopStats(n, a) for n, a in route]
            q.put(("route", hops, ip))
            pool = ThreadPoolExecutor(max_workers=max(4, len(hops)))
            monitor = self.mode == "monitor"
            conn = db_connect() if (monitor and cfg["save_history"]) else None
            state, rounds = {"last": 0.0}, 0
            while not stop.is_set():
                t0 = time.time()
                results = probe_round(hops, pool, cfg["timeout"])
                rounds += 1
                self.rounds = rounds
                if conn is not None:
                    conn.executemany("INSERT INTO samples VALUES (?,?,?,?,?)",
                                     [(t0, target, h.n, h.ip, rtt) for h, rtt in results])
                    conn.commit()
                if monitor:
                    msg = check_alerts(hops[-1], cfg, state, conn, target)
                    if msg:
                        q.put(("alert", msg))
                stop.wait(max(0.0, cfg["interval"] - (time.time() - t0)))
        except Exception as e:  # noqa
            q.put(("error", f"Erro: {e}"))
        finally:
            if pool:
                pool.shutdown(wait=False, cancel_futures=True)
            if conn:
                conn.close()
            q.put(("done",))

    def export(self):
        if not self.hops:
            messagebox.showinfo(APP_NAME, "Execute um MTR antes de exportar.")
            return
        os.makedirs(EXPORT_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", self.target_run)
        path = filedialog.asksaveasfilename(
            title="Exportar resultado", initialdir=EXPORT_DIR, initialfile=f"mtr_{safe}.html", defaultextension=".html",
            filetypes=[("Página HTML", "*.html"), ("Planilha CSV", "*.csv"), ("Texto", "*.txt")])
        if path:
            export_snapshot(self.hops, self.target_run, self.rounds, path)
            self.app.set_status(f"Exportado: {path}", P.ok)

    def report(self):
        if not self.app.cfg["save_history"]:
            messagebox.showinfo(APP_NAME, "O histórico está desligado em Configurações.")
            return
        target = self.target_run or self.target.get()
        conn = db_connect()
        path = generate_report(conn, target, self.t_start - 5 if self.t_start else 0)
        conn.close()
        if not path:
            messagebox.showinfo(APP_NAME, "Ainda não há amostras gravadas para este alvo.")
            return
        self.app.set_status(f"Relatório gerado: {path}", P.ok)
        webbrowser.open("file://" + os.path.abspath(path))

    # ---- atualização da interface ----
    def _on_select(self, _=None):
        s = self.tree.selection()
        self.sel = int(s[0]) if s else None
        self._refresh()

    def _pump(self):
        try:
            while True:
                ev = self.q.get_nowait()
                k = ev[0]
                if k == "status":
                    self.status.config(text=ev[1], fg=P.accent)
                elif k == "route":
                    self.hops, self.ip = ev[1], ev[2]
                    self.status.config(text=f"Monitorando {self.target_run} ({self.ip})", fg=P.ok)
                elif k == "alert":
                    self._alert_items.insert(0, ("bad", f"{datetime.datetime.now():%H:%M:%S}  {ev[1]}"))
                    del self._alert_items[8:]
                    if self.app.cfg["alert_beep"]:
                        self.bell()
                    self.app.set_status("Alerta: " + ev[1], P.bad)
                elif k == "error":
                    self.status.config(text=ev[1], fg=P.bad)
                    self.app.set_status(ev[1], P.bad)
                elif k == "done":
                    self.running = False
                    self.btn.set("▶  Iniciar", kind="primary", enabled=True)
                    if not self.status.cget("fg") == P.bad:
                        self.status.config(text="Parado", fg=P.muted)
                    self.app.set_status("Pronto", P.ok)
        except queue.Empty:
            pass
        if self.visible():
            self._refresh()
        self.after(450, self._pump)

    def _refresh(self):
        hops = self.hops
        if not hops:
            return
        rows = []
        for h in hops:
            if not h.ip:
                rows.append((str(h.n), (h.n, "(sem resposta)", "—", "—", "—", "—", "—", "—", "—", "—", "—", ""), ("none",)))
                continue
            sev = "bad" if (h.loss >= 5 or (h.avg or 0) >= 150) else \
                  "warn" if (h.loss > 0 or (h.avg or 0) >= 60) else "ok"
            rows.append((str(h.n), (h.n, NAMES.get(h.ip) or h.ip, h.ip, f"{h.loss:.1f}", h.sent, h.recv, fmt_ms(h.best),
                                    fmt_ms(h.avg), fmt_ms(h.worst), fmt_ms(h.last),
                                    fmt_ms(h.jitter) if h.recv > 1 else "—", spark_text(h.hist, 30)), (sev,)))
        sync_tree(self.tree, rows)
        d = hops[-1]
        lv = "bad" if d.loss >= 5 else "warn" if d.loss > 0 else "ok"
        self.cards["loss"].set(f"{d.loss:.1f}%", lv, f"{d.sent - d.recv} de {d.sent} pacotes perdidos")
        la = None if d.avg is None else ("bad" if d.avg >= 150 else "warn" if d.avg >= 60 else "ok")
        self.cards["avg"].set(f"{fmt_ms(d.avg)} ms", la, f"melhor {fmt_ms(d.best)} · pior {fmt_ms(d.worst)} ms")
        self.cards["jit"].set(f"{fmt_ms(d.jitter) if d.recv > 1 else '—'} ms", "warn" if d.jitter >= 30 else None, "desvio padrão da latência")
        self.cards["hops"].set(str(len(hops)), None, f"{sum(1 for h in hops if h.ip)} com resposta")
        el = int(time.time() - self.t_start) if self.running else 0
        self.cards["rounds"].set(str(self.rounds), None, f"{el // 60:02d}:{el % 60:02d} em execução" if self.running else "parado")
        sel = next((h for h in hops if h.n == self.sel and h.ip), None) or (d if d.ip else None)
        if sel:
            self.chart.set([dict(values=list(sel.hist), color=P.accent, loss=True)],
                           title=f"Salto {sel.n} · {NAMES.get(sel.ip) or sel.ip}   latência por pacote")
        self.diag.set(diagnose(hops, self.rounds))
        if self.mode == "monitor":
            self.alerts.set(self._alert_items)

    def shutdown(self):
        if self.stop_evt:
            self.stop_evt.set()


# ----------------------------------------------------------------------------
#  Qualidade (VoIP / MOS)
# ----------------------------------------------------------------------------
class QualityPage(Page):
    def __init__(self, app):
        super().__init__(app)
        self.running, self.stop_evt, self.vals, self.total = False, None, [], 20
        self.header("Qualidade da conexão", "Mede latência, jitter e perda e estima a nota MOS para chamadas de voz e vídeo.")
        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 10))
        self.label(ctl, "DESTINO").pack(side="left", padx=(0, 10))
        self.target = Field(ctl, "8.8.8.8", width=28)
        self.target.pack(side="left")
        self.target.e.bind("<Return>", lambda e: self.toggle())
        self.label(ctl, "PACOTES").pack(side="left", padx=(18, 10))
        self.count = Combo(ctl, ["10", "20", "50", "100"], "20", width=6)
        self.count.pack(side="left")
        self.btn = Btn(ctl, "▶  Iniciar teste", self.toggle)
        self.btn.pack(side="left", padx=14)
        self.prog = ttk.Progressbar(self, style="Dark.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.prog.pack(fill="x", padx=PADX, pady=(0, 14))

        body = tk.Frame(self, bg=P.bg)
        body.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=0, minsize=330)
        body.grid_rowconfigure(0, weight=1)
        left = tk.Frame(body, bg=P.bg)
        left.grid(row=0, column=0, sticky="nsew")
        cr = tk.Frame(left, bg=P.bg)
        cr.pack(fill="x", pady=(0, 12))
        self.cards = {}
        for i, (k, t, col) in enumerate([("loss", "Perda", P.ok), ("avg", "Latência média", P.accent),
                                         ("rng", "Mín / Máx", P.dim), ("jit", "Jitter", P.accent2)]):
            cr.grid_columnconfigure(i, weight=1, uniform="q")
            c = Card(cr, t, col)
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            self.cards[k] = c
        cp = Panel(left, "Latência por pacote")
        cp.pack(fill="both", expand=True)
        self.chart = LineChart(cp.body, y_fmt=lambda v: f"{v:.0f} ms")
        self.chart.pack(fill="both", expand=True, padx=6, pady=4)
        right = tk.Frame(body, bg=P.bg)
        right.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        gp = Panel(right, "Qualidade estimada (MOS)")
        gp.pack(fill="x")
        self.gauge = Gauge(gp.body, 260)
        self.gauge.pack(pady=(8, 6))
        npn = Panel(right, "Interpretação")
        npn.pack(fill="both", expand=True, pady=(12, 0))
        self.notes = ListPanel(npn.body, "Execute o teste para ver a interpretação.", wrap=290)
        self.notes.pack(fill="x", pady=(2, 8))
        self._pump()

    def toggle(self):
        if self.running:
            self.stop_evt.set()
            return
        target = self.target.get()
        if not target:
            return
        self.total, self.vals = int(self.count.get()), []
        self.chart.set([], title="")
        self.prog["value"] = 0
        self.gauge.set(None, "", "none")
        self.notes.set([])
        self.stop_evt = threading.Event()
        self.running = True
        self.btn.set("■  Parar", kind="danger")
        threading.Thread(target=self._work, args=(target, self.total, self.app.cfg["timeout"], self.stop_evt), daemon=True).start()

    def _work(self, target, n, timeout, stop):
        ip = resolve_host(target)
        if not ip:
            self.q.put(("error", f"Não foi possível resolver “{target}”."))
            self.q.put(("end",))
            return
        for i in range(n):
            if stop.is_set():
                break
            self.q.put(("p", ping_once(ip, timeout)))
            stop.wait(0.2)
        self.q.put(("end",))

    def _pump(self):
        changed = False
        try:
            while True:
                ev = self.q.get_nowait()
                if ev[0] == "p":
                    self.vals.append(ev[1])
                    changed = True
                elif ev[0] == "error":
                    self.notes.set([("bad", ev[1])])
                elif ev[0] == "end":
                    self.running = False
                    self.btn.set("▶  Iniciar teste", kind="primary")
                    self._finish()
        except queue.Empty:
            pass
        if changed:
            self.prog["value"] = 100.0 * len(self.vals) / max(1, self.total)
            self._update()
        self.after(150, self._pump)

    def _stats(self):
        ok = [v for v in self.vals if v is not None]
        loss = 100.0 * (len(self.vals) - len(ok)) / len(self.vals) if self.vals else 0.0
        avg = sum(ok) / len(ok) if ok else None
        jit = (sum(abs(ok[i] - ok[i - 1]) for i in range(1, len(ok))) / (len(ok) - 1)) if len(ok) > 1 else 0.0
        return ok, loss, avg, jit

    def _update(self):
        ok, loss, avg, jit = self._stats()
        self.chart.set([dict(values=list(self.vals), color=P.accent, loss=True)])
        self.cards["loss"].set(f"{loss:.1f}%", "bad" if loss >= 5 else "warn" if loss > 0 else "ok", f"{len(self.vals)} pacotes enviados")
        if ok:
            self.cards["avg"].set(f"{avg:.1f} ms", "bad" if avg >= 150 else "warn" if avg >= 60 else "ok")
            self.cards["rng"].set(f"{min(ok):.0f} / {max(ok):.0f} ms")
            self.cards["jit"].set(f"{jit:.1f} ms", "warn" if jit >= 30 else "ok", "variação média entre pacotes")

    def _finish(self):
        ok, loss, avg, jit = self._stats()
        if not self.vals:
            return
        if not ok:
            self.notes.set([("bad", "100% de perda: o destino não respondeu (ou bloqueia ICMP).")])
            return
        mos = estimate_mos(avg, jit, loss)
        verdict, lvl = mos_verdict(mos)
        self.gauge.set(mos, verdict, lvl)
        notes = []
        notes.append((lvl, f"Qualidade {verdict.lower()} para chamadas de voz e vídeo (MOS {mos:.2f})."))
        if loss >= 1:
            notes.append(("bad" if loss >= 5 else "warn", f"Perda de {loss:.1f}%: causa picotes e cortes de áudio."))
        if jit >= 30:
            notes.append(("warn", f"Jitter de {jit:.0f} ms: acima de 30 ms prejudica VoIP."))
        if avg >= 150:
            notes.append(("warn", f"Latência média de {avg:.0f} ms: acima de 150 ms a conversa fica atrasada."))
        if len(notes) == 1 and lvl == "ok":
            notes.append(("info", "Perda, jitter e latência dentro dos limites recomendados."))
        notes.append(("info", "MOS calculado por modelo E simplificado: serve como referência."))
        self.notes.set(notes)
        self.app.set_status(f"Teste concluído: MOS {mos:.2f} ({verdict})", P.ok)

    def shutdown(self):
        if self.stop_evt:
            self.stop_evt.set()


# ----------------------------------------------------------------------------
#  Tráfego (estilo ntopng): banda, conexões, captura
# ----------------------------------------------------------------------------
def missing_module(parent, name, pip, extra=""):
    f = tk.Frame(parent, bg=P.panel)
    f.pack(fill="both", expand=True)
    tk.Label(f, text=f"Módulo {name} não encontrado", font=F(15, True), fg=P.warn, bg=P.panel).pack(pady=(60, 6))
    tk.Label(f, text=f"Este recurso usa o {name}. Instale com:", font=F(10), fg=P.muted, bg=P.panel).pack()
    tk.Label(f, text=f"  pip install {pip}  ", font=F(12, True, True), fg=P.accent, bg=P.panel2).pack(pady=10, ipady=6)
    if extra:
        tk.Label(f, text=extra, font=F(9), fg=P.dim, bg=P.panel, justify="center").pack()
    tk.Label(f, text="Depois feche e abra o NETHUB TRACK novamente.", font=F(9), fg=P.dim, bg=P.panel).pack(pady=(14, 0))


class BandwidthView(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=P.bg)
        self.app, self.job, self.prev, self.tprev = app, None, None, 0.0
        self.peak, self.down, self.up = defaultdict(float), deque(maxlen=90), deque(maxlen=90)
        self.peak_d = 0.0
        if read_counters() is None:
            missing_module(self, "psutil", "psutil")
            self.ok = False
            return
        self.ok = True
        self.cards = grid_cards(self, [("d", "Download agora", P.accent), ("u", "Upload agora", P.accent2),
                                       ("pk", "Pico de download", P.warn), ("tot", "Volume desde o início", P.dim)])
        cp = Panel(self, "Tráfego total (últimos 90 s)")
        cp.pack(fill="x", padx=PADX, pady=(0, 12))
        tk.Label(cp.hdr, text="●", fg=P.accent, bg=P.panel, font=F(9)).pack(side="right")
        tk.Label(cp.hdr, text=" Download   ", fg=P.muted, bg=P.panel, font=F(9)).pack(side="right")
        tk.Label(cp.hdr, text="●", fg=P.accent2, bg=P.panel, font=F(9)).pack(side="right", padx=(0, 0))
        tk.Label(cp.hdr, text=" Upload   ", fg=P.muted, bg=P.panel, font=F(9)).pack(side="right")
        self.chart = LineChart(cp.body, height=210, y_fmt=lambda v: fmt_bits_rate(v))
        self.chart.pack(fill="x", padx=6, pady=4)
        tp = Panel(self, "Interfaces")
        tp.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        wrap, self.tree = make_tree(tp.body, [("if", "Interface", 220, "w", True), ("d", "↓ Download", 110, "e"),
                                               ("u", "↑ Upload", 110, "e"), ("pk", "Pico", 110, "e"),
                                               ("td", "Total ↓", 100, "e"), ("tu", "Total ↑", 100, "e")], height=5)
        wrap.pack(fill="both", expand=True)

    def start(self):
        if self.ok and self.job is None:
            self.prev, self.tprev = read_counters(), time.time()
            self.job = self.after(1000, self._tick)

    def stop(self):
        if self.job:
            self.after_cancel(self.job)
            self.job = None

    def _tick(self):
        cur, now = read_counters(), time.time()
        dt = max(0.001, now - self.tprev)
        rows, td, tu, tot_rx, tot_tx = [], 0.0, 0.0, 0, 0
        for k, (rx, tx) in (cur or {}).items():
            lk = k.lower()
            if lk == "lo" or "loopback" in lk or k not in (self.prev or {}):
                continue
            drx, dtx = max(0, rx - self.prev[k][0]) / dt, max(0, tx - self.prev[k][1]) / dt
            self.peak[k] = max(self.peak[k], drx + dtx)
            td += drx
            tu += dtx
            tot_rx += rx
            tot_tx += tx
            rows.append((k, (k, fmt_bits_rate(drx), fmt_bits_rate(dtx), fmt_bits_rate(self.peak[k]), fmt_bytes(rx), fmt_bytes(tx)),
                         ("ok" if drx + dtx > 0 else "none"), drx + dtx))
        self.prev, self.tprev = cur, now
        rows.sort(key=lambda r: -r[3])
        sync_tree(self.tree, [(r[0], r[1], (r[2],)) for r in rows])
        self.down.append(td)
        self.up.append(tu)
        self.peak_d = max(self.peak_d, td)
        self.cards["d"].set(fmt_bits_rate(td), None, "recebendo")
        self.cards["u"].set(fmt_bits_rate(tu), None, "enviando")
        self.cards["pk"].set(fmt_bits_rate(self.peak_d))
        self.cards["tot"].set(fmt_bytes(tot_rx), None, f"↑ {fmt_bytes(tot_tx)} enviados (desde o boot)")
        self.chart.set([dict(values=list(self.down), color=P.accent, name="↓"), dict(values=list(self.up), color=P.accent2, name="↑")])
        self.job = self.after(1000, self._tick)


class ConnectionsView(tk.Frame):
    label = Page.label

    def __init__(self, parent, app):
        super().__init__(parent, bg=P.bg)
        self.app, self.stop_evt, self.rows, self.q = app, None, [], queue.Queue()
        self.ps = get_psutil()
        if not self.ps:
            missing_module(self, "psutil", "psutil")
            return
        self.cards = grid_cards(self, [("est", "Estabelecidas", P.ok), ("lis", "Portas em escuta", P.accent),
                                       ("proc", "Processos com rede", P.accent2), ("rem", "Hosts remotos", P.dim)])
        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 10))
        self.label(ctl, "FILTRAR").pack(side="left", padx=(0, 10))
        self.filter = Field(ctl, "", width=34)
        self.filter.pack(side="left")
        self.filter.e.bind("<KeyRelease>", lambda e: self._apply())
        self.info = tk.Label(ctl, text="", font=F(9), fg=P.dim, bg=P.bg)
        self.info.pack(side="right")
        tp = Panel(self, "Conexões ativas")
        tp.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        wrap, self.tree = make_tree(tp.body, [("proc", "Processo", 170, "w"), ("local", "Local", 170, "w"),
                                               ("remote", "Remoto", 170, "w"), ("svc", "Serviço", 110, "w"),
                                               ("state", "Estado", 110, "w"), ("host", "Host remoto", 300, "w", True)], height=12)
        self.tree.tag_configure("listen", foreground=P.accent)
        wrap.pack(fill="both", expand=True)
        self.pc = {}
        self._poll()

    def _pname(self, pid):
        if not pid:
            return "—"
        if pid not in self.pc:
            try:
                self.pc[pid] = self.ps.Process(pid).name()
            except Exception:
                self.pc[pid] = "?"
        return self.pc[pid]

    def start(self):
        if not self.ps or (self.stop_evt and not self.stop_evt.is_set()):
            return
        self.stop_evt = threading.Event()
        threading.Thread(target=self._work, args=(self.stop_evt,), daemon=True).start()

    def stop(self):
        if self.stop_evt:
            self.stop_evt.set()

    def _work(self, stop):
        while not stop.is_set():
            try:
                conns = self.ps.net_connections(kind="inet")
                rows = []
                for c in conns:
                    if c.status not in ("ESTABLISHED", "LISTEN"):
                        continue
                    loc = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
                    rem = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
                    svc = l7_name(c.raddr.port if c.raddr else c.laddr.port)
                    rows.append((self._pname(c.pid), loc, rem, svc, c.status, c.raddr.ip if c.raddr else None))
                self.q.put(("rows", rows))
            except Exception as e:  # noqa
                self.q.put(("err", str(e)))
            stop.wait(2.5)

    def _poll(self):
        try:
            while True:
                ev = self.q.get_nowait()
                if ev[0] == "rows":
                    self.rows = ev[1]
                    self.info.config(text="", fg=P.dim)
                    self._apply()
                else:
                    self.info.config(text="Sem permissão para listar todas as conexões: execute como administrador/root.", fg=P.warn)
        except queue.Empty:
            pass
        self.after(700, self._poll)

    def _apply(self):
        flt = self.filter.get().lower()
        est = [r for r in self.rows if r[4] == "ESTABLISHED"]
        lis = [r for r in self.rows if r[4] == "LISTEN"]
        self.cards["est"].set(str(len(est)))
        self.cards["lis"].set(str(len({r[1] for r in lis})))
        self.cards["proc"].set(str(len({r[0] for r in self.rows})))
        self.cards["rem"].set(str(len({r[5] for r in est if r[5]})))
        out, seen = [], set()
        for r in sorted(self.rows, key=lambda r: (r[4] != "ESTABLISHED", r[0].lower(), r[1])):
            host = (NAMES.get(r[5]) or "") if r[5] else ""
            line = (r[0], r[1], r[2], r[3], "ESTABELECIDA" if r[4] == "ESTABLISHED" else "ESCUTA", host)
            if flt and flt not in " ".join(line).lower():
                continue
            key = f"{r[0]}|{r[1]}|{r[2]}|{r[4]}"
            if key in seen:
                continue
            seen.add(key)
            out.append((key, line, ("ok" if r[4] == "ESTABLISHED" else "listen",)))
            if len(out) >= 600:
                break
        sync_tree(self.tree, out)


class CaptureView(tk.Frame):
    label = Page.label

    def __init__(self, parent, app):
        super().__init__(parent, bg=P.bg)
        self.app, self.sniffer, self.job = app, None, None
        self.lock = threading.Lock()
        self.reset()
        self.sc = get_scapy()
        if not self.sc:
            missing_module(self, "scapy", "scapy", "No Windows instale também o Npcap (npcap.com).\nA captura exige executar como administrador/root.")
            return
        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 12))
        self.label(ctl, "INTERFACE").pack(side="left", padx=(0, 10))
        ps = get_psutil()
        names = ["(padrão)"] + (sorted(ps.net_if_addrs().keys()) if ps else [])
        self.iface = Combo(ctl, names, names[0], width=26)
        self.iface.pack(side="left")
        self.btn = Btn(ctl, "▶  Iniciar captura", self.toggle)
        self.btn.pack(side="left", padx=14)
        self.msg = tk.Label(ctl, text="" if is_admin() else "⚠ Execute como administrador/root para capturar.",
                            font=F(9), fg=P.warn, bg=P.bg)
        self.msg.pack(side="left")
        self.cards = grid_cards(self, [("pk", "Pacotes", P.accent), ("vol", "Volume", P.accent2),
                                       ("rate", "Taxa média", P.ok), ("hosts", "Hosts remotos", P.dim)])
        body = tk.Frame(self, bg=P.bg)
        body.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)
        tp = Panel(body, "Top talkers (hosts remotos)")
        tp.grid(row=0, column=0, sticky="nsew")
        wrap, self.tree = make_tree(tp.body, [("ip", "Host remoto", 140, "w"), ("name", "Nome", 220, "w", True),
                                               ("d", "↓ Down", 90, "e"), ("u", "↑ Up", 90, "e"), ("n", "Pacotes", 80, "e")], height=10)
        wrap.pack(fill="both", expand=True)
        pp = Panel(body, "Protocolos e aplicações (por porta)")
        pp.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        self.bars = BarList(pp.body, color=P.accent2)
        self.bars.pack(fill="x", pady=8)

    def reset(self):
        with self.lock:
            self.by_remote = defaultdict(lambda: [0, 0, 0])
            self.by_proto = defaultdict(int)
            self.tot = {"bytes": 0, "pkts": 0}
        self.t0 = time.time()

    def toggle(self):
        if self.sniffer:
            self._stop_capture()
            return
        sc = self.sc
        locals_ = local_ips()

        def on_pkt(p):
            if sc.IP not in p:
                return
            ip, size = p[sc.IP], len(p)
            if sc.TCP in p:
                proto, sp, dp = "TCP", p[sc.TCP].sport, p[sc.TCP].dport
            elif sc.UDP in p:
                proto, sp, dp = "UDP", p[sc.UDP].sport, p[sc.UDP].dport
            elif sc.ICMP in p:
                proto, sp, dp = "ICMP", 0, 0
            else:
                proto, sp, dp = f"IP/{ip.proto}", 0, 0
            label = "ICMP" if proto == "ICMP" else next((f"{SERVICES[x]} ({proto})" for x in (dp, sp) if x in SERVICES), f"{proto} outras")
            up = ip.src in locals_
            remote = ip.dst if up else ip.src
            with self.lock:
                r = self.by_remote[remote]
                r[1 if up else 0] += size
                r[2] += 1
                self.by_proto[label] += size
                self.tot["bytes"] += size
                self.tot["pkts"] += 1

        self.reset()
        iface = None if self.iface.get() == "(padrão)" else self.iface.get()
        try:
            self.sniffer = sc.AsyncSniffer(prn=on_pkt, store=False, iface=iface)
            self.sniffer.start()
        except Exception as e:
            self.sniffer = None
            messagebox.showerror(APP_NAME, f"Não foi possível iniciar a captura:\n{e}")
            return
        self.btn.set("■  Parar captura", kind="danger")
        self.after(1200, self._check_alive)
        self.job = self.after(1500, self._tick)

    def _check_alive(self):
        if self.sniffer is not None and not getattr(self.sniffer, "running", True):
            self._stop_capture()
            messagebox.showerror(APP_NAME, "A captura não iniciou. Verifique se está executando como administrador/root "
                                           "(e, no Windows, se o Npcap está instalado).")

    def _stop_capture(self):
        if self.job:
            self.after_cancel(self.job)
            self.job = None
        try:
            if self.sniffer is not None and getattr(self.sniffer, "running", False):
                self.sniffer.stop()
        except Exception:
            pass
        self.sniffer = None
        self.btn.set("▶  Iniciar captura", kind="primary")

    def start(self): pass
    def stop(self): pass

    def _tick(self):
        with self.lock:
            remotes = sorted(self.by_remote.items(), key=lambda x: -(x[1][0] + x[1][1]))[:40]
            protos = sorted(self.by_proto.items(), key=lambda x: -x[1])[:10]
            tb, tp, nh = self.tot["bytes"], self.tot["pkts"], len(self.by_remote)
        el = max(1.0, time.time() - self.t0)
        self.cards["pk"].set(f"{tp:,}".replace(",", "."))
        self.cards["vol"].set(fmt_bytes(tb))
        self.cards["rate"].set(fmt_bits_rate(tb / el))
        self.cards["hosts"].set(str(nh))
        sync_tree(self.tree, [(ip, (ip, NAMES.get(ip) or "", fmt_bytes(d), fmt_bytes(u), n), ("ok",)) for ip, (d, u, n) in remotes])
        mx = protos[0][1] if protos else 1
        self.bars.set([(lab, b / mx, f"{fmt_bytes(b)}  {100.0 * b / tb:.0f}%") for lab, b in protos])
        self.job = self.after(1500, self._tick)

    def shutdown(self):
        self._stop_capture()


class TrafficPage(Page):
    VIEWS = [("bw", "Banda por interface"), ("cn", "Conexões e portas"), ("cap", "Captura de pacotes")]

    def __init__(self, app):
        super().__init__(app)
        self.header("Tráfego da rede", "Visibilidade do que passa pela sua máquina: banda, processos, hosts remotos e protocolos.")
        seg = tk.Frame(self, bg=P.panel2)
        seg.pack(anchor="w", padx=PADX, pady=(0, 14))
        self.tabs, self.views, self.cur = {}, {}, None
        holder = tk.Frame(self, bg=P.bg)
        holder.pack(fill="both", expand=True)
        for key, text in self.VIEWS:
            b = tk.Label(seg, text=text, font=F(10, True), padx=18, pady=8, cursor="hand2")
            b.pack(side="left", padx=1, pady=1)
            b.bind("<Button-1>", lambda e, k=key: self.select(k))
            self.tabs[key] = b
        self.views["bw"] = BandwidthView(holder, app)
        self.views["cn"] = ConnectionsView(holder, app)
        self.views["cap"] = CaptureView(holder, app)
        self.select("bw")

    def select(self, key):
        if self.cur:
            self.views[self.cur].stop()
            self.views[self.cur].pack_forget()
        self.cur = key
        for k, b in self.tabs.items():
            b.config(bg=P.accent_dark if k == key else P.panel2, fg=P.accent if k == key else P.muted)
        self.views[key].pack(fill="both", expand=True)
        if self.winfo_ismapped():
            self.views[key].start()

    def on_show(self):
        self.views[self.cur].start()

    def on_hide(self):
        self.views[self.cur].stop()

    def shutdown(self):
        for v in self.views.values():
            if hasattr(v, "shutdown"):
                v.shutdown()
            v.stop()


# ----------------------------------------------------------------------------
#  Relatórios (histórico)
# ----------------------------------------------------------------------------
class ReportsPage(Page):
    PERIODS = {"Última hora": 3600, "Últimas 24 horas": 86400, "Últimos 7 dias": 604800, "Todo o histórico": 0}

    def __init__(self, app):
        super().__init__(app)
        self.header("Relatórios e histórico", "Dados gravados pelo Monitor contínuo. Gere um relatório HTML para enviar ao provedor ou ao time de TI.")
        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 14))
        self.label(ctl, "PERÍODO").pack(side="left", padx=(0, 10))
        self.period = Combo(ctl, list(self.PERIODS), "Últimas 24 horas", width=18)
        self.period.pack(side="left")
        self.period.bind("<<ComboboxSelected>>", lambda e: self.detail())
        Btn(ctl, "Gerar relatório HTML", self.make_report).pack(side="left", padx=14)
        Btn(ctl, "Atualizar lista", self.load, kind="ghost").pack(side="left")
        Btn(ctl, "Excluir histórico do alvo", self.delete, kind="danger").pack(side="right")
        self.cards = grid_cards(self, [("loss", "Perda", P.ok), ("avg", "Latência média", P.accent), ("p95", "Percentil 95", P.accent2),
                                       ("jit", "Jitter", P.warn), ("n", "Amostras", P.dim)])
        body = tk.Frame(self, bg=P.bg)
        body.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        body.grid_columnconfigure(0, weight=2, uniform="r")
        body.grid_columnconfigure(1, weight=3, uniform="r")
        body.grid_rowconfigure(0, weight=1)
        tp = Panel(body, "Alvos monitorados")
        tp.grid(row=0, column=0, sticky="nsew")
        wrap, self.tree = make_tree(tp.body, [("t", "Alvo", 170, "w", True), ("n", "Amostras", 80, "e"),
                                               ("a", "Início", 130, "w"), ("b", "Fim", 130, "w")], height=8)
        wrap.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.detail())
        cp = Panel(body, "Latência no destino")
        cp.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        self.chart = LineChart(cp.body, y_fmt=lambda v: f"{v:.0f} ms")
        self.chart.pack(fill="both", expand=True, padx=6, pady=4)

    def on_show(self):
        self.load()

    def _target(self):
        s = self.tree.selection()
        return s[0] if s else None

    def _since(self):
        secs = self.PERIODS[self.period.get()]
        return time.time() - secs if secs else 0

    def load(self):
        conn = db_connect()
        rows = conn.execute("SELECT target,COUNT(*),MIN(ts),MAX(ts) FROM samples GROUP BY target ORDER BY MAX(ts) DESC").fetchall()
        conn.close()
        sync_tree(self.tree, [(t, (t, f"{n:,}".replace(",", "."), ts_str(a), ts_str(b)), ("ok",)) for t, n, a, b in rows])
        if rows and not self._target():
            self.tree.selection_set(rows[0][0])
        self.detail()

    def detail(self):
        t = self._target()
        if not t:
            self.chart.set([], title="Nenhum histórico ainda: rode o Monitor contínuo.")
            return
        conn = db_connect()
        pts = conn.execute("SELECT ts,rtt FROM samples WHERE target=? AND ts>=? AND hop=(SELECT MAX(hop) FROM samples WHERE target=?) "
                           "ORDER BY ts DESC LIMIT 60000", (t, self._since(), t)).fetchall()[::-1]
        conn.close()
        st = series_stats(pts)
        self.cards["loss"].set(f"{st['loss']:.1f}%", "bad" if st["loss"] >= 5 else "warn" if st["loss"] > 0 else "ok")
        for k, key in (("avg", "avg"), ("p95", "p95"), ("jit", "jit")):
            v = st[key]
            self.cards[k].set("—" if v is None else f"{v:.1f} ms")
        self.cards["n"].set(f"{st['sent']:,}".replace(",", "."))
        vals = [r for _, r in pts]
        b = max(1, math.ceil(len(vals) / 500))
        ds = []
        for i in range(0, len(vals), b):
            ch = [v for v in vals[i:i + b] if v is not None]
            ds.append(max(ch) if ch else None)
        self.chart.set([dict(values=ds, color=P.accent, loss=True)], title=f"{t} · {self.period.get().lower()}")

    def make_report(self):
        t = self._target()
        if not t:
            messagebox.showinfo(APP_NAME, "Selecione um alvo na lista.")
            return
        conn = db_connect()
        path = generate_report(conn, t, self._since())
        conn.close()
        if not path:
            messagebox.showinfo(APP_NAME, "Sem dados nesse período.")
            return
        self.app.set_status(f"Relatório gerado: {path}", P.ok)
        webbrowser.open("file://" + os.path.abspath(path))

    def delete(self):
        t = self._target()
        if t and messagebox.askyesno(APP_NAME, f"Excluir todo o histórico de “{t}”?"):
            conn = db_connect()
            conn.execute("DELETE FROM samples WHERE target=?", (t,))
            conn.execute("DELETE FROM alerts WHERE target=?", (t,))
            conn.commit()
            conn.close()
            self.load()


# ----------------------------------------------------------------------------
#  DNS
# ----------------------------------------------------------------------------
class DNSPage(Page):
    def __init__(self, app):
        super().__init__(app)
        self.running, self.res = False, {}
        self.header("Teste de DNS", "Mede o tempo de resolução de nomes. DNS lento faz a internet parecer lenta.")
        ctl = tk.Frame(self, bg=P.bg)
        ctl.pack(fill="x", padx=PADX, pady=(0, 14))
        self.label(ctl, "DOMÍNIOS").pack(side="left", padx=(0, 10))
        self.domains = Field(ctl, "google.com, cloudflare.com, wikipedia.org, uol.com.br, microsoft.com", width=64)
        self.domains.pack(side="left")
        self.btn = Btn(ctl, "▶  Testar", self.run)
        self.btn.pack(side="left", padx=14)
        self.cards = grid_cards(self, [("avg", "Média das consultas", P.accent), ("slow", "Mais lento", P.warn), ("fail", "Falhas", P.ok)])
        tp = Panel(self, "Resultados")
        tp.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        wrap, self.tree = make_tree(tp.body, [("d", "Domínio", 220, "w", True), ("a", "1ª consulta", 100, "e"), ("b", "2ª", 90, "e"),
                                               ("c", "3ª", 90, "e"), ("m", "Média", 90, "e"), ("ip", "Endereço", 150, "w"),
                                               ("s", "Status", 100, "w")], height=10)
        wrap.pack(fill="both", expand=True)
        tk.Label(tp.body, text="A 2ª e a 3ª consultas podem vir do cache do sistema; a 1ª reflete melhor o servidor DNS.",
                 font=F(9), fg=P.dim, bg=P.panel).pack(anchor="w", padx=14, pady=(0, 8))
        self._pump()

    def run(self):
        if self.running:
            return
        doms = [d.strip() for d in self.domains.get().split(",") if d.strip()]
        if not doms:
            return
        self.res = {}
        self.tree.delete(*self.tree.get_children())
        self.running = True
        self.btn.set("Testando…", enabled=False)
        threading.Thread(target=self._work, args=(doms,), daemon=True).start()

    def _work(self, doms):
        for d in doms:
            times, addr = [], "—"
            for _ in range(3):
                t0 = time.time()
                try:
                    addr = socket.getaddrinfo(d, 80, socket.AF_INET)[0][4][0]
                    times.append((time.time() - t0) * 1000)
                except Exception:
                    times.append(None)
                time.sleep(0.15)
            self.q.put(("r", d, times, addr))
        self.q.put(("end",))

    def _pump(self):
        try:
            while True:
                ev = self.q.get_nowait()
                if ev[0] == "r":
                    self.res[ev[1]] = (ev[2], ev[3])
                    self._render()
                else:
                    self.running = False
                    self.btn.set("▶  Testar", enabled=True)
        except queue.Empty:
            pass
        self.after(200, self._pump)

    def _render(self):
        rows, allv, fails, slow = [], [], 0, ("—", 0)
        for d, (times, addr) in self.res.items():
            ok = [t for t in times if t is not None]
            fails += times.count(None)
            avg = sum(ok) / len(ok) if ok else None
            allv += ok
            if avg and avg > slow[1]:
                slow = (d, avg)
            lvl = "bad" if avg is None or avg >= 150 else "warn" if avg >= 60 else "ok"
            f = lambda t: "falha" if t is None else f"{t:.0f} ms"
            rows.append((d, (d, f(times[0]), f(times[1]), f(times[2]), "—" if avg is None else f"{avg:.0f} ms", addr,
                             "FALHOU" if avg is None else "LENTO" if avg >= 150 else "ATENÇÃO" if avg >= 60 else "OK"), (lvl,)))
        sync_tree(self.tree, rows)
        a = sum(allv) / len(allv) if allv else None
        self.cards["avg"].set("—" if a is None else f"{a:.0f} ms", None if a is None else ("bad" if a >= 150 else "warn" if a >= 60 else "ok"))
        self.cards["slow"].set(slow[0], None, f"{slow[1]:.0f} ms de média" if slow[1] else "")
        self.cards["fail"].set(str(fails), "bad" if fails else "ok")


# ----------------------------------------------------------------------------
#  Configurações
# ----------------------------------------------------------------------------
def open_folder(path):
    os.makedirs(path, exist_ok=True)
    try:
        if IS_WIN:
            os.startfile(path)  # noqa
        elif IS_MAC:
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


class SettingsPage(Page):
    FIELDS = [("interval", "Intervalo entre rodadas", "segundos entre cada rodada de ping", float),
              ("timeout", "Timeout do ping", "segundos de espera por resposta", float),
              ("max_hops", "Máximo de saltos", "limite do traceroute", int),
              ("alert_loss", "Alerta de perda", "% de perda na janela de amostras", float),
              ("alert_latency", "Alerta de latência", "ms (média na janela de amostras)", float),
              ("alert_window", "Janela de análise", "quantidade de amostras avaliadas", int),
              ("alert_cooldown", "Intervalo entre alertas", "segundos mínimos entre avisos repetidos", int)]
    TOGGLES = [("resolve_names", "Resolver nomes dos saltos", "usa DNS reverso para mostrar nomes em vez de IPs"),
               ("save_history", "Gravar histórico do monitor", "necessário para gerar relatórios"),
               ("alert_beep", "Apito sonoro nos alertas", "toca um som quando um alerta dispara")]

    def __init__(self, app):
        super().__init__(app)
        self.header("Configurações", "Ajuste a coleta, os limites de alerta e o histórico.")
        body = tk.Frame(self, bg=P.bg)
        body.pack(fill="both", expand=True, padx=PADX, pady=(0, 20))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        pf = Panel(body, "Coleta e alertas")
        pf.grid(row=0, column=0, sticky="new")
        self.ctrl = {}
        g = tk.Frame(pf.body, bg=P.panel)
        g.pack(fill="x", padx=16, pady=10)
        g.grid_columnconfigure(1, weight=1)
        r = 0
        for key, title, hint, _ in self.FIELDS:
            tk.Label(g, text=title, font=F(10, True), fg=P.text, bg=P.panel).grid(row=r, column=0, sticky="w", pady=7)
            fld = Field(g, app.cfg[key], width=12)
            fld.grid(row=r, column=1, sticky="w", padx=14)
            tk.Label(g, text=hint, font=F(9), fg=P.dim, bg=P.panel).grid(row=r, column=2, sticky="w")
            self.ctrl[key] = fld
            r += 1
        for key, title, hint in self.TOGGLES:
            tk.Label(g, text=title, font=F(10, True), fg=P.text, bg=P.panel).grid(row=r, column=0, sticky="w", pady=7)
            t = Toggle(g, app.cfg[key])
            t.grid(row=r, column=1, sticky="w", padx=14)
            tk.Label(g, text=hint, font=F(9), fg=P.dim, bg=P.panel).grid(row=r, column=2, sticky="w")
            self.ctrl[key] = t
            r += 1
        bf = tk.Frame(pf.body, bg=P.panel)
        bf.pack(fill="x", padx=16, pady=(4, 16))
        Btn(bf, "Salvar configurações", self.save).pack(side="left")
        Btn(bf, "Restaurar padrões", self.reset, kind="ghost").pack(side="left", padx=10)
        side = tk.Frame(body, bg=P.bg)
        side.grid(row=0, column=1, sticky="new", padx=(12, 0))
        ip = Panel(side, "Ambiente")
        ip.pack(fill="x")
        mods = [("ok" if get_psutil() else "warn", "psutil: " + ("instalado (banda e conexões)" if get_psutil() else "ausente  →  pip install psutil")),
                ("ok" if get_scapy() else "warn", "scapy: " + ("instalado (captura)" if get_scapy() else "ausente  →  pip install scapy")),
                ("ok" if is_admin() else "info", "Privilégios: " + ("administrador/root" if is_admin() else "usuário comum (captura exige admin)")),
                ("info", f"Histórico: {DB_PATH}"), ("info", f"Relatórios: {EXPORT_DIR}")]
        lp = ListPanel(ip.body, wrap=330)
        lp.pack(fill="x", pady=(2, 8))
        lp.set(mods)
        af = Panel(side, "Dados")
        af.pack(fill="x", pady=(12, 0))
        bf2 = tk.Frame(af.body, bg=P.panel)
        bf2.pack(fill="x", padx=16, pady=14)
        Btn(bf2, "Abrir pasta de relatórios", lambda: open_folder(EXPORT_DIR), kind="ghost").pack(anchor="w")
        Btn(bf2, "Limpar todo o histórico", self.wipe, kind="danger").pack(anchor="w", pady=(10, 0))

    def save(self):
        cfg = self.app.cfg
        try:
            for key, _, _, cast in self.FIELDS:
                cfg[key] = cast(self.ctrl[key].get().replace(",", "."))
            for key, _, _ in self.TOGGLES:
                cfg[key] = self.ctrl[key].get()
        except ValueError:
            messagebox.showerror(APP_NAME, "Há um valor numérico inválido.")
            return
        NAMES.enabled = bool(cfg["resolve_names"])
        save_cfg(cfg)
        self.app.set_status("Configurações salvas.", P.ok)

    def reset(self):
        for key, _, _, _ in self.FIELDS:
            self.ctrl[key].set(DEFAULT_CFG[key])
        for key, _, _ in self.TOGGLES:
            self.ctrl[key].set(DEFAULT_CFG[key])

    def wipe(self):
        if messagebox.askyesno(APP_NAME, "Apagar TODO o histórico e os alertas gravados?"):
            conn = db_connect()
            conn.execute("DELETE FROM samples")
            conn.execute("DELETE FROM alerts")
            conn.commit()
            conn.execute("VACUUM")
            conn.close()
            self.app.set_status("Histórico apagado.", P.ok)


# ----------------------------------------------------------------------------
#  Início
# ----------------------------------------------------------------------------
class HomePage(Page):
    TARGETS = [("Cloudflare", "1.1.1.1"), ("Google DNS", "8.8.8.8"), ("Google", "google.com")]
    TILES = [("mtr", "MTR ao vivo", "Traceroute com perda e latência em cada salto."),
             ("monitor", "Monitor contínuo", "Timeline, alertas e histórico gravado."),
             ("quality", "Qualidade VoIP", "Jitter, perda e nota MOS da conexão."),
             ("traffic", "Tráfego", "Banda, conexões ativas e captura de pacotes."),
             ("reports", "Relatórios", "Gráficos em HTML para enviar ao provedor."),
             ("dns", "Teste de DNS", "Tempo de resolução de nomes.")]

    def __init__(self, app):
        super().__init__(app)
        self.stop_evt, self.hist = None, [deque(maxlen=60) for _ in self.TARGETS]
        hero = tk.Frame(self, bg=P.bg)
        hero.pack(fill="x", padx=PADX, pady=(30, 8))
        t = tk.Frame(hero, bg=P.bg)
        t.pack(anchor="w")
        tk.Label(t, text="NETHUB", font=F(34, True), fg=P.text, bg=P.bg).pack(side="left")
        tk.Label(t, text=" TRACK", font=F(34, True), fg=P.accent, bg=P.bg).pack(side="left")
        tk.Label(hero, text="Veja o caminho. Meça a qualidade. Prove o problema.", font=F(12), fg=P.muted, bg=P.bg).pack(anchor="w", pady=(2, 14))
        qf = tk.Frame(hero, bg=P.bg)
        qf.pack(anchor="w")
        self.quick = Field(qf, "", width=34)
        self.quick.pack(side="left")
        self.quick.e.bind("<Return>", lambda e: self.go())
        Btn(qf, "Rastrear rota agora", self.go).pack(side="left", padx=12)
        tk.Label(qf, text="digite um site ou IP", font=F(9), fg=P.dim, bg=P.bg).pack(side="left")

        body = tk.Frame(self, bg=P.bg)
        body.pack(fill="both", expand=True, padx=PADX, pady=(16, 20))
        body.grid_columnconfigure(0, weight=3, uniform="h")
        body.grid_columnconfigure(1, weight=2, uniform="h")
        body.grid_rowconfigure(0, weight=1)
        sp = Panel(body, "Conexão agora")
        sp.grid(row=0, column=0, sticky="nsew")
        self.rows = []
        for i, (name, addr) in enumerate(self.TARGETS):
            r = tk.Frame(sp.body, bg=P.panel)
            r.pack(fill="x", padx=14, pady=8)
            r.grid_columnconfigure(1, weight=1)
            lf = tk.Frame(r, bg=P.panel)
            lf.grid(row=0, column=0, sticky="w")
            tk.Label(lf, text=name, font=F(11, True), fg=P.text, bg=P.panel, width=12, anchor="w").pack(anchor="w")
            tk.Label(lf, text=addr, font=F(9, mono=True), fg=P.dim, bg=P.panel).pack(anchor="w")
            ch = LineChart(r, height=46, mini=True)
            ch.grid(row=0, column=1, sticky="ew", padx=14)
            val = tk.Label(r, text="—", font=F(17, True), fg=P.dim, bg=P.panel, width=9, anchor="e")
            val.grid(row=0, column=2)
            self.rows.append((ch, val))
        tk.Label(sp.body, text="Latência até servidores públicos, atualizada a cada 2 segundos.", font=F(9), fg=P.dim, bg=P.panel).pack(anchor="w", padx=14, pady=(0, 10))
        tp = tk.Frame(body, bg=P.bg)
        tp.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        tp.grid_columnconfigure((0, 1), weight=1, uniform="t")
        for i, (key, title, desc) in enumerate(self.TILES):
            tile = tk.Frame(tp, bg=P.panel, highlightbackground=P.line, highlightthickness=1, cursor="hand2")
            tile.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0 if i % 2 == 0 else 8, 0), pady=(0 if i < 2 else 8, 0))
            tp.grid_rowconfigure(i // 2, weight=1)
            a = tk.Label(tile, text=title, font=F(11, True), fg=P.text, bg=P.panel, anchor="w", cursor="hand2")
            a.pack(fill="x", padx=14, pady=(12, 2))
            b = tk.Label(tile, text=desc, font=F(9), fg=P.muted, bg=P.panel, anchor="w", justify="left", wraplength=190, cursor="hand2")
            b.pack(fill="x", padx=14, pady=(0, 12))
            for w in (tile, a, b):
                w.bind("<Button-1>", lambda e, k=key: app.show(k))
                w.bind("<Enter>", lambda e, tl=tile: tl.config(highlightbackground=P.accent))
                w.bind("<Leave>", lambda e, tl=tile: tl.config(highlightbackground=P.line))
        self._pump()

    def go(self):
        t = self.quick.get()
        if t:
            self.app.show("mtr")
            self.app.pages["mtr"].launch(t)

    def on_show(self):
        if self.stop_evt and not self.stop_evt.is_set():
            return
        self.stop_evt = threading.Event()
        threading.Thread(target=self._work, args=(self.stop_evt,), daemon=True).start()

    def on_hide(self):
        if self.stop_evt:
            self.stop_evt.set()

    def _work(self, stop):
        ips = [resolve_host(a) or a for _, a in self.TARGETS]
        with ThreadPoolExecutor(max_workers=3) as pool:
            while not stop.is_set():
                futs = [pool.submit(ping_once, ip, 1.0) for ip in ips]
                for i, f in enumerate(futs):
                    self.q.put((i, f.result()))
                stop.wait(2.0)

    def _pump(self):
        try:
            while True:
                i, rtt = self.q.get_nowait()
                self.hist[i].append(rtt)
                ch, val = self.rows[i]
                ch.set([dict(values=list(self.hist[i]), color=P.accent, loss=True)])
                if rtt is None:
                    val.config(text="sem resp.", fg=P.bad, font=F(12, True))
                else:
                    val.config(text=f"{rtt:.0f} ms", fg=P.ok if rtt < 60 else P.warn if rtt < 150 else P.bad, font=F(17, True))
        except queue.Empty:
            pass
        self.after(250, self._pump)

    def shutdown(self):
        self.on_hide()


# ============================================================================
#  JANELA PRINCIPAL
# ============================================================================
def make_icon(size=64):
    img = tk.PhotoImage(width=size, height=size)
    s = size / 64.0
    nodes = [(14 * s, 47 * s), (31 * s, 19 * s), (50 * s, 35 * s)]
    r_corner = 14 * s

    def seg_dist(px, py, a, b):
        ax, ay, bx, by = a[0], a[1], b[0], b[1]
        dx, dy = bx - ax, by - ay
        t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
        return math.hypot(px - (ax + t * dx), py - (ay + t * dy))

    for y in range(size):
        for x in range(size):
            cx = min(max(x, r_corner), size - 1 - r_corner)
            cy = min(max(y, r_corner), size - 1 - r_corner)
            if math.hypot(x - cx, y - cy) > r_corner:
                continue
            col = blend("#101a36", "#0a0f1e", y / size)
            d = min(seg_dist(x, y, nodes[0], nodes[1]), seg_dist(x, y, nodes[1], nodes[2]))
            if d < 2.6 * s:
                col = P.accent
            for i, (nx, ny) in enumerate(nodes):
                dd = math.hypot(x - nx, y - ny)
                if dd < 6.2 * s:
                    col = "#ffffff" if dd < 3 * s else P.accent
            img.put(col, (x, y))
    return img


class App(tk.Tk):
    NAV = [("home", "Início", None),
           (None, "DIAGNÓSTICO", None),
           ("mtr", "MTR ao vivo", None), ("monitor", "Monitor contínuo", None),
           ("quality", "Qualidade VoIP", None), ("dns", "Teste de DNS", None),
           (None, "TRÁFEGO", None), ("traffic", "Tráfego da rede", None),
           (None, "DADOS", None), ("reports", "Relatórios", None),
           (None, "SISTEMA", None), ("settings", "Configurações", None)]

    def __init__(self):
        if IS_WIN:
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        super().__init__()
        self.title(APP_NAME)
        self.configure(bg=P.bg)
        self.cfg = load_cfg()
        NAMES.enabled = bool(self.cfg["resolve_names"])
        init_fonts()
        self.scale = max(1.0, self.winfo_fpixels("1i") / 96.0)
        setup_style(self, self.scale)
        w, h = int(1380 * min(self.scale, 1.5)), int(880 * min(self.scale, 1.5))
        w, h = min(w, self.winfo_screenwidth() - 60), min(h, self.winfo_screenheight() - 90)
        self.geometry(f"{w}x{h}+{max(0, (self.winfo_screenwidth() - w) // 2)}+{max(0, (self.winfo_screenheight() - h) // 3)}")
        self.minsize(1120, 700)
        try:
            self._icon = make_icon(64)
            self.iconphoto(True, self._icon)
        except Exception:
            pass

        # barra de status
        self.sbar = tk.Frame(self, bg=P.side, height=30)
        self.sbar.pack(side="bottom", fill="x")
        self.sbar.pack_propagate(False)
        self.st_dot = tk.Label(self.sbar, text="●", fg=P.ok, bg=P.side, font=F(9))
        self.st_dot.pack(side="left", padx=(16, 6))
        self.st_txt = tk.Label(self.sbar, text="Pronto", fg=P.muted, bg=P.side, font=F(9))
        self.st_txt.pack(side="left")
        mods = f"psutil {'✓' if get_psutil() else '✗'}   scapy {'✓' if get_scapy() else '✗'}   v{VERSION}"
        tk.Label(self.sbar, text=mods, fg=P.dim, bg=P.side, font=F(9)).pack(side="right", padx=16)
        tk.Frame(self, bg=P.line, height=1).pack(side="bottom", fill="x")

        # barra lateral
        self.side = tk.Frame(self, bg=P.side, width=int(232 * min(self.scale, 1.5)))
        self.side.pack(side="left", fill="y")
        self.side.pack_propagate(False)
        tk.Frame(self, bg=P.line, width=1).pack(side="left", fill="y")
        self._logo()
        self.nav_items = {}
        for key, text, _ in self.NAV:
            if key is None:
                tk.Label(self.side, text=text, fg=P.dim, bg=P.side, font=F(8, True), anchor="w").pack(fill="x", padx=22, pady=(16, 4))
            else:
                self._nav_item(key, text)

        self.content = tk.Frame(self, bg=P.bg)
        self.content.pack(side="left", fill="both", expand=True)
        self.pages = {"home": HomePage(self), "mtr": TracePage(self, "mtr"), "monitor": TracePage(self, "monitor"),
                      "quality": QualityPage(self), "dns": DNSPage(self), "traffic": TrafficPage(self),
                      "reports": ReportsPage(self), "settings": SettingsPage(self)}
        self.cur = None
        self.show("home")
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _logo(self):
        c = tk.Canvas(self.side, bg=P.side, highlightthickness=0, height=82)
        c.pack(fill="x")
        pts = [(26, 52), (42, 30), (60, 44)]
        c.create_line(*[v for p in pts for v in p], fill=P.accent, width=3, joinstyle="round")
        for x, y in pts:
            c.create_oval(x - 6, y - 6, x + 6, y + 6, fill=P.accent, outline=P.side, width=2)
            c.create_oval(x - 2.5, y - 2.5, x + 2.5, y + 2.5, fill="#ffffff", outline="")
        c.create_text(80, 33, text="NETHUB", anchor="w", fill=P.text, font=F(15, True))
        c.create_text(81, 54, text="T R A C K", anchor="w", fill=P.accent, font=F(10, True))
        tk.Frame(self.side, bg=P.line, height=1).pack(fill="x", padx=18, pady=(2, 6))

    def _nav_item(self, key, text):
        row = tk.Frame(self.side, bg=P.side, cursor="hand2")
        row.pack(fill="x", padx=10, pady=1)
        bar = tk.Frame(row, bg=P.side, width=3)
        bar.pack(side="left", fill="y")
        lab = tk.Label(row, text=text, fg=P.muted, bg=P.side, font=F(10, True), anchor="w", padx=14, pady=9, cursor="hand2")
        lab.pack(side="left", fill="x", expand=True)
        for w in (row, lab, bar):
            w.bind("<Button-1>", lambda e, k=key: self.show(k))
            w.bind("<Enter>", lambda e, k=key: self._nav_paint(k, True))
            w.bind("<Leave>", lambda e, k=key: self._nav_paint(k, False))
        self.nav_items[key] = (row, bar, lab)

    def _nav_paint(self, key, hover=False):
        row, bar, lab = self.nav_items[key]
        active = key == self.cur_key
        bg = P.panel2 if active else (blend(P.side, P.panel2, 0.5) if hover else P.side)
        for w in (row, lab):
            w.config(bg=bg)
        bar.config(bg=P.accent if active else bg)
        lab.config(fg=P.text if active else (P.text if hover else P.muted))

    cur_key = None

    def show(self, key):
        if self.cur:
            self.cur.on_hide()
            self.cur.pack_forget()
        old = self.cur_key
        self.cur_key = key
        self.cur = self.pages[key]
        self.cur.pack(fill="both", expand=True)
        self.update_idletasks()
        self.cur.on_show()
        for k in self.nav_items:
            self._nav_paint(k)

    def set_status(self, text, color=None):
        self.st_dot.config(fg=color or P.ok)
        self.st_txt.config(text=text[:160])

    def _close(self):
        for p in self.pages.values():
            try:
                p.shutdown()
            except Exception:
                pass
        self.destroy()


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
