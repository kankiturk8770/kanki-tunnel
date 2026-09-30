#!/usr/bin/env python3
"""Kanki Tunnel panel server.

A small, dependency-free web panel that manages tunnels run by the BackPack
engine (https://github.com/AminMGMT/BackPack). Tunnels are written exactly the
way BackPack writes its own (/etc/backpack/<name>.toml + backpack-<name>.service),
so BackPack's own menu sees and manages them too.

Standard library only. Runs as root under systemd (kanki-panel.service).
"""
import base64, hashlib, hmac, http.server, json, os, re, secrets, socketserver
import ssl, subprocess, sys, threading, time
from urllib.parse import urlparse

# ---------------- paths (overridable for testing) ----------------
ROOT        = os.environ.get("KANKI_ROOT", "")
KANKI_DIR   = ROOT + "/etc/kanki"
CONF_FILE   = KANKI_DIR + "/panel.json"
TUN_FILE    = KANKI_DIR + "/tunnels.json"
BP_CONF_DIR = ROOT + "/etc/backpack"
UNIT_DIR    = ROOT + "/etc/systemd/system"
BP_BIN      = "/usr/local/bin/backpack"
HTML_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
DRY_RUN     = os.environ.get("KANKI_DRYRUN") == "1"

SESSION_TTL = 12 * 3600
MAX_BODY    = 64 * 1024
LOCK        = threading.Lock()
RESERVED    = {"webui", "monitor", "proxy", "panel", "kanki"}
FEC         = {"l": (10, 2), "b": (10, 3), "h": (10, 5)}

# ---------------- config ----------------
def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000)
    return f"pbkdf2${salt}${dk.hex()}"

def check_pw(pw, stored):
    try:
        _, salt, _ = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_pw(pw, salt), stored)

# ---------------- system helpers ----------------
def sh(*args):
    if DRY_RUN:
        print("[dry-run]", " ".join(args), file=sys.stderr)
        return 0, "active" if args[:2] == ("systemctl", "is-active") else ""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:  # e.g. ufw not installed
        return 127, str(e)
    return p.returncode, (p.stdout + p.stderr).strip()

def unit_name(name):
    return f"backpack-{name}.service"

def unit_text(name):
    # Same unit BackPack itself writes (internal/manage/core/systemd.go).
    return (f"[Unit]\nDescription=Backpack Tunnel ({name})\nAfter=network.target\n\n"
            f"[Service]\nType=simple\nExecStart={BP_BIN} -c {BP_CONF_DIR}/{name}.toml\n"
            "Restart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n"
            "[Install]\nWantedBy=multi-user.target\n")

def ufw_allow(port, udp):
    rc, out = sh("ufw", "status")
    if rc == 0 and "Status: active" in out:
        sh("ufw", "allow", f"{port}/tcp")
        if udp:
            sh("ufw", "allow", f"{port}/udp")

def cpu_percent():
    def snap():
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        return v[3] + v[4], sum(v)
    i1, t1 = snap(); time.sleep(0.2); i2, t2 = snap()
    return round(100 * (1 - (i2 - i1) / max(t2 - t1, 1)))

def mem_percent():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0])
    total, avail = info.get("MemTotal", 1), info.get("MemAvailable", 0)
    return round(100 * (1 - avail / total))

def uptime_hours():
    with open("/proc/uptime") as f:
        return round(float(f.read().split()[0]) / 3600, 1)

def local_ip():
    rc, out = sh("ip", "-4", "route", "get", "1.1.1.1")
    m = re.search(r"src (\S+)", out)
    return m.group(1) if m else ""

# ---------------- validation ----------------
NAME_RE  = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
HOST_RE  = re.compile(r"^[A-Za-z0-9.\-]{3,253}$|^\[?[0-9a-fA-F:]{2,39}\]?$")
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(=([A-Za-z0-9.\-]+:)?\d{1,5})?$")

def valid_port(p):
    return isinstance(p, (str, int)) and str(p).isdigit() and 1 <= int(p) <= 65535

def parse_ports(raw):
    items = [x.strip() for x in str(raw or "").split(",") if x.strip()]
    for it in items:
        if not PORTS_RE.match(it):
            return None
        for n in re.findall(r"\d+", it.split("=")[0]):
            if not 1 <= int(n) <= 65535:
                return None
    return items

def validate(p, need_ports):
    errs = []
    name = str(p.get("name", ""))
    if not NAME_RE.match(name) or name.lower() in RESERVED:
        errs.append("name")
    if p.get("mode") not in ("reverse", "direct"):
        errs.append("mode")
    if p.get("kind") not in ("stealth", "game"):
        errs.append("kind")
    if not HOST_RE.match(str(p.get("peer", ""))):
        errs.append("peer")
    if not valid_port(p.get("port")):
        errs.append("port")
    if p.get("fec", "b") not in FEC:
        errs.append("fec")
    if not re.fullmatch(r"[0-9a-f]{32,64}", str(p.get("token", ""))):
        errs.append("token")
    ports = parse_ports(p.get("ports", ""))
    if ports is None or (need_ports and not ports):
        errs.append("ports")
    return errs, ports or []

# ---------------- BackPack TOML (keys verified against v1.8.4 config/) ----------------
def q(s):
    return json.dumps(s)

def arr(a):
    return "[" + ", ".join(q(x) for x in a) + "]"

def build(p, ports, side):
    """side: 'iran' (the server that created it) or 'kharej' (joined by link)."""
    name, peer, port, tk = p["name"], p["peer"], int(p["port"]), p["token"]
    ds, ps = FEC[p.get("fec", "b")]
    game = p["kind"] == "game"
    head = f"# Kanki Tunnel - {name} ({p['mode']}, {'gaming' if game else 'stealth'}, {side})\n"
    kcp = (f"kcp_nodelay = 1\nkcp_interval = 10\nkcp_resend = 2\nkcp_nocongestion = 1\n"
           f"kcp_mtu = 1250\nkcp_datashards = {ds}\nkcp_parityshards = {ps}\n")

    if p["mode"] == "reverse":
        tr = "kcp" if game else "stealth"
        fb = 'fallback_transports = ["wss", "tcpmux"]\n' if (not game and p.get("fb")) else ""
        if side == "iran":
            out = f"[server]\nbind_addr = \"0.0.0.0:{port}\"\ntransport = \"{tr}\"\ntoken = \"{tk}\"\nports = {arr(ports)}\n"
            if game or p.get("udp"):
                out += "accept_udp = true\n"
            if not game and p.get("pp"):
                out += "proxy_protocol = true\n"
        else:
            out = f"[client]\nremote_addr = \"{peer}:{port}\"\ntransport = \"{tr}\"\ntoken = \"{tk}\"\n"
        return head + out + fb + (kcp if game else "")

    if game:  # direct gaming = layer-3 tunnel over UDP with FEC
        if side == "iran":
            out = (f"[l3]\nmode = \"dial\"\naddr = \"{peer}:{port}\"\ntoken = \"{tk}\"\ncarrier = \"udp\"\n"
                   f"local_ip = \"10.10.0.1/30\"\npeer_ip = \"10.10.0.2\"\nfec_data = {ds}\nfec_parity = {ps}\n")
            if ports:
                out += f"ports = {arr(ports)}\naccept_udp = true\n"
        else:
            out = (f"[l3]\nmode = \"listen\"\naddr = \"0.0.0.0:{port}\"\ntoken = \"{tk}\"\ncarrier = \"udp\"\n"
                   f"local_ip = \"10.10.0.2/30\"\npeer_ip = \"10.10.0.1\"\nfec_data = {ds}\nfec_parity = {ps}\n")
        return head + out

    if side == "iran":  # direct stealth
        out = f"[direct]\nrole = \"iran\"\naddr = \"{peer}:{port}\"\ntransport = \"stealth\"\ntoken = \"{tk}\"\nports = {arr(ports)}\n"
        if p.get("udp"):
            out += "accept_udp = true\n"
    else:
        out = f"[direct]\nrole = \"kharej\"\naddr = \"0.0.0.0:{port}\"\ntransport = \"stealth\"\ntoken = \"{tk}\"\n"
    return head + out

def make_link(p):
    keep = {k: p.get(k) for k in ("mode", "kind", "name", "peer", "port", "token", "fec", "fb", "iran_host")}
    keep["v"] = 1
    raw = json.dumps(keep, separators=(",", ":")).encode()
    return "kanki://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")

def read_link(link):
    link = link.strip()
    if not link.startswith("kanki://"):
        raise ValueError
    b = link[8:]
    return json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))

# ---------------- tunnel operations ----------------
def tunnels():
    return load_json(TUN_FILE, [])

def install_tunnel(meta, toml):
    name = meta["name"]
    os.makedirs(BP_CONF_DIR, exist_ok=True)
    path = f"{BP_CONF_DIR}/{name}.toml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(toml)
    with open(f"{UNIT_DIR}/{unit_name(name)}", "w") as f:
        f.write(unit_text(name))
    sh("systemctl", "daemon-reload")
    rc, out = sh("systemctl", "enable", "--now", unit_name(name))
    ufw_allow(meta["port"], meta["kind"] == "game" or meta.get("udp"))
    lst = [t for t in tunnels() if t["name"] != name] + [meta]
    save_json(TUN_FILE, lst)
    return rc, out

def remove_tunnel(name):
    sh("systemctl", "disable", "--now", unit_name(name))
    for path in (f"{UNIT_DIR}/{unit_name(name)}", f"{BP_CONF_DIR}/{name}.toml"):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    sh("systemctl", "daemon-reload")
    save_json(TUN_FILE, [t for t in tunnels() if t["name"] != name])

def state(name):
    rc, out = sh("systemctl", "is-active", unit_name(name))
    last = out.splitlines()[-1].strip() if out else ""
    known = {"active", "inactive", "failed", "activating", "deactivating", "reloading"}
    return last if last in known else "unknown"

# ---------------- auth ----------------
SESSIONS = {}          # token -> expiry
FAILS = {}             # ip -> (count, blocked_until)

def blocked(ip):
    c, until = FAILS.get(ip, (0, 0))
    return until > time.time()

def fail(ip):
    c, _ = FAILS.get(ip, (0, 0))
    c += 1
    FAILS[ip] = (c, time.time() + 900 if c >= 5 else 0)

# ---------------- HTTP ----------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Kanki"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    # -- helpers
    @property
    def base(self):
        return "/" + CONF["base_path"] + "/"

    def send(self, code, body=b"", ctype="application/json", headers=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ValueError("bad json")

    def authed(self):
        c = self.headers.get("Cookie", "")
        m = re.search(r"kanki_s=([A-Za-z0-9_\-]+)", c)
        if not m:
            return False
        exp = SESSIONS.get(m.group(1), 0)
        if exp < time.time():
            SESSIONS.pop(m.group(1), None)
            return False
        return True

    def route(self):
        path = urlparse(self.path).path
        if path == self.base[:-1]:
            return "redirect"
        if not path.startswith(self.base):
            return None
        return path[len(self.base):]

    # -- methods
    def do_GET(self):
        r = self.route()
        if r is None:
            return self.send(404, "", "text/plain")
        if r == "redirect":
            return self.send(301, "", "text/plain", [("Location", self.base)])
        if r == "":
            with open(HTML_FILE, "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8",
                                 [("Content-Security-Policy",
                                   "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                   "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                   "font-src https://fonts.gstatic.com; connect-src 'self'")])
        if r == "api/session":
            return self.send(200, {"ok": self.authed()})
        if not self.authed():
            return self.send(401, {"error": "auth"})
        if r == "api/status":
            lst = tunnels()
            active = sum(1 for t in lst if state(t["name"]) == "active")
            return self.send(200, {"cpu": cpu_percent(), "ram": mem_percent(), "uptime": uptime_hours(),
                                   "ip": local_ip(), "host": os.uname().nodename,
                                   "engine": os.path.exists(BP_BIN) or DRY_RUN,
                                   "tunnels": len(lst), "active": active})
        if r == "api/tunnels":
            out = []
            for t in tunnels():
                out.append({k: t.get(k) for k in ("name", "mode", "kind", "peer", "port", "ports", "side")}
                           | {"state": state(t["name"])})
            return self.send(200, out)
        m = re.fullmatch(r"api/tunnels/([A-Za-z0-9_-]{1,32})/link", r)
        if m:
            t = next((x for x in tunnels() if x["name"] == m.group(1)), None)
            if not t or t.get("side") != "iran":
                return self.send(404, {"error": "notfound"})
            return self.send(200, {"link": make_link(t)})
        return self.send(404, {"error": "notfound"})

    def do_POST(self):
        r = self.route()
        if r in (None, "redirect"):
            return self.send(404, "", "text/plain")
        # A custom header can't be sent cross-site without CORS, so this blocks CSRF.
        if self.headers.get("X-Kanki") != "1":
            return self.send(403, {"error": "csrf"})
        ip = self.client_address[0]
        try:
            data = self.body()
        except ValueError:
            return self.send(400, {"error": "body"})

        if r == "api/login":
            if blocked(ip):
                return self.send(429, {"error": "blocked"})
            if check_pw(str(data.get("password", "")), CONF["password"]):
                FAILS.pop(ip, None)
                tok = secrets.token_urlsafe(32)
                SESSIONS[tok] = time.time() + SESSION_TTL
                cookie = f"kanki_s={tok}; Path={self.base}; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}"
                return self.send(200, {"ok": True}, headers=[("Set-Cookie", cookie)])
            fail(ip)
            time.sleep(1)
            return self.send(401, {"error": "password"})

        if r == "api/logout":
            m = re.search(r"kanki_s=([A-Za-z0-9_\-]+)", self.headers.get("Cookie", ""))
            if m:
                SESSIONS.pop(m.group(1), None)
            return self.send(200, {"ok": True}, headers=[("Set-Cookie", f"kanki_s=; Path={self.base}; Max-Age=0")])

        if not self.authed():
            return self.send(401, {"error": "auth"})

        if r == "api/token":
            return self.send(200, {"token": secrets.token_hex(16)})

        if r == "api/tunnels":
            p = {k: data.get(k) for k in ("mode", "kind", "name", "peer", "port", "ports", "token", "fec", "udp", "pp", "fb")}
            p["port"] = str(p.get("port") or "")
            p["fec"] = p.get("fec") or "b"
            need_ports = not (p.get("mode") == "direct" and p.get("kind") == "game")
            errs, ports = validate(p, need_ports)
            if errs:
                return self.send(400, {"error": "invalid", "fields": errs})
            with LOCK:
                if any(t["name"] == p["name"] for t in tunnels()):
                    return self.send(409, {"error": "exists"})
                meta = p | {"ports": ports, "side": "iran", "created": int(time.time())}
                # In reverse the abroad server dials the Iran host; in direct it listens.
                meta["iran_host"] = p["peer"] if p["mode"] == "reverse" else ""
                rc, out = install_tunnel(meta, build(p, ports, "iran"))
            return self.send(200, {"ok": rc == 0, "detail": out[-300:], "link": make_link(meta),
                                   "config": build(p, ports, "iran")})

        if r == "api/join":
            try:
                p = read_link(str(data.get("link", "")))
            except Exception:
                return self.send(400, {"error": "link"})
            p["port"] = str(p.get("port") or "")
            p["fec"] = p.get("fec") or "b"
            errs, _ = validate(p | {"ports": ""}, False)
            if errs:
                return self.send(400, {"error": "link", "fields": errs})
            with LOCK:
                if any(t["name"] == p["name"] for t in tunnels()):
                    return self.send(409, {"error": "exists"})
                meta = {k: p.get(k) for k in ("mode", "kind", "name", "peer", "port", "token", "fec", "fb")}
                meta |= {"ports": [], "side": "kharej", "created": int(time.time())}
                cfg = build(meta, [], "kharej")
                rc, out = install_tunnel(meta, cfg)
            return self.send(200, {"ok": rc == 0, "detail": out[-300:], "config": cfg})

        m = re.fullmatch(r"api/tunnels/([A-Za-z0-9_-]{1,32})/restart", r)
        if m:
            rc, out = sh("systemctl", "restart", unit_name(m.group(1)))
            return self.send(200, {"ok": rc == 0})
        return self.send(404, {"error": "notfound"})

    def do_DELETE(self):
        r = self.route()
        if r in (None, "redirect") or self.headers.get("X-Kanki") != "1":
            return self.send(403, {"error": "forbidden"})
        if not self.authed():
            return self.send(401, {"error": "auth"})
        m = re.fullmatch(r"api/tunnels/([A-Za-z0-9_-]{1,32})", r)
        if not m:
            return self.send(404, {"error": "notfound"})
        with LOCK:
            remove_tunnel(m.group(1))
        return self.send(200, {"ok": True})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global CONF
    if "--set-password" in sys.argv:
        pw = sys.stdin.readline().strip()
        if len(pw) < 6:
            sys.exit("password must be at least 6 characters")
        c = load_json(CONF_FILE, {})
        c["password"] = hash_pw(pw)
        save_json(CONF_FILE, c)
        print("password updated")
        return
    CONF = load_json(CONF_FILE, None)
    if not CONF:
        sys.exit(f"missing {CONF_FILE} - run install.sh")
    srv = Server(("0.0.0.0", int(CONF["port"])), Handler)
    if CONF.get("cert") and CONF.get("key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CONF["cert"], CONF["key"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"Kanki panel on :{CONF['port']}/{CONF['base_path']}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
