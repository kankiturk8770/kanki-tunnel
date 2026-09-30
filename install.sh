#!/usr/bin/env bash
#
# Kanki Tunnel installer. Run as root on BOTH servers (Iran and abroad):
#
#   Public repo:
#     bash <(curl -fsSL https://raw.githubusercontent.com/kankiturk8770/kanki-tunnel/main/install.sh)
#   Private repo:
#     export GH_TOKEN=ghp_xxx
#     bash <(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" https://raw.githubusercontent.com/kankiturk8770/kanki-tunnel/main/install.sh)
#
# Tunnel engine: BackPack by Amin Mohammadi (AminMGMT) - https://github.com/AminMGMT/BackPack
set -euo pipefail

# ======== EDIT THIS ONE LINE after you create your GitHub repo ========
KANKI_REPO="${KANKI_REPO:-kankiturk8770/kanki-tunnel}"
# ======================================================================
KANKI_BRANCH="${KANKI_BRANCH:-main}"
GH_TOKEN="${GH_TOKEN:-}"
BP_REPO="AminMGMT/BackPack"
BP_BIN="/usr/local/bin/backpack"
APP_DIR="/opt/kanki"
ETC="/etc/kanki"

Y=$'\033[1;33m'; G=$'\033[1;32m'; R=$'\033[1;31m'; D=$'\033[2m'; N=$'\033[0m'
info(){ echo -e "${Y}[*]${N} $*"; }
ok(){   echo -e "${G}[✓]${N} $*"; }
die(){  echo -e "${R}[x]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo -i first)."
command -v systemctl >/dev/null || die "systemd is required."
command -v apt-get >/dev/null || die "This installer supports Debian/Ubuntu."

echo -e "\n${Y}  ██  KANKI TUNNEL${N}"
echo -e "${N}${D}  engine: BackPack by AminMGMT${N}\n"

# ---------- 1. dependencies ----------
info "Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq python3 openssl curl tar ca-certificates iproute2 >/dev/null
ok "Dependencies ready"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
AUTH=(); [[ -n "$GH_TOKEN" ]] && AUTH=(-H "Authorization: Bearer $GH_TOKEN")

# ---------- 2. Kanki files ----------
SRC=""
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -n "$SELF_DIR" && -f "$SELF_DIR/panel/server.py" ]]; then
  SRC="$SELF_DIR"
else
  [[ "$KANKI_REPO" == YOUR_USER/* ]] && die "Edit KANKI_REPO at the top of install.sh to your GitHub repo first."
  info "Downloading Kanki from github.com/${KANKI_REPO}..."
  curl -fsSL --connect-timeout 20 "${AUTH[@]}" \
    "https://api.github.com/repos/${KANKI_REPO}/tarball/${KANKI_BRANCH}" -o "$TMP/kanki.tgz" \
    || die "Download failed. Private repo? export GH_TOKEN=... first. Also check KANKI_REPO."
  mkdir -p "$TMP/src"
  tar -xzf "$TMP/kanki.tgz" -C "$TMP/src" --strip-components=1
  SRC="$TMP/src"
fi
[[ -f "$SRC/panel/server.py" && -f "$SRC/panel/index.html" && -f "$SRC/kanki" ]] || die "Kanki files are incomplete."
mkdir -p "$APP_DIR/panel" "$ETC/tls"
chmod 700 "$ETC"
install -m 0644 "$SRC/panel/server.py"  "$APP_DIR/panel/server.py"
install -m 0644 "$SRC/panel/index.html" "$APP_DIR/panel/index.html"
install -m 0755 "$SRC/kanki"            /usr/local/bin/kanki
printf 'KANKI_REPO=%q\nKANKI_BRANCH=%q\n' "$KANKI_REPO" "$KANKI_BRANCH" > "$ETC/install.env"
ok "Kanki files installed"

# ---------- 3. BackPack engine ----------
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  i386|i686)     ARCH=386 ;;
  s390x)         ARCH=s390x ;;
  *) die "Unsupported CPU: $(uname -m)" ;;
esac
ASSET="backpack_linux_${ARCH}.tar.gz"

install_engine(){
  local dir="$TMP/bp"; mkdir -p "$dir"
  if [[ -f "/root/$ASSET" && -f "/root/SHA256SUMS" ]]; then
    info "Using offline engine files from /root"
    cp "/root/$ASSET" "/root/SHA256SUMS" "$dir/"
  else
    info "Downloading BackPack engine ($ARCH)..."
    curl -fsSL --connect-timeout 20 "https://github.com/${BP_REPO}/releases/latest/download/${ASSET}" -o "$dir/$ASSET" &&
    curl -fsSL --connect-timeout 20 "https://github.com/${BP_REPO}/releases/latest/download/SHA256SUMS" -o "$dir/SHA256SUMS" ||
      die "Could not reach GitHub. Offline: download ${ASSET} and SHA256SUMS from
     https://github.com/${BP_REPO}/releases/latest on another machine, copy both to /root, re-run."
  fi
  local want got
  want="$(grep -E "[[:space:]]\*?${ASSET}\$" "$dir/SHA256SUMS" | awk '{print $1}' | head -1)"
  got="$(sha256sum "$dir/$ASSET" | awk '{print $1}')"
  [[ -n "$want" && "$want" == "$got" ]] || die "Engine checksum mismatch - refusing to install."
  tar -xzf "$dir/$ASSET" -C "$dir" backpack
  install -m 0755 "$dir/backpack" "$BP_BIN"
  ok "BackPack engine installed (checksum verified)"
}
if [[ -x "$BP_BIN" && "${KANKI_UPDATE_ENGINE:-0}" != "1" ]]; then
  ok "BackPack engine already installed"
else
  install_engine
fi
mkdir -p /etc/backpack

# ---------- 4. panel config (first install only) ----------
PUBLIC_IP="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
NEW_PASS=""
if [[ ! -f "$ETC/panel.json" ]]; then
  while :; do
    PORT=$(( (RANDOM % 40000) + 20000 ))
    ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN || break
  done
  BASE="$(tr -dc 'a-z0-9' </dev/urandom | head -c 10 || true)"
  NEW_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12 || true)"
  if [[ ! -f "$ETC/tls/cert.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=kanki" \
      -addext "subjectAltName=IP:${PUBLIC_IP:-127.0.0.1}" \
      -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" >/dev/null 2>&1
    chmod 600 "$ETC/tls/key.pem"
  fi
  PORT="$PORT" BASE="$BASE" python3 - <<'PY'
import json, os
c = {"port": int(os.environ["PORT"]), "base_path": os.environ["BASE"], "password": "",
     "cert": "/etc/kanki/tls/cert.pem", "key": "/etc/kanki/tls/key.pem"}
fd = os.open("/etc/kanki/panel.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(c, f, indent=2)
PY
  echo "$NEW_PASS" | python3 "$APP_DIR/panel/server.py" --set-password >/dev/null
  ok "Panel configured"
fi

# ---------- 5. service ----------
cat > /etc/systemd/system/kanki-panel.service <<UNIT
[Unit]
Description=Kanki Tunnel panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${APP_DIR}/panel/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable kanki-panel >/dev/null 2>&1
systemctl restart kanki-panel
sleep 1
systemctl is-active --quiet kanki-panel || die "Panel failed to start: journalctl -u kanki-panel -n 30"

PORT="$(python3 -c 'import json;print(json.load(open("/etc/kanki/panel.json"))["port"])')"
BASE="$(python3 -c 'import json;print(json.load(open("/etc/kanki/panel.json"))["base_path"])')"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null && ok "Firewall: opened ${PORT}/tcp"
fi

# ---------- 6. done ----------
echo
echo -e "${G}══════════════════════════════════════════════${N}"
echo -e "  ${Y}Kanki Tunnel is running${N}"
echo -e "  Panel:    ${Y}https://${PUBLIC_IP:-SERVER_IP}:${PORT}/${BASE}/${N}"
if [[ -n "$NEW_PASS" ]]; then
  echo -e "  Password: ${Y}${NEW_PASS}${N}   ${D}(shown once - save it)${N}"
else
  echo -e "  Password: unchanged   ${D}(change with: kanki password)${N}"
fi
echo -e "${G}══════════════════════════════════════════════${N}"
echo -e "  ${D}The browser warns about the certificate at first (self-signed)."
echo -e "  That's expected. For a real certificate: kanki ssl your.domain${N}"
echo -e "  Manage from the terminal any time:  ${Y}kanki${N}"
echo
