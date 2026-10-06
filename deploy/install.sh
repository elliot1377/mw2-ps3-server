#!/bin/bash
# MW2 PS3 community server - install on a fresh Ubuntu / Debian VPS (run as root):
#   git clone https://github.com/elliot1377/mw2-ps3-server && bash mw2-ps3-server/deploy/install.sh
# Installs to /opt/mw2dw and starts two services: mw2-dw (DemonWare server) and mw2-dns (DNS for real PS3s), and
# opens the firewall ports. Re-run any time to update. Override the detected IP with PUBLIC_IP=1.2.3.4.
set -e
SRC="$(cd "$(dirname "$0")/../server" && pwd)"
DST=/opt/mw2dw
PUBLIC_IP="${PUBLIC_IP:-$(curl -4 -s https://api.ipify.org || true)}"
if [ -z "$PUBLIC_IP" ]; then echo "Could not detect the public IP - run: PUBLIC_IP=1.2.3.4 bash install.sh"; exit 1; fi
echo "Public IP: $PUBLIC_IP"

apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv >/dev/null
mkdir -p "$DST/files"
cp "$SRC"/dwserver.py "$SRC"/dwcore.py "$SRC"/dnsserver.py "$SRC"/tiger_sboxes.bin "$DST"/
cp -rn "$SRC"/files/. "$DST/files/"          # keep files edited on the server (playlists, MOTD)
python3 -m venv "$DST/venv"
"$DST/venv/bin/pip" install -q pycryptodome

# port 53 is often held by systemd-resolved's stub listener - free it (the VPS keeps resolving via upstream DNS)
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\nDNS=1.1.1.1 8.8.8.8\n' > /etc/systemd/resolved.conf.d/mw2dw.conf
  systemctl restart systemd-resolved
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
fi

cat > /etc/systemd/system/mw2-dw.service <<EOF
[Unit]
Description=MW2 PS3 DemonWare server
After=network-online.target
[Service]
WorkingDirectory=$DST
ExecStart=$DST/venv/bin/python $DST/dwserver.py --bind 0.0.0.0 --public-ip $PUBLIC_IP --log ""
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/mw2-dns.service <<EOF
[Unit]
Description=MW2 PS3 community DNS
After=network-online.target
[Service]
WorkingDirectory=$DST
ExecStart=/usr/bin/python3 $DST/dnsserver.py --ip $PUBLIC_IP --bind 0.0.0.0 --port 53
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mw2-dw mw2-dns
systemctl restart mw2-dw mw2-dns

if command -v ufw >/dev/null; then
  ufw allow 22/tcp >/dev/null
  ufw allow 53/udp >/dev/null
  ufw allow 3074/tcp >/dev/null
  ufw allow 3074/udp >/dev/null
  ufw --force enable >/dev/null
fi

echo
echo "Done. Services:"
systemctl --no-pager --lines=0 status mw2-dw mw2-dns | grep -E "Active|mw2-"
echo
echo "PS3 players:    Settings > Network > Internet Connection Settings > Custom > DNS manual: primary $PUBLIC_IP"
echo "RPCS3 players:  Install Online Fix.bat $PUBLIC_IP   (see docs/PLAYERS.md)"
echo "Logs:           journalctl -u mw2-dw -f    |   journalctl -u mw2-dns -f"
