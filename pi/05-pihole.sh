#!/usr/bin/env bash
# 05-pihole.sh: Pi-hole on the Pi. Blocks ads, trackers and bad domains for any device
# that uses the Pi for DNS, and sends every lookup to Splunk.
#
#   ./05-pihole.sh                 show the plan (safe, changes nothing)
#   sudo ./05-pihole.sh --apply    do it
#   sudo ./05-pihole.sh --apply --lan 192.168.1.0/24   set your home network yourself
#
# What it does:
#   0. Checks DNS port 53 and dashboard port 8082 are free. (8080 is CrowdSec's and 8081 is
#      Caddy's. Pi-hole would otherwise grab 80/443 or fall back to 8080 and break CrowdSec.)
#   1. Writes Pi-hole's settings file BEFORE installing, so the installer runs without
#      questions: upstream DNS = Quad9 (which also blocks known malware domains),
#      answer only devices on your home network, DHCP off (your router keeps doing that).
#   2. Downloads Pi-hole's official installer, shows its fingerprint, asks, then runs it.
#   3. Lets you set your own dashboard password (hidden as you type).
#   4. Firewall: DNS (53) and the dashboard (8082) open to your home network only.
#   5. Tests: lookups work, an ad domain is blocked, and CrowdSec and the website still run.
#   6. Sends the query log to Splunk (sourcetype pihole) with read-only access.
#
# Nothing on your network changes until you point a device's DNS at the Pi. Start with one
# computer, so the rest of the house isn't affected if the Pi is ever off.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

LAN=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--lan" ]; then LAN="$arg"; fi
  prev="$arg"
done

mode_banner
require_root_for_apply

WEB_PORT=8082                       # 8080 = CrowdSec local API, 8081 = Caddy (website)
UPSTREAM_1="9.9.9.9"                # Quad9: privacy-focused, blocks known malicious domains
UPSTREAM_2="149.112.112.112"
TOML="/etc/pihole/pihole.toml"
FWD_HOME="/opt/splunkforwarder"
FWD_USER="splunkfwd"
DNS_APP_SRC="$HERE/../splunk/forwarder-app/qs_pilab_dns"
DNS_APP_DST="$FWD_HOME/etc/apps/qs_pilab_dns"
TEST_AD_DOMAIN="doubleclick.net"    # on Pi-hole's default blocklist

# Is something other than <allowed> listening on <port>? Prints ok/warn, or stops.
check_port() {
  local port="$1" allowed="$2" what="$3" listener
  listener="$(ss -Hlntup "sport = :$port" 2>/dev/null || true)"
  if [ -z "$listener" ]; then
    ok "port $port is free for $what"
  elif grep -q "\"$allowed\"" <<<"$listener"; then
    ok "port $port is already Pi-hole's"
  elif [ "$(id -u)" -ne 0 ]; then
    warn "something is listening on port $port (run with sudo to see which program)"
  else
    fail "Port $port is already in use by another program:
   $listener
   Pi-hole can't share it. Tell Claude which program it is."
  fi
}

# Set one Pi-hole setting with Pi-hole's own tool (it checks the value and applies it).
ftl_set() {
  run pihole-FTL --config "$1" "$2"
}

# ---------------------------------------------------------------- 0. checks
step "0. Checking the Pi"
command -v ss >/dev/null 2>&1 || fail "The 'ss' tool is missing, so ports can't be checked. Install it with: sudo apt-get install iproute2"
IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
[ -n "$IFACE" ] || fail "Couldn't find the Pi's network connection (no default route). Is the network cable in?"
PI_CIDR="$(ip -o -f inet addr show "$IFACE" | awk '{print $4; exit}')"
PI_IP="${PI_CIDR%/*}"
[ -n "$PI_IP" ] || fail "The Pi has no IPv4 address on $IFACE."
ok "network: $IFACE, Pi address $PI_IP"
if [ -z "$LAN" ]; then
  LAN="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$PI_CIDR")"
fi
case "$LAN" in
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ok "home network: $LAN" ;;
  *) fail "$LAN isn't a private home network range. Refusing to open DNS to it. Use --lan to set it." ;;
esac
check_port 53 pihole-FTL "DNS"
check_port "$WEB_PORT" pihole-FTL "the Pi-hole dashboard"
if command -v pihole >/dev/null 2>&1; then
  INSTALLED=yes
  ok "Pi-hole is already installed (settings will be re-applied, nothing reinstalled)"
else
  INSTALLED=no
  ok "Pi-hole isn't installed yet"
fi
if command -v ufw >/dev/null 2>&1; then ok "ufw firewall found"; else fail "ufw isn't installed. Run 01-harden.sh --apply first."; fi
if [ -x "$FWD_HOME/bin/splunk" ]; then ok "Splunk forwarder found"; else warn "Splunk forwarder not found; DNS logs won't reach Splunk until 03-splunk-forwarder.sh is run"; fi

# ---------------------------------------------------------------- 1. settings
step "1. Pi-hole settings (written before installing)"
info "Upstream DNS: Quad9 ($UPSTREAM_1, $UPSTREAM_2). Answers: home network only."
info "Dashboard: port $WEB_PORT. DHCP: off (your router keeps handing out addresses)."
if [ "$INSTALLED" = "no" ] && [ ! -f "$TOML" ]; then
  write_file "$TOML" 0644 <<EOF
# Pre-seeded by Quiet Signal lab kit (05-pihole.sh) so Pi-hole's installer runs without
# questions. Pi-hole adds every other setting, with its defaults, the first time it starts.
# Change settings later in the dashboard (Settings > All settings) or with
#   sudo pihole-FTL --config <setting> <value>

[dns]
  upstreams = ["$UPSTREAM_1", "$UPSTREAM_2"]
  interface = "$IFACE"
  listeningMode = "LOCAL"
  queryLogging = true

[dhcp]
  active = false

[webserver]
  port = "$WEB_PORT"
EOF
else
  info "Pi-hole's settings file already exists, so each setting is applied with pihole-FTL instead."
fi

# ---------------------------------------------------------------- 2. install
step "2. Installing Pi-hole (official installer)"
INSTALLER="/tmp/qs-pihole-install.sh"
if [ "$INSTALLED" = "yes" ]; then
  ok "already installed"
elif [ "$MODE" = "apply" ]; then
  curl -fsSL https://install.pi-hole.net -o "$INSTALLER"
  ok "downloaded to $INSTALLER ($(wc -l < "$INSTALLER") lines)"
  info "Fingerprint (SHA-256): $(sha256sum "$INSTALLER" | awk '{print $1}')"
  info "Read it now if you like, in another window:  less $INSTALLER"
  read -r -p "   Run Pi-hole's installer? [y/N] " answer
  case "$answer" in
    y|Y|yes) bash "$INSTALLER" --unattended ;;
    *) fail "Stopped before installing. Only the settings file ($TOML) was written." ;;
  esac
  command -v pihole >/dev/null 2>&1 || fail "The installer finished but 'pihole' isn't there. Scroll up for its error."
  ok "Pi-hole installed"
else
  info "would download https://install.pi-hole.net to $INSTALLER, show its fingerprint,"
  info "ask before running it, then run it with --unattended (it reads the settings above)"
fi

info "Making sure each setting is in place (the installer can change some):"
# If 06-encrypt-dns.sh has set up encrypted lookups, keep using them instead of plain Quad9.
if [ -f /etc/unbound/unbound.conf.d/qs-quad9-dot.conf ]; then
  info "Encrypted lookups (06-encrypt-dns.sh) are set up, so the upstream stays 127.0.0.1#5335."
  ftl_set dns.upstreams '["127.0.0.1#5335"]'
else
  ftl_set dns.upstreams "[\"$UPSTREAM_1\",\"$UPSTREAM_2\"]"
fi
ftl_set dns.interface "$IFACE"
# 08-pihole-tailscale.sh switches to ALL (the firewall then decides who can ask); keep that on re-runs.
if [ -f /etc/pihole/qs-tailscale-dns ]; then
  info "Pi-hole also serves your Tailscale devices (08-pihole-tailscale.sh), so listening mode stays ALL."
  ftl_set dns.listeningMode ALL
else
  ftl_set dns.listeningMode LOCAL
fi
ftl_set dns.queryLogging true
ftl_set dhcp.active false
ftl_set webserver.port "$WEB_PORT"
if [ "$MODE" = "apply" ]; then
  systemctl restart pihole-FTL
  sleep 5
  systemctl is-active --quiet pihole-FTL || fail "Pi-hole didn't start. See: sudo journalctl -u pihole-FTL -n 30"
  GOT_PORT="$(pihole-FTL --config webserver.port 2>/dev/null || true)"
  if [ "$GOT_PORT" = "$WEB_PORT" ]; then ok "dashboard port is $WEB_PORT"; else fail "Dashboard port reads back as '$GOT_PORT', not $WEB_PORT. Tell Claude."; fi
  GOT_DHCP="$(pihole-FTL --config dhcp.active 2>/dev/null || true)"
  if [ "$GOT_DHCP" = "false" ]; then ok "DHCP is off"; else fail "Pi-hole's DHCP reads back as '$GOT_DHCP'. Turn it off before anything else: sudo pihole-FTL --config dhcp.active false"; fi
  ok "Pi-hole is running"
fi

# ---------------------------------------------------------------- 3. password
step "3. Dashboard password"
if [ "$MODE" = "apply" ]; then
  info "The installer made a random password (printed above). Set your own now and save it"
  info "in Proton Pass. Typing is hidden. Never paste it into a chat."
  read -r -p "   Set the dashboard password now? [Y/n] " answer
  case "$answer" in
    n|N|no) info "Skipped. Set it any time with:  sudo pihole setpassword" ;;
    *) pihole setpassword || warn "Password not changed (the two didn't match?). Try again later:  sudo pihole setpassword" ;;
  esac
else
  info "would ask you to set the dashboard password (hidden) with 'pihole setpassword'"
fi

# ---------------------------------------------------------------- 4. firewall
step "4. Firewall: DNS and dashboard open to your home network only"
run ufw allow from "$LAN" to any port 53 proto udp comment 'Pi-hole DNS from home network'
run ufw allow from "$LAN" to any port 53 proto tcp comment 'Pi-hole DNS from home network'
run ufw allow from "$LAN" to any port "$WEB_PORT" proto tcp comment 'Pi-hole dashboard from home network'

# ---------------------------------------------------------------- 5. tests
step "5. Testing"
run env DEBIAN_FRONTEND=noninteractive apt-get -y install bind9-dnsutils
if [ "$MODE" = "apply" ]; then
  ANSWER="$(dig +short +time=3 +tries=2 @"$PI_IP" example.com A 2>/dev/null | tail -1 || true)"
  if [ -n "$ANSWER" ]; then ok "answers lookups from the network (example.com -> $ANSWER)"; else fail "Pi-hole didn't answer a lookup on $PI_IP. See: sudo journalctl -u pihole-FTL -n 30"; fi
  BLOCKED="$(dig +short +time=3 +tries=2 @"$PI_IP" "$TEST_AD_DOMAIN" A 2>/dev/null | tail -1 || true)"
  if [ "$BLOCKED" = "0.0.0.0" ]; then
    ok "blocks ad domains ($TEST_AD_DOMAIN -> 0.0.0.0)"
  else
    warn "$TEST_AD_DOMAIN wasn't blocked (got '$BLOCKED'). The blocklist may still be loading. Run: sudo pihole -g"
  fi
  if curl -fsS -o /dev/null "http://127.0.0.1:$WEB_PORT/admin/"; then ok "dashboard answers on port $WEB_PORT"; else warn "dashboard didn't answer on port $WEB_PORT. See: sudo journalctl -u pihole-FTL -n 30"; fi
  for p in 80 443; do
    if grep -q '"pihole-FTL"' <<<"$(ss -Hltnp "sport = :$p" 2>/dev/null || true)"; then
      warn "Pi-hole is also listening on port $p (only $WEB_PORT was asked for). Tell Claude."
    fi
  done
  for svc in crowdsec caddy cloudflared SplunkForwarder; do
    if ! systemctl cat "$svc.service" >/dev/null 2>&1; then continue; fi
    if systemctl is-active --quiet "$svc"; then ok "$svc still running"; else warn "$svc isn't running. See: sudo journalctl -u $svc -n 30"; fi
  done
else
  info "would test: a lookup through $PI_IP, that $TEST_AD_DOMAIN is blocked, the dashboard,"
  info "and that CrowdSec, Caddy, cloudflared and the Splunk forwarder are still running"
fi

# ---------------------------------------------------------------- 6. Splunk
step "6. Sending DNS lookups to Splunk"
if [ -x "$FWD_HOME/bin/splunk" ] || [ "$MODE" != "apply" ]; then
  [ -f "$DNS_APP_SRC/default/inputs.conf" ] || fail "The kit's qs_pilab_dns app is missing. Re-unzip the kit."
  run mkdir -p "$DNS_APP_DST"
  run cp -r "$DNS_APP_SRC/." "$DNS_APP_DST/"
  run chown -R "$FWD_USER:$FWD_USER" "$DNS_APP_DST"
  info "Read-only access to Pi-hole's log folder for the forwarder (new files inherit it):"
  run env DEBIAN_FRONTEND=noninteractive apt-get -y install acl
  if [ -d /var/log/pihole ] || [ "$MODE" != "apply" ]; then
    run setfacl -m "u:$FWD_USER:rx" /var/log/pihole
    run setfacl -d -m "u:$FWD_USER:r" /var/log/pihole
  fi
  write_log_acl_service "$FWD_USER"
  run systemctl daemon-reload
  run systemctl start qs-crowdsec-log-acl.service
  run systemctl restart SplunkForwarder
  if [ "$MODE" = "apply" ]; then
    if sudo -u "$FWD_USER" test -r /var/log/pihole/pihole.log; then
      ok "forwarder can read /var/log/pihole/pihole.log"
    else
      warn "forwarder can't read /var/log/pihole/pihole.log yet. Fix:  sudo systemctl start qs-crowdsec-log-acl.service"
    fi
  fi
else
  warn "Skipped: no Splunk forwarder on this Pi."
fi

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Pi-hole is running. Nothing on your network uses it yet."
  cat <<EOF

Dashboard (from a computer at home):  http://$PI_IP:$WEB_PORT/admin

Try it on ONE computer first: set that computer's DNS server to $PI_IP.
  Undo: set its DNS back to Automatic (DHCP).

In Splunk:  index=pilab sourcetype=pihole | stats count by dns_client
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
