#!/usr/bin/env bash
# 06-encrypt-dns.sh: encrypt Pi-hole's lookups to Quad9 (DNS over TLS), so your internet
# provider can't read which sites are looked up.
#
#   ./06-encrypt-dns.sh                 show the plan (safe, changes nothing)
#   sudo ./06-encrypt-dns.sh --apply    do it
#
# How it works:
#   Before: device -> Pi-hole -> Quad9 on port 53 (plain text; your provider can read it)
#   After:  device -> Pi-hole -> Unbound (on the Pi, 127.0.0.1:5335) -> Quad9 on port 853,
#           encrypted with TLS and checked against Quad9's certificate (dns.quad9.net)
#
#   1. Writes Unbound's settings BEFORE installing it. (Otherwise Debian's Unbound starts on
#      port 53 right away and fights Pi-hole for it.)
#   2. Installs Unbound (Debian's package, patched by automatic updates) and tests it alone.
#   3. Only if that works, points Pi-hole at it. If Pi-hole then can't look things up,
#      it switches straight back to plain Quad9, so DNS never stays broken.
#   4. Proves the encryption: asks Quad9 which protocol it received ("dot" = encrypted).
#
# Note: your provider can still see that you talk to Quad9, just not what you look up.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

mode_banner
require_root_for_apply

DOT_PORT=5335                     # Unbound, Pi only. 53 = Pi-hole, 8080 = CrowdSec, 8081 = Caddy, 8082 = Pi-hole dashboard
CONF="/etc/unbound/unbound.conf.d/qs-quad9-dot.conf"
ENCRYPTED_UPSTREAM='["127.0.0.1#5335"]'
PLAIN_UPSTREAM='["9.9.9.9","149.112.112.112"]'

# ---------------------------------------------------------------- 0. checks
step "0. Checking the Pi"
command -v ss >/dev/null 2>&1 || fail "The 'ss' tool is missing. Install it with: sudo apt-get install iproute2"
command -v pihole-FTL >/dev/null 2>&1 || fail "Pi-hole isn't installed. Run 05-pihole.sh --apply first."
ok "Pi-hole found"
LISTENER="$(ss -Hlntup "sport = :$DOT_PORT" 2>/dev/null || true)"
if [ -z "$LISTENER" ]; then
  ok "port $DOT_PORT is free for Unbound"
elif grep -q '"unbound"' <<<"$LISTENER"; then
  ok "port $DOT_PORT is already Unbound's"
elif [ "$(id -u)" -ne 0 ]; then
  warn "something is listening on port $DOT_PORT (run with sudo to see which program)"
else
  fail "Port $DOT_PORT is already in use by another program:
   $LISTENER
   Find out which program it is before going on:  sudo ss -ltnup"
fi
IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
PI_IP="$(ip -o -f inet addr show "$IFACE" 2>/dev/null | awk '{print $4; exit}')"
PI_IP="${PI_IP%/*}"
[ -n "$PI_IP" ] || fail "Couldn't find the Pi's address."
ok "Pi address $PI_IP"

# ---------------------------------------------------------------- 1. settings
step "1. Unbound settings (written before installing)"
write_file "$CONF" 0644 <<EOF
# Written by Quiet Signal lab kit (06-encrypt-dns.sh).
# Unbound takes Pi-hole's lookups and sends them to Quad9 encrypted (DNS over TLS, port 853).
server:
    # Only the Pi itself can use it (Pi-hole). Never opened to the network.
    interface: 127.0.0.1
    port: $DOT_PORT
    do-ip6: no
    access-control: 127.0.0.0/8 allow

    # Check Quad9's certificate with the system's trusted list.
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

    # Privacy and speed
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    prefetch: yes
    verbosity: 0

forward-zone:
    name: "."
    forward-tls-upstream: yes
    # address@port#name-on-the-certificate
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
EOF

# ---------------------------------------------------------------- 2. install + test Unbound
step "2. Installing Unbound and testing it on its own"
run env DEBIAN_FRONTEND=noninteractive apt-get -y install unbound ca-certificates bind9-dnsutils
if [ "$MODE" = "apply" ]; then
  # Debian's helper would make the Pi itself use Unbound; Pi-hole is the only user we want.
  if systemctl cat unbound-resolvconf.service >/dev/null 2>&1; then
    systemctl disable --now unbound-resolvconf.service >/dev/null 2>&1 || true
    ok "turned off unbound-resolvconf (the Pi's own DNS settings stay as they are)"
  fi
  # Unbound's DNSSEC key file is normally created when the service first starts; make sure it
  # exists now, because the settings check below refuses to pass without it.
  if [ ! -f /var/lib/unbound/root.key ] && [ -x /usr/libexec/unbound-helper ]; then
    /usr/libexec/unbound-helper root_trust_anchor_update || true
  fi
  if unbound-checkconf >/dev/null 2>&1; then
    ok "Unbound configuration is valid"
  else
    unbound-checkconf || true
    fail "Unbound rejected the configuration (details above). Pi-hole wasn't changed."
  fi
  systemctl enable unbound >/dev/null 2>&1 || true
  if ! systemctl restart unbound; then
    journalctl -u unbound -n 15 --no-pager | sed 's/^/      /'
    fail "Unbound didn't start (its log is above). Pi-hole wasn't changed."
  fi
  sleep 3
  ANSWER=""
  for _ in 1 2 3; do
    ANSWER="$(dig +short +time=5 +tries=1 @127.0.0.1 -p "$DOT_PORT" example.com A 2>/dev/null | tail -1 || true)"
    [ -n "$ANSWER" ] && break
    sleep 2
  done
  if [ -n "$ANSWER" ]; then
    ok "Unbound answers through the encrypted link (example.com -> $ANSWER)"
  else
    fail "Unbound didn't get an answer from Quad9 over port 853. Pi-hole wasn't changed.
   See: sudo journalctl -u unbound -n 30"
  fi
else
  info "would turn off unbound-resolvconf if present, validate the settings, start Unbound,"
  info "and test a lookup through it before touching Pi-hole"
fi

# ---------------------------------------------------------------- 3. switch Pi-hole
step "3. Pointing Pi-hole at Unbound"
run pihole-FTL --config dns.upstreams "$ENCRYPTED_UPSTREAM"
if [ "$MODE" = "apply" ]; then
  sleep 2
  ANSWER="$(dig +short +time=5 +tries=2 @"$PI_IP" example.com A 2>/dev/null | tail -1 || true)"
  if [ -n "$ANSWER" ]; then
    ok "Pi-hole answers through Unbound (example.com -> $ANSWER)"
  else
    warn "Pi-hole couldn't look things up through Unbound. Switching back to plain Quad9."
    pihole-FTL --config dns.upstreams "$PLAIN_UPSTREAM" >/dev/null
    fail "Switched back; DNS works as before. See why with:  sudo journalctl -u unbound -n 30"
  fi
  BLOCKED="$(dig +short +time=5 +tries=2 @"$PI_IP" doubleclick.net A 2>/dev/null | tail -1 || true)"
  if [ "$BLOCKED" = "0.0.0.0" ]; then ok "ad blocking still works (doubleclick.net -> 0.0.0.0)"; else warn "doubleclick.net gave '$BLOCKED', expected 0.0.0.0"; fi
fi

# ---------------------------------------------------------------- 4. prove it
step "4. Proving the lookups are encrypted"
if [ "$MODE" = "apply" ]; then
  # Quad9 answers this name with the protocol it received the question over.
  PROTO="$(dig +short +time=5 +tries=2 @"$PI_IP" TXT proto.on.quad9.net 2>/dev/null | tr -d '"' | tail -1 || true)"
  case "$PROTO" in
    dot) ok "Quad9 says it received the lookup over DNS over TLS (\"dot\")" ;;
    "")  warn "Quad9's protocol check didn't answer; the connection check below still applies" ;;
    *)   warn "Quad9 says it received the lookup as \"$PROTO\", not \"dot\". Check: sudo journalctl -u unbound -n 30" ;;
  esac
  CONNS="$(ss -Htnp state established '( dport = :853 )' 2>/dev/null || true)"
  if grep -q '"unbound"' <<<"$CONNS"; then
    ok "Unbound has an encrypted connection open to Quad9 on port 853"
  else
    info "No port 853 connection open right now (Unbound closes idle ones; fine if the check above passed)"
  fi
else
  info "would ask Quad9 which protocol it received (expect \"dot\") and check for port 853 connections"
fi

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Pi-hole's lookups to Quad9 are now encrypted."
  cat <<EOF

Check from Windows (VPN off):   nslookup -type=txt proto.on.quad9.net
  The answer should say "dot".

Undo (back to plain Quad9):     sudo pihole-FTL --config dns.upstreams '$PLAIN_UPSTREAM'
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
