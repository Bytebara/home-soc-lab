#!/usr/bin/env bash
# 08-pihole-tailscale.sh: let your Tailscale devices (like your phone) use Pi-hole from
# anywhere, so ads and trackers are blocked on mobile data too and their lookups reach Splunk.
#
#   ./08-pihole-tailscale.sh                 show the plan (safe, changes nothing)
#   sudo ./08-pihole-tailscale.sh --apply    do it
#
# Run 05-pihole.sh and 07-tailscale.sh on the Pi first.
#
# Why the listening mode changes: Pi-hole's "LOCAL" mode only answers devices on the Pi's own
# networks. Tailscale devices come from 100.x addresses that aren't one, so Pi-hole would refuse
# them. "ALL" answers anyone who can reach port 53, so the firewall becomes the gatekeeper.
# This script refuses to switch unless the firewall blocks incoming traffic by default, and it
# opens port 53 only to your home network (already) and to Tailscale (added here).
#
# Afterwards, one setting in the Tailscale admin page makes your devices use the Pi (see the end).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

mode_banner
require_root_for_apply

MARKER="/etc/pihole/qs-tailscale-dns"

# ---------------------------------------------------------------- 0. checks
step "0. Checking the Pi"
command -v pihole-FTL >/dev/null 2>&1 || fail "Pi-hole isn't installed. Run 05-pihole.sh --apply first."
ok "Pi-hole found"
command -v tailscale >/dev/null 2>&1 || fail "Tailscale isn't installed. Run 07-tailscale.sh --apply first."
TS_IP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
[ -n "$TS_IP" ] || fail "Tailscale isn't connected on this Pi. Run: sudo tailscale up --accept-dns=false"
ok "Pi's Tailscale address: $TS_IP"
if [ "$(id -u)" -eq 0 ]; then
  UFW_STATUS="$(ufw status verbose 2>/dev/null || true)"
  grep -q "Status: active" <<<"$UFW_STATUS" || fail "The firewall (ufw) isn't active. Pi-hole can't answer everyone without it."
  grep -q "deny (incoming)" <<<"$UFW_STATUS" || fail "The firewall doesn't block incoming traffic by default. Not switching Pi-hole to ALL."
  ok "firewall is on and blocks incoming traffic by default"
else
  info "Can't check the firewall without sudo; the --apply run checks it before changing anything."
fi

# ---------------------------------------------------------------- 1. firewall
step "1. Firewall: DNS from your Tailscale devices"
run ufw allow in on tailscale0 to any port 53 proto udp comment 'Pi-hole DNS from Tailscale devices'
run ufw allow in on tailscale0 to any port 53 proto tcp comment 'Pi-hole DNS from Tailscale devices'

# ---------------------------------------------------------------- 2. Pi-hole
step "2. Pi-hole: answer Tailscale devices too"
run pihole-FTL --config dns.listeningMode ALL
write_file "$MARKER" 0644 <<'EOF'
# Written by Quiet Signal lab kit (08-pihole-tailscale.sh): Pi-hole also serves Tailscale devices.
# 05-pihole.sh sees this file and keeps dns.listeningMode = ALL. Delete it to go back to LOCAL.
EOF

# ---------------------------------------------------------------- 3. test
step "3. Testing through the Tailscale address"
if [ "$MODE" = "apply" ]; then
  sleep 2
  ANSWER="$(dig +short +time=5 +tries=2 @"$TS_IP" example.com A 2>/dev/null | tail -1 || true)"
  if [ -n "$ANSWER" ]; then
    ok "Pi-hole answers on $TS_IP (example.com -> $ANSWER)"
  else
    warn "No answer on $TS_IP. Going back to LOCAL mode."
    pihole-FTL --config dns.listeningMode LOCAL >/dev/null
    rm -f "$MARKER"
    fail "Switched back; nothing else changed. See why with:  sudo journalctl -u pihole-FTL -n 30"
  fi
  BLOCKED="$(dig +short +time=5 +tries=2 @"$TS_IP" doubleclick.net A 2>/dev/null | tail -1 || true)"
  if [ "$BLOCKED" = "0.0.0.0" ]; then ok "ad blocking works there too (doubleclick.net -> 0.0.0.0)"; else warn "doubleclick.net gave '$BLOCKED', expected 0.0.0.0"; fi
else
  info "would look up example.com and doubleclick.net through $TS_IP; if that fails it switches back to LOCAL"
fi

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Pi-hole now answers your Tailscale devices."
  cat <<EOF

Last step, in a browser: login.tailscale.com > DNS
  1. Nameservers > Add nameserver > Custom:  $TS_IP
  2. Turn on "Override DNS servers" (it may say "Override local DNS").
Then on the phone, in the Tailscale app settings, make sure "Use Tailscale DNS" is on.

Your Pi and Ubuntu PC ignore this (they joined with --accept-dns=false).
If the Pi is off, devices with Tailscale switched on can't look up names: switch Tailscale off.

Undo:  sudo pihole-FTL --config dns.listeningMode LOCAL && sudo rm $MARKER
       (and remove the nameserver in the Tailscale admin page)
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
