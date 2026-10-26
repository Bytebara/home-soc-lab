#!/usr/bin/env bash
# 07-tailscale.sh: join this machine to your private Tailscale network, so you can reach
# your lab from anywhere without opening anything on your router.
# Works on the Pi AND on the Ubuntu PC (run it on each).
#
#   ./07-tailscale.sh                 show the plan (safe, changes nothing)
#   sudo ./07-tailscale.sh --apply    do it
#
# What it does:
#   1. Adds Tailscale's official, signed package repository and installs Tailscale.
#   2. Connects this machine: it prints a link; open it and approve with your Tailscale account.
#      Only this machine joins. It does NOT share your home network (no subnet routing),
#      is NOT an exit node, and does NOT change this machine's DNS (Pi-hole stays in charge).
#   3. Firewall: allows SSH from your Tailscale devices only (the tailscale0 interface).
#      Splunk's web page stays closed; reach it through an SSH tunnel as you do at home.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

mode_banner
require_root_for_apply

# ---------------------------------------------------------------- 0. checks
step "0. Checking this machine"
[ -r /etc/os-release ] || fail "Can't tell which system this is (/etc/os-release missing)."
# shellcheck disable=SC1091
. /etc/os-release
DISTRO="${ID:-}"
CODENAME="${VERSION_CODENAME:-}"
case "$DISTRO" in
  debian|ubuntu) ok "system: ${PRETTY_NAME:-$DISTRO} ($CODENAME)" ;;
  raspbian) DISTRO="debian"; ok "system: ${PRETTY_NAME:-Raspberry Pi OS} ($CODENAME)" ;;
  *) fail "This script supports Debian, Raspberry Pi OS and Ubuntu; this is '${ID:-unknown}'." ;;
esac
[ -n "$CODENAME" ] || fail "Couldn't find the system's release name."
command -v ufw >/dev/null 2>&1 || fail "ufw isn't installed. Set up the firewall first (01-harden.sh on the Pi)."
ok "ufw firewall found"
if command -v tailscale >/dev/null 2>&1; then
  INSTALLED=yes
  ok "Tailscale already installed"
else
  INSTALLED=no
fi
ok "this machine will appear in Tailscale as: $(hostname)"

# ---------------------------------------------------------------- 1. install
step "1. Installing Tailscale from its official repository"
KEY_URL="https://pkgs.tailscale.com/stable/$DISTRO/$CODENAME.noarmor.gpg"
LIST_URL="https://pkgs.tailscale.com/stable/$DISTRO/$CODENAME.tailscale-keyring.list"
if [ "$INSTALLED" = "yes" ]; then
  info "skipping (already installed; automatic updates keep it patched)"
elif [ "$MODE" = "apply" ]; then
  if ! command -v curl >/dev/null 2>&1; then
    env DEBIAN_FRONTEND=noninteractive apt-get -y install curl ca-certificates
  fi
  if ! curl -fsSL "$KEY_URL" -o /usr/share/keyrings/tailscale-archive-keyring.gpg; then
    fail "Couldn't download $KEY_URL (no internet, or no Tailscale repository for $DISTRO '$CODENAME'). Nothing was changed."
  fi
  ok "saved Tailscale's signing key"
  curl -fsSL "$LIST_URL" -o /etc/apt/sources.list.d/tailscale.list
  ok "added /etc/apt/sources.list.d/tailscale.list"
  apt-get update
  env DEBIAN_FRONTEND=noninteractive apt-get -y install tailscale
  ok "Tailscale installed"
else
  info "would download Tailscale's signing key:  $KEY_URL"
  info "would add its repository list:            $LIST_URL"
  info "would run: apt-get update && apt-get -y install tailscale"
fi

# ---------------------------------------------------------------- 2. connect
step "2. Connecting this machine to your Tailscale account"
if [ "$MODE" = "apply" ]; then
  systemctl enable --now tailscaled >/dev/null 2>&1 || true
  if tailscale status >/dev/null 2>&1; then
    ok "already connected"
  else
    info "A link appears below. Open it in a browser, sign in to Tailscale, and approve this machine."
    info "(This window waits until you do.)"
    tailscale up --accept-dns=false --accept-routes=false
    ok "connected"
  fi
  TS_IP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
  [ -n "$TS_IP" ] && ok "this machine's Tailscale address: $TS_IP"
else
  info "would run: tailscale up --accept-dns=false --accept-routes=false"
  info "  --accept-dns=false     keeps this machine's own DNS settings (Pi-hole stays in charge)"
  info "  --accept-routes=false  doesn't route other networks through Tailscale"
  info "  (no --advertise-routes, no --advertise-exit-node: only this machine is shared)"
fi

# ---------------------------------------------------------------- 3. firewall
step "3. Firewall: SSH from your Tailscale devices"
run ufw allow in on tailscale0 to any port 22 proto tcp comment 'SSH from Tailscale devices'

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "This machine is on your Tailscale network."
  cat <<EOF

Its Tailscale address: ${TS_IP:-run 'tailscale ip -4'}
From any of your Tailscale devices:   ssh $(admin_user)@${TS_IP:-<tailscale-address>}

Status any time:   tailscale status
Disconnect:        sudo tailscale down     (reconnect: sudo tailscale up --accept-dns=false)
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
