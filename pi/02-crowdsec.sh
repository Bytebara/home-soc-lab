#!/usr/bin/env bash
# 02-crowdsec.sh: install CrowdSec and its firewall bouncer, then prove they work.
#
#   ./02-crowdsec.sh                show what would happen (safe)
#   sudo ./02-crowdsec.sh --apply   install and test
#
# Run 01-harden.sh first: CrowdSec needs the log files it sets up.
#
# CrowdSec reads your logs and spots attacks (like SSH password guessing).
# The "bouncer" turns those decisions into firewall blocks.
# Note: CrowdSec ignores private home-network addresses by default, so you
# can't ban yourself by mistyping a password from your own computer.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

mode_banner
require_root_for_apply

TEST_IP="203.0.113.99"   # reserved for documentation, never a real host

# ---------------------------------------------------------------- 0. prerequisites
step "0. Checking prerequisites"
if [ -f /var/log/auth.log ]; then
  ok "/var/log/auth.log exists"
elif [ "$MODE" = "apply" ]; then
  fail "/var/log/auth.log is missing. Run 01-harden.sh --apply first."
else
  warn "/var/log/auth.log is missing; 01-harden.sh --apply creates it"
fi
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
  arm64|aarch64|amd64|x86_64) ok "64-bit system ($ARCH)" ;;
  *) fail "CrowdSec needs a 64-bit OS; this one is $ARCH. Re-image with Raspberry Pi OS Lite (64-bit)." ;;
esac

# ---------------------------------------------------------------- 1. repository
step "1. Adding the official CrowdSec package repository"
REPO_SCRIPT="/tmp/crowdsec-repo-setup.sh"
info "The official setup script is downloaded first, so you can read it before it runs."
if [ "$MODE" = "apply" ]; then
  if compgen -G "/etc/apt/sources.list.d/*crowdsec*" >/dev/null; then
    ok "CrowdSec repository already added"
  else
    curl -fsSL https://install.crowdsec.net -o "$REPO_SCRIPT"
    ok "downloaded to $REPO_SCRIPT ($(wc -l < "$REPO_SCRIPT") lines)"
    info "Read it now if you like, in another window:  less $REPO_SCRIPT"
    read -r -p "   Run it? [y/N] " answer
    case "$answer" in
      y|Y|yes) sh "$REPO_SCRIPT" ;;
      *) fail "Stopped before adding the repository. Nothing else was changed." ;;
    esac
  fi
else
  info "would download https://install.crowdsec.net to $REPO_SCRIPT, show it, and ask before running it"
fi

# ---------------------------------------------------------------- 2. install
step "2. Installing CrowdSec and the nftables firewall bouncer"
run apt-get update
run env DEBIAN_FRONTEND=noninteractive apt-get -y install crowdsec
run env DEBIAN_FRONTEND=noninteractive apt-get -y install crowdsec-firewall-bouncer-nftables

# ---------------------------------------------------------------- 3. verify
step "3. Checking it's running"
if [ "$MODE" = "apply" ]; then
  if systemctl is-active --quiet crowdsec; then
    ok "crowdsec service is running"
  else
    fail "crowdsec service isn't running. See: sudo journalctl -u crowdsec -n 50"
  fi
  if systemctl is-active --quiet crowdsec-firewall-bouncer; then
    ok "firewall bouncer is running"
  else
    warn "bouncer isn't running yet. See: sudo journalctl -u crowdsec-firewall-bouncer -n 50"
  fi
  info "Installed detection collections (look for crowdsecurity/linux and crowdsecurity/sshd):"
  cscli collections list 2>/dev/null | sed 's/^/      /' | head -20
  info "Registered bouncers:"
  cscli bouncers list 2>/dev/null | sed 's/^/      /'
else
  info "would check both services are running and list collections and bouncers"
fi

# ---------------------------------------------------------------- 4. test detection
step "4. Testing detection with a fake log line"
SAMPLE="$(date '+%b %e %H:%M:%S') $(hostname) sshd[4242]: Invalid user admin from $TEST_IP port 51515"
info "Asking CrowdSec how it would handle a fake SSH attack line (nothing real happens):"
info "  $SAMPLE"
run cscli explain --log "$SAMPLE" --type syslog

# ---------------------------------------------------------------- 5. test blocking
step "5. Testing the firewall block with a documentation-only address"
info "Adds a 2-minute ban on $TEST_IP (an address reserved for examples), shows it, then removes it."
run cscli decisions add --ip "$TEST_IP" --duration 2m --reason "Quiet Signal lab test"
if [ "$MODE" = "apply" ]; then
  sleep 12   # the bouncer checks for new decisions every 10 seconds
  cscli decisions list 2>/dev/null | sed 's/^/      /'
  if grep -q "$TEST_IP" <<<"$(nft list ruleset 2>/dev/null)"; then
    ok "the firewall now blocks $TEST_IP: detection to block works end to end"
  else
    warn "ban recorded but not yet in the firewall; check:  sudo nft list ruleset | grep $TEST_IP"
  fi
fi
run cscli decisions delete --ip "$TEST_IP"

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "CrowdSec is protecting this Pi."
  cat <<'EOF'

Handy commands:
   sudo cscli metrics            what CrowdSec is reading and detecting
   sudo cscli alerts list        attacks it has seen
   sudo cscli decisions list     who is currently blocked
   sudo cscli decisions delete --ip <address>    unblock an address

Screenshot steps 3 to 5 for your lab notebook (redact your hostname first).
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
