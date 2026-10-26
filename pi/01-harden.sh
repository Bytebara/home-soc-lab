#!/usr/bin/env bash
# 01-harden.sh: lock down a fresh Raspberry Pi.
#
#   ./01-harden.sh                 show what would change (safe, changes nothing)
#   sudo ./01-harden.sh --apply    make the changes
#   sudo ./01-harden.sh --apply --lan 192.168.1.0/24   set your home network yourself
#
# What it does, in order:
#   1. Checks you can log in with an SSH key, so turning off passwords can't lock you out.
#   2. Installs updates and turns on automatic security updates.
#   3. Adds classic log files (/var/log/auth.log etc.) that CrowdSec and Splunk read.
#   4. SSH: keys only, no root login, fewer login attempts.
#   5. Firewall (ufw): block everything coming in except SSH from your home network.
#
# Keep your current SSH session open while this runs. Test a NEW login before closing it.

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
USER_NAME="$(admin_user)"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"

# ---------------------------------------------------------------- 1. key check
step "1. Making sure '$USER_NAME' can log in with an SSH key"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
if [ "$USER_NAME" = "root" ]; then
  fail "Run this as your normal user with sudo, not as root, so the script knows whose key to protect."
fi
if [ ! -s "$AUTH_KEYS" ]; then
  fail "No SSH key found in $AUTH_KEYS.
   Turning off passwords now would lock you out. Fix first:
   - Re-image with Raspberry Pi Imager and paste your public key in the SSH settings, or
   - From your computer run:  ssh-copy-id $USER_NAME@<pi-address>"
fi
if ! grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ' "$AUTH_KEYS"; then
  fail "$AUTH_KEYS exists but contains no valid public key line. Not continuing."
fi
ok "$(grep -Ec '^(ssh-|ecdsa-|sk-)' "$AUTH_KEYS") key(s) found for $USER_NAME"
if [ -n "${SSH_CONNECTION:-}" ]; then
  ok "you're connected over SSH right now; keep this session open until step 5's test passes"
fi

# ---------------------------------------------------------------- 2. updates
step "2. Updates and automatic security updates"
run apt-get update
run env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
run env DEBIAN_FRONTEND=noninteractive apt-get -y install unattended-upgrades apt-listchanges
write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
// Written by Quiet Signal lab kit: check daily and install security updates automatically.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# ---------------------------------------------------------------- 3. log files
step "3. Classic log files for CrowdSec and Splunk"
if [ -f /var/log/auth.log ]; then
  ok "/var/log/auth.log already exists"
else
  info "Raspberry Pi OS keeps logs only in the systemd journal by default."
  info "rsyslog copies them into plain files like /var/log/auth.log, which both tools read."
  run env DEBIAN_FRONTEND=noninteractive apt-get -y install rsyslog
  run systemctl enable --now rsyslog
fi

# ---------------------------------------------------------------- 4. SSH
step "4. SSH: keys only"
write_file /etc/ssh/sshd_config.d/10-quiet-signal.conf 0644 <<EOF
# Written by Quiet Signal lab kit. Delete this file and run 'sudo systemctl reload ssh' to undo.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers $USER_NAME
EOF
if [ "$MODE" = "apply" ]; then
  if sshd -t; then
    ok "SSH configuration is valid"
    run systemctl reload ssh
    ok "SSH reloaded. Your current session stays connected."
  else
    rm -f /etc/ssh/sshd_config.d/10-quiet-signal.conf
    fail "SSH rejected the new settings, so they were removed and nothing changed."
  fi
else
  info "would check the settings with 'sshd -t' and only reload SSH if they're valid"
fi

# ---------------------------------------------------------------- 5. firewall
step "5. Firewall"
if [ -z "$LAN" ] && command -v ip >/dev/null 2>&1; then
  IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  if [ -n "$IFACE" ]; then
    LAN="$(ip -o -f inet addr show "$IFACE" | awk '{print $4; exit}')"
    # Turn host address (192.168.1.57/24) into the network (192.168.1.0/24).
    if [ -n "$LAN" ] && command -v python3 >/dev/null; then
      LAN="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$LAN")"
    fi
  fi
fi
if [ -z "$LAN" ]; then
  fail "Couldn't work out your home network. Run again with it set, e.g.  --lan 192.168.1.0/24"
fi
case "$LAN" in
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ok "home network: $LAN" ;;
  *) fail "$LAN isn't a private home network range. Refusing to open SSH to it. Use --lan to set it." ;;
esac
run env DEBIAN_FRONTEND=noninteractive apt-get -y install ufw
run ufw default deny incoming
run ufw default allow outgoing
run ufw allow from "$LAN" to any port 22 proto tcp comment 'SSH from home network'
run ufw logging low
run ufw --force enable

# ---------------------------------------------------------------- done
step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Pi hardened."
  printf '\n%sBefore you close this window:%s open a NEW terminal on your computer and run\n' "$BOLD" "$RESET"
  printf '   ssh %s@%s\n' "$USER_NAME" "$(hostname).local"
  printf 'If that works, you are done. If it fails, use THIS session to undo:\n'
  printf '   sudo ufw disable\n   sudo rm /etc/ssh/sshd_config.d/10-quiet-signal.conf && sudo systemctl reload ssh\n'
  printf '\nCheck status any time with:  sudo ufw status verbose\n'
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s --apply\n' "$0"
fi
