"""Checks for the Quiet Signal lab kit. Run:  python3 tests/test_kit.py

- Every Splunk field extraction in props.conf pulls the right values from sample log lines.
- Every .conf file parses, and the dashboard XML is valid.
- Sample lines use documentation IP addresses only (RFC 5737), never real ones.
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "splunk" / "server-app" / "quiet_signal_lab"
failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def parse_conf(path):
    """Minimal Splunk .conf reader: [stanza] then key = value, with \\ line continuation."""
    stanzas, current, pending = {}, None, ""
    for raw in path.read_text().splitlines():
        line = pending + raw
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1]
            stanzas[current] = {}
            continue
        if "=" not in s or current is None:
            raise ValueError(f"{path.name}: bad line: {s}")
        key, value = s.split("=", 1)
        stanzas[current][key.strip()] = value.strip()
    return stanzas


def splunk_regex(pattern):
    """Splunk uses PCRE named groups (?<name>...); Python wants (?P<name>...)."""
    return re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", pattern))


# ---------------------------------------------------------------- conf files parse
confs = list(ROOT.rglob("*.conf")) + list(ROOT.rglob("*.conf.template")) + list(ROOT.rglob("*.meta"))
parsed = {}
for c in confs:
    try:
        parsed[c] = parse_conf(c)
        check(f"parses: {c.relative_to(ROOT)}", True)
    except Exception as e:  # noqa: BLE001
        check(f"parses: {c.relative_to(ROOT)}", False, str(e))

props = parse_conf(APP / "default" / "props.conf")
saved = parse_conf(APP / "default" / "savedsearches.conf")

# ---------------------------------------------------------------- extractions
# Synthetic lines in the formats OpenSSH, sudo, ufw and CrowdSec write.
CASES = [
    ("linux_secure", "EXTRACT-ssh_src",
     "Oct 23 21:14:02 qs-sensor01 sshd[1201]: Invalid user admin from 203.0.113.45 port 51515",
     {"src_ip": "203.0.113.45", "src_port": "51515"}),
    ("linux_secure", "EXTRACT-ssh_src",
     "Oct 23 21:14:09 qs-sensor01 sshd[1203]: Connection closed by authenticating user root 198.51.100.7 port 40022 [preauth]",
     {"src_ip": "198.51.100.7", "src_port": "40022"}),
    ("linux_secure", "EXTRACT-ssh_src",
     "Oct 23 21:14:11 qs-sensor01 sshd[1204]: Disconnected from authenticating user pi 192.0.2.10 port 38001 [preauth]",
     {"src_ip": "192.0.2.10", "src_port": "38001"}),
    ("linux_secure", "EXTRACT-ssh_src",
     "Oct 23 21:15:30 qs-sensor01 sshd[1310]: Accepted publickey for qsadmin from 192.168.1.15 port 50122 ssh2: ED25519 SHA256:abc",
     {"src_ip": "192.168.1.15", "src_port": "50122"}),
    ("linux_secure", "EXTRACT-ssh_invalid_user",
     "Oct 23 21:14:02 qs-sensor01 sshd[1201]: Invalid user admin from 203.0.113.45 port 51515",
     {"attempted_user": "admin"}),
    ("linux_secure", "EXTRACT-ssh_accepted",
     "Oct 23 21:15:30 qs-sensor01 sshd[1310]: Accepted publickey for qsadmin from 192.168.1.15 port 50122 ssh2",
     {"auth_method": "publickey", "user": "qsadmin"}),
    ("linux_secure", "EXTRACT-sudo",
     "Oct 23 21:16:00 qs-sensor01 sudo:  qsadmin : TTY=pts/0 ; PWD=/home/qsadmin ; USER=root ; COMMAND=/usr/sbin/ufw status verbose",
     {"sudo_user": "qsadmin", "sudo_command": "/usr/sbin/ufw status verbose"}),
    ("ufw", "EXTRACT-ufw_action",
     "Oct 23 21:20:01 qs-sensor01 kernel: [ 812.3] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.88 DST=192.168.1.30 LEN=44 PROTO=TCP SPT=40000 DPT=23",
     {"ufw_action": "BLOCK"}),
    ("crowdsec", "EXTRACT-crowdsec_ban",
     "time=\"2026-10-23T21:25:00Z\" level=info msg=\"Ip 203.0.113.45 performed 'crowdsecurity/ssh-bf' (6 events over 2.1s) at 2026-10-23 21:25:00 +0000 UTC\"",
     {"src_ip": "203.0.113.45", "scenario": "crowdsecurity/ssh-bf", "event_count": "6"}),
    # Pi-hole (dnsmasq) query log, plain and with the extra details newer versions can add.
    ("pihole", "EXTRACT-dns_query",
     "Oct 26 18:02:11 dnsmasq[812]: query[A] www.example.com from 192.168.1.20",
     {"dns_qtype": "A", "dns_query": "www.example.com", "dns_client": "192.168.1.20"}),
    ("pihole", "EXTRACT-dns_query",
     "Oct 26 18:02:11 dnsmasq[812]: 4321 192.168.1.20/53001 query[AAAA] cdn.example.org from 192.168.1.20",
     {"dns_qtype": "AAAA", "dns_query": "cdn.example.org", "dns_client": "192.168.1.20"}),
    ("pihole", "EXTRACT-dns_query",
     "Oct 26 18:02:12 dnsmasq[812]: query[HTTPS] example.net from 192.168.1.20",
     {"dns_qtype": "HTTPS", "dns_query": "example.net", "dns_client": "192.168.1.20"}),
    ("pihole", "EXTRACT-dns_block",
     "Oct 26 18:02:13 dnsmasq[812]: gravity blocked ads.example.net is 0.0.0.0",
     {"dns_block_reason": "gravity blocked", "dns_blocked_domain": "ads.example.net"}),
    ("pihole", "EXTRACT-dns_block",
     "Oct 26 18:02:14 dnsmasq[812]: regex denied tracker.example.com is 0.0.0.0",
     {"dns_block_reason": "regex denied", "dns_blocked_domain": "tracker.example.com"}),
    ("pihole", "EXTRACT-dns_reply",
     "Oct 26 18:02:11 dnsmasq[812]: reply www.example.com is 192.0.2.80",
     {"dns_reply_type": "reply", "dns_reply_domain": "www.example.com", "dns_answer": "192.0.2.80"}),
    ("pihole", "EXTRACT-dns_reply",
     "Oct 26 18:02:15 dnsmasq[812]: cached example.org is 198.51.100.4",
     {"dns_reply_type": "cached", "dns_reply_domain": "example.org", "dns_answer": "198.51.100.4"}),
    ("pihole", "EXTRACT-dns_forward",
     "Oct 26 18:02:11 dnsmasq[812]: forwarded www.example.com to 9.9.9.9",
     {"dns_forwarded_domain": "www.example.com", "dns_upstream": "9.9.9.9"}),
]
for sourcetype, key, line, expected in CASES:
    pattern = props.get(sourcetype, {}).get(key)
    if not pattern:
        check(f"{sourcetype} {key} exists", False, "missing from props.conf")
        continue
    m = splunk_regex(pattern).search(line)
    got = m.groupdict() if m else {}
    check(f"{sourcetype} {key}: {line[40:80]}…", got == expected, f"got {got}, expected {expected}")

# Lines that must NOT produce an SSH source (avoid false fields).
m = splunk_regex(props["linux_secure"]["EXTRACT-ssh_src"]).search(
    "Oct 23 21:00:00 qs-sensor01 systemd[1]: Started ssh.service - OpenBSD Secure Shell server.")
check("linux_secure EXTRACT-ssh_src ignores unrelated lines", m is None)

# A blocked lookup must not look like a normal reply, and a reply must not look like a block.
check("pihole: a block line isn't read as a reply",
      splunk_regex(props["pihole"]["EXTRACT-dns_reply"]).search("dnsmasq[812]: gravity blocked ads.example.net is 0.0.0.0") is None)
check("pihole: a reply line isn't read as a block",
      splunk_regex(props["pihole"]["EXTRACT-dns_block"]).search("dnsmasq[812]: reply www.example.com is 192.0.2.80") is None)
check("pihole: 'config' lines give no query fields",
      splunk_regex(props["pihole"]["EXTRACT-dns_query"]).search("dnsmasq[812]: config pi.hole is 192.168.1.15") is None)

# ufw writes KEY=value pairs that Splunk extracts automatically with KV_MODE=auto.
check("ufw uses automatic key=value extraction", props["ufw"].get("KV_MODE") == "auto")

# ---------------------------------------------------------------- saved searches
for name, s in saved.items():
    q = s.get("search", "")
    check(f"saved search uses the pilab index: {name}", "index=pilab" in q)
    check(f"saved search has no unbalanced quotes: {name}", q.count('"') % 2 == 0)
check("the Pi-silent alert is off by default (alerts need the trial)",
      saved["QS - Pi stopped sending logs"].get("enableSched") == "0")

# ---------------------------------------------------------------- inputs / outputs
inputs = parse_conf(ROOT / "splunk/forwarder-app/qs_pilab_forwarder/default/inputs.conf")
check("all forwarder inputs go to pilab", inputs["default"].get("index") == "pilab")
check("Caddy input stays off until Phase 5", inputs["monitor:///var/log/caddy/access.log"]["disabled"] == "true")
out = (ROOT / "splunk/forwarder-app/qs_pilab_forwarder/default/outputs.conf.template").read_text()
check("outputs template has exactly one placeholder", out.count("SPLUNK_SERVER") == 1)
dns_inputs = parse_conf(ROOT / "splunk/forwarder-app/qs_pilab_dns/default/inputs.conf")
dns_in = dns_inputs.get("monitor:///var/log/pihole/pihole.log", {})
check("Pi-hole input is on, sourcetype pihole, index pilab",
      dns_in.get("disabled") == "false" and dns_in.get("sourcetype") == "pihole" and dns_in.get("index") == "pilab")
idx = parse_conf(APP / "default" / "indexes.conf")
check("index size is capped", "maxTotalDataSizeMB" in idx["pilab"])

# ---------------------------------------------------------------- dashboard
dash = APP / "default/data/ui/views/pi_lab_overview.xml"
try:
    tree = ET.parse(dash)
    queries = [q.text for q in tree.iter("query")]
    check("dashboard XML is valid", True)
    check("dashboard has panels", len(queries) >= 12, f"{len(queries)} queries")
    check("every dashboard query uses pilab", all("index=pilab" in q for q in queries))
except ET.ParseError as e:
    check("dashboard XML is valid", False, str(e))

# ---------------------------------------------------------------- shell pitfalls
# With 'set -o pipefail', 'cmd | grep -q' can wrongly report "not found" (grep exits early,
# cmd gets SIGPIPE). This once made install-server.sh re-run 'enable boot-start' and stop.
for sh in list((ROOT / "pi").glob("*.sh")) + list((ROOT / "splunk").glob("*.sh")):
    bad = [l.strip() for l in sh.read_text().splitlines() if re.search(r"\|\s*grep -q", l) and not l.lstrip().startswith("#")]
    check(f"no 'cmd | grep -q' pipelines in {sh.name}", not bad, "; ".join(bad))

# ---------------------------------------------------------------- Pi-hole script and shared log access
pihole_sh = (ROOT / "pi/05-pihole.sh").read_text()
check("Pi-hole dashboard port is set to 8082", re.search(r"^WEB_PORT=8082\b", pihole_sh, re.M) is not None)
for busy, owner in (("8080", "CrowdSec"), ("8081", "Caddy")):
    check(f"Pi-hole never takes port {busy} ({owner})", not re.search(rf"WEB_PORT={busy}\b|port = \"{busy}", pihole_sh))
check("Pi-hole settings are written before the installer runs",
      pihole_sh.index('write_file "$TOML"') < pihole_sh.index('bash "$INSTALLER" --unattended'))
check("Pi-hole DHCP is turned off (router keeps DHCP)", "active = false" in pihole_sh and "ftl_set dhcp.active false" in pihole_sh)
check("Pi-hole starts out answering the home network only", 'listeningMode = "LOCAL"' in pihole_sh)
check("Pi-hole firewall rules are limited to the home network",
      all(f'ufw allow from "$LAN" to any port {p}' in pihole_sh for p in ("53 proto udp", "53 proto tcp", '"$WEB_PORT" proto tcp')))
check("Pi-hole installer asks before running", 'read -r -p "   Run Pi-hole\'s installer? [y/N] "' in pihole_sh)
# Block lines don't name the device; the per-device count must borrow it from the query line.
per_device = saved["QS - DNS lookups by device (Pi-hole)"]["search"]
check("DNS per-device blocks are matched to the asking device", "streamstats last(dns_client)" in per_device)
dash_text = (APP / "default/data/ui/views/pi_lab_overview.xml").read_text()
check("dashboard per-device panel matches blocks to devices", "streamstats last(dns_client)" in dash_text)
enc = (ROOT / "pi/06-encrypt-dns.sh").read_text()
check("Unbound settings are written before it is installed",
      enc.index('write_file "$CONF"') < enc.index("apt-get -y install unbound"))
check("Unbound listens on the Pi only, port 5335", "interface: 127.0.0.1" in enc and re.search(r"^DOT_PORT=5335\b", enc, re.M))
check("Unbound sends to Quad9 over TLS with certificate names",
      "forward-tls-upstream: yes" in enc and enc.count("@853#dns.quad9.net") == 2)
check("Pi-hole is only switched after Unbound answers",
      enc.index("Unbound answers through the encrypted link") < enc.index('run pihole-FTL --config dns.upstreams "$ENCRYPTED_UPSTREAM"'))
check("encryption step switches back to plain Quad9 if Pi-hole stops answering", '"$PLAIN_UPSTREAM"' in enc)
check("05-pihole.sh keeps the encrypted upstream on re-runs", "qs-quad9-dot.conf" in pihole_sh and "127.0.0.1#5335" in pihole_sh)
ts = (ROOT / "pi/07-tailscale.sh").read_text()
check("Tailscale doesn't take over DNS (Pi-hole stays in charge)", "--accept-dns=false" in ts)
check("Tailscale shares only this machine (no subnet routes, no exit node)",
      all("--advertise" not in l for l in ts.splitlines() if re.match(r"\s*tailscale up", l))
      and "--accept-routes=false" in ts)
check("Tailscale SSH rule is limited to the tailscale0 interface",
      "ufw allow in on tailscale0 to any port 22 proto tcp" in ts and "port 8000" not in ts.split("# ---")[-1])
check("Tailscale comes from its signed repository", "tailscale-archive-keyring.gpg" in ts and "pkgs.tailscale.com/stable/" in ts)
pts = (ROOT / "pi/08-pihole-tailscale.sh").read_text()
check("Pi-hole only answers everyone if the firewall denies incoming by default",
      pts.index('"deny (incoming)"') < pts.index("run pihole-FTL --config dns.listeningMode ALL"))
check("Pi-hole DNS over Tailscale is limited to tailscale0",
      "ufw allow in on tailscale0 to any port 53 proto udp" in pts and "ufw allow in on tailscale0 to any port 53 proto tcp" in pts)
check("Pi-hole over Tailscale switches back to LOCAL if the test fails", "dns.listeningMode LOCAL" in pts)
check("05-pihole.sh keeps ALL mode when Tailscale DNS is set up", "qs-tailscale-dns" in pihole_sh and "ftl_set dns.listeningMode ALL" in pihole_sh)
common = (ROOT / "pi/common.sh").read_text()
check("shared log access covers Pi-hole's log", "/var/log/pihole/pihole.log" in common)
for name in ("03-splunk-forwarder.sh", "04-web-tunnel.sh", "05-pihole.sh"):
    body = (ROOT / "pi" / name).read_text()
    check(f"{name} writes log access from the shared list", 'write_log_acl_service "$FWD_USER"' in body
          and "qs-crowdsec-log-acl.service 0644 <<" not in body)

# ---------------------------------------------------------------- no real addresses
doc_ranges = ("192.0.2.", "198.51.100.", "203.0.113.", "192.168.", "10.", "127.")
text = "\n".join(p.read_text() for p in ROOT.rglob("*") if p.is_file() and p.suffix in {".md", ".sh", ".conf", ".xml", ".template", ".py"})
PUBLIC_RESOLVERS = {"9.9.9.9", "149.112.112.112", "1.1.1.1", "0.0.0.0"}   # public DNS, and the "blocked" answer
for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
    ok = ip.startswith(doc_ranges) or ip in PUBLIC_RESOLVERS
    check(f"address {ip} is a documentation or private address", ok)

print(f"\n{len(failures)} failed" if failures else "\nAll checks passed.")
sys.exit(1 if failures else 0)
