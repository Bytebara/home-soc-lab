# Splunk searches for the Quiet Signal lab

All of these are saved in the **Quiet Signal Lab** app under **Reports**, and most appear on the **Pi lab overview** dashboard. They're written out here so you can learn what each part does and change them.

Splunk searches read left to right. Each `|` passes the results to the next command, like pipes in a terminal.

## 1. Is data arriving?

```
index=pilab | stats count by sourcetype
```

The first search to run after setup. You should see `linux_secure`, `syslog`, and later `crowdsec` and `ufw`. If nothing appears, check the forwarder on the Pi (`sudo systemctl status SplunkForwarder`) and the Ubuntu PC's firewall.

## 2. Failed and invalid SSH logins

```
index=pilab sourcetype=linux_secure ("Invalid user" OR "Failed password" OR "Connection closed by authenticating user" OR "Disconnected from authenticating user")
| stats count AS attempts, values(attempted_user) AS usernames_tried, latest(_time) AS last_seen BY src_ip
| sort - attempts
| convert ctime(last_seen)
```

- `index=pilab sourcetype=linux_secure` limits the search to the Pi's authentication log.
- The quoted phrases are the ways OpenSSH records a failed attempt. With key-only login there's no password to guess, so most attempts show as invalid users or closed connections.
- `stats ... BY src_ip` gives one row per source address with how many tries and which usernames.

Your Pi's SSH only accepts your home network, so expect almost nothing here except your own mistakes. That quiet result is itself evidence the firewall works.

## 3. Successful SSH logins

```
index=pilab sourcetype=linux_secure "Accepted"
| table _time host user auth_method src_ip
| sort - _time
```

Every login that worked. In a real SOC this is one of the most-watched searches: a successful login from an unexpected place matters more than a thousand failures.

## 4. sudo commands

```
index=pilab sourcetype=linux_secure "COMMAND="
| table _time host sudo_user sudo_command
```

Who ran admin commands and what they ran. Useful for spotting changes you don't remember making.

## 5. CrowdSec bans by attack type

```
index=pilab sourcetype=crowdsec "performed"
| stats count AS bans, dc(src_ip) AS unique_sources, values(src_ip) AS sources BY scenario
| sort - bans
```

CrowdSec logs a line like `Ip 203.0.113.7 performed 'crowdsecurity/ssh-bf' (6 events over 2s)` when it decides to ban. The app extracts `src_ip` and `scenario` from that line. `dc()` means distinct count.

## 6. Firewall blocks by port

```
index=pilab sourcetype=ufw ufw_action="BLOCK"
| fillnull value="no port" DPT
| stats count AS blocks, dc(SRC) AS unique_sources BY DPT PROTO
| sort - blocks
```

Which ports outsiders try. Some protocols have no port at all (ICMP pings, IGMP multicast from your own router), so `fillnull` labels those "no port" instead of silently dropping them. Without it, `stats ... BY DPT` skips any event missing that field, which is why the dashboard once showed 31 blocks in total but nothing in the by-port panel. `DPT` is destination port, `SRC` is source address. Splunk pulls these out automatically because ufw writes `KEY=value` pairs.

## 7. Web requests and scanning (Phase 5)

After Caddy is running, turn on its input in `qs_pilab_forwarder/default/inputs.conf` on the Pi (set `disabled = false`) and restart the forwarder.

```
index=pilab sourcetype=caddy:access
| stats count AS requests, values(status) AS status_codes BY client_ip
| sort - requests
```

Behind Cloudflare Tunnel, every request reaches Caddy from the tunnel itself, so the normal client address is useless. The app builds `client_ip` from the `Cf-Connecting-Ip` header that Cloudflare adds. This is a real detail worth mentioning in your write-up.

Scanners probe for things a static site doesn't have:

```
index=pilab sourcetype=caddy:access
| search request.uri="*wp-login*" OR request.uri="*.env*" OR request.uri="*.git/*" OR request.uri="*phpmyadmin*"
| stats count AS probes, values(request.uri) AS paths BY client_ip
| sort - probes
```

## 8. Alert: the Pi went quiet

```
| tstats latest(_time) AS last_event WHERE index=pilab BY host
| eval minutes_silent = round((now() - last_event) / 60)
| where minutes_silent > 30
```

`tstats` is a fast search over indexed data. This finds any host that's been silent for 30 minutes. It's saved as an alert, turned off by default because alerts only run on the Enterprise trial, not the Free license. Turn it on under **Settings → Searches, reports, and alerts** while your trial lasts.

## Practice ideas

- Change search 2 to show attempts per hour with `| timechart span=1h count`.
- Add `| iplocation src_ip` to search 5 to see which countries attacks come from.
- Build your own: which hour of the day sees the most firewall blocks?


## Pi-hole DNS (Project A)

Each lookup writes a few lines to `/var/log/pihole/pihole.log`. The app pulls out these fields:

| Field | Example | Meaning |
|---|---|---|
| `dns_query`, `dns_qtype`, `dns_client` | `www.example.com`, `A`, `192.168.1.20` | who asked for what |
| `dns_block_reason`, `dns_blocked_domain` | `gravity blocked`, `ads.example.net` | Pi-hole refused (gravity = its blocklists) |
| `dns_reply_type`, `dns_answer` | `reply`, `192.0.2.80` | the answer (`cached` = Pi-hole remembered it) |
| `dns_upstream` | `9.9.9.9` | which upstream server answered |

- **QS - DNS lookups by device:** lookups, blocks and unique domains per device. A device suddenly making 10x its normal lookups deserves a look.
- **QS - DNS top domains:** what normal looks like on your network. Learn this first; hunting is spotting what's different.
- **QS - DNS blocked domains:** what Pi-hole stopped. Mostly ads and telemetry.
- **QS - DNS odd-looking domains:** names over 50 characters or with more than 6 parts. Malware sometimes hides data in DNS names (DNS tunneling) or contacts random-looking domains. Most hits are harmless (CDNs, telemetry); write down what each one is. That's the habit an analyst needs.

Try by hand:

```
index=pilab sourcetype=pihole dns_client=192.168.1.20 dns_query=* | timechart span=1h count
index=pilab sourcetype=pihole dns_query=* | rare dns_query limit=20
```
