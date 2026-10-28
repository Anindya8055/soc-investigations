# Investigation: Kongtuke Rebuke — Kongtuke / ClickFix

## Summary
A domain-joined workstation (10.9.11.135) visited a likely lure website and then
contacted a suspicious domain linked to Kongtuke ClickFix activity. No starting IP was
given, so I found the malicious infrastructure from DNS before identifying the host and
user.

## Scenario
Investigate Kongtuke ClickFix activity on a Windows host. No malicious IP was provided.
Environment: 10.9.11.0/24 LAN, AD domain `overhands.org`, domain controller 10.9.11.2.
Source: malware-traffic-analysis.net exercise "Kongtuke rebuke!" (2026-09-11).

## Tools used
Wireshark, in an isolated low-privilege Linux account.

## How I found it
1. **No lead, so I started with DNS.** The first query in the capture was for
   `quadcinema.com`, a plausible lure site. Shortly after came `aatthews.cfd`: a
   meaningless name on the often-abused `.cfd` TLD. I ruled out `code.jquery.com`, which
   appeared nearby, as a normal web library.
2. **Followed the domain, not the IP.** `aatthews.cfd` resolved to Cloudflare IPs shared
   by many sites, so I filtered by TLS SNI instead:
   `tls.handshake.extensions_server_name == "aatthews.cfd"`. The host connected over
   QUIC (HTTP/3).
3. **MAC:** Ethernet II source of that traffic.
4. **Hostname:** this capture had no DHCP handshake, and LLMNR/NBNS only showed domain
   names. A raw-byte search for "DESKTOP" found a Microsoft Windows Browser Protocol
   announcement containing the computer name.
5. **User account:** `kerberos.msg_type == 10` (AS-REQ only), `CNameString`.
6. **Full name:** raw-byte search for the username led to the SAMR QueryUserInfo
   response.

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 10.9.11.135 |
| MAC address | 08:d4:0c:7a:29:1e |
| Hostname | DESKTOP-6T17ZFM |
| User account | gmcdowell |
| Full name | Gabriel McDowell |
| Suspicious domain | aatthews.cfd |

## What it means
ClickFix attacks trick a user into pasting a malicious command (often via a fake
"verify you're human" page). The pattern here fits that: a normal-looking site visit,
then immediate contact with an unrelated, suspicious domain.

## MITRE ATT&CK mapping
- **T1071.001 — Application Layer Protocol: Web Protocols:** contact with the suspicious
  domain over HTTPS/QUIC.
- The ClickFix user-execution step itself isn't visible in network traffic, so I haven't
  tagged it.

## What I'd do next (if this were a real job)
1. Isolate DESKTOP-6T17ZFM and block `aatthews.cfd` at DNS/proxy level.
2. Check endpoint logs for PowerShell or Run-dialog commands at that time.
3. Reset the `gmcdowell` account and tell the user how ClickFix lures work.
