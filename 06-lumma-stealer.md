# Investigation: Lumma Stealer

## Summary
A Windows workstation (10.1.21.58) exchanged about 2 MB of traffic with a server tied to
Lumma Stealer, a well-known information stealer. I identified the host, user and full
name, and found the C2 domain hidden behind the IP address.

## Scenario
An alert flagged suspicious traffic to 153.92.1.49. An extra question asked for the
command-and-control (C2) domain name, not just the IP.
Source: malware-traffic-analysis.net exercise "Lumma Stealer" (2026-01-31).

## Tools used
Wireshark (Conversations view, display filters), in an isolated low-privilege Linux
account.

## How I found it
1. **My first filter returned 0 results.** Instead of giving up, I opened
   **Statistics → Conversations** with "Limit to display filter" unchecked. That showed the
   real connection: 10.1.21.58 ↔ 153.92.1.49, 2,968 packets, about 2 MB. My first filter
   simply had a typo.
2. **IP + MAC:** right-clicked that conversation → *Apply as Filter → Selected → A ↔ B*,
   then read the MAC address from the Ethernet layer.
3. **Hostname:** DHCP Option 12 (Host Name).
4. **User account:** Kerberos AS-REQ `CNameString` (human account, no trailing `$`).
5. **Full name:** a raw-bytes search for the username led to the SAMR `QueryUserInfo`
   response.
6. **C2 domain (the bonus question):** my first try was wrong. I filtered for
   `tls.handshake.extensions_server_name == "153.92.1.49"`, but SNI only ever holds a
   domain name, never an IP, so that can never match. The fix was to filter for the TLS
   Client Hello going *to* that IP (`ip.dst == 153.92.1.49 and tls.handshake.type == 1`)
   and read the SNI field in it.

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 10.1.21.58 |
| C2 server IP | 153.92.1.49 |
| Hostname | DESKTOP-ES9F3ML |
| User account | gwyatt |
| Full name | Gabriel Wyatt |
| C2 domain | `whitepepper.su` |

## What it means
About 2 MB of traffic to a stealer's C2 server suggests real data, such as browser
passwords, cookies or crypto-wallet files, may have left the network. The `.su` domain
(the old Soviet Union country code) is a red flag: it's rarely used by legitimate
business sites and often seen in malicious infrastructure.

## MITRE ATT&CK mapping
- **T1071.001 — Application Layer Protocol: Web Protocols:** C2 over HTTPS (TLS).

I did not tag a specific data-exfiltration technique. The traffic volume suggests data
theft, but the content is encrypted, so I can't prove what was taken.

## What I'd do next (if this were a real job)
1. Isolate DESKTOP-ES9F3ML and block `whitepepper.su` and 153.92.1.49 at DNS and the
   firewall.
2. Treat every password and session saved in that machine's browsers as stolen. Reset
   them and sign the user out of all sessions.
3. Search DNS logs for any other host that looked up `whitepepper.su`.
4. Reimage the machine.

## What I learned
- When a filter returns nothing, check your tools (Conversations, Statistics) before
  deciding the traffic isn't there.
- SNI carries domain names, not IPs. To find a domain behind an IP, filter by the IP and
  then read the SNI.
