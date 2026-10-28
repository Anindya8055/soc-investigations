# Investigation: Easy As 123 — NetSupport Manager RAT

## Summary
A Windows workstation (10.2.28.88) was infected with NetSupport Manager, a legitimate
remote-access tool abused here as a RAT. It beaconed to an attacker-controlled server
(45.131.214.85) about every 60 seconds. I identified the infected host, its user
account, and the user's full name from the packet capture alone.

## Scenario
A SOC alert flagged NetSupport Manager RAT activity from 45.131.214.85 over TCP port 443,
originating from an internal host on 2026-02-28. Environment: 10.2.28.0/24 LAN, Active
Directory domain `easyas123.tech`, domain controller 10.2.28.2.
Source: malware-traffic-analysis.net exercise "Easy As 123" (2026-02-28).

## Tools used
Wireshark, in an isolated low-privilege Linux account. The capture contained no
executable files, and nothing was run.

## How I found it
1. **Started from the alert's IP.** Filter `ip.addr == 45.131.214.85` showed one internal
   host, 10.2.28.88, repeatedly sending HTTP POSTs to `/fakeurl.htm` on the bare IP.
2. **Confirmed it was malicious.** The requests repeated roughly every 60 seconds
   (beaconing, not human behavior), went to a bare IP with a fake-looking page name, and
   carried the User-Agent `NetSupport Manager/1.3`, matching the alert.
3. **MAC address:** read from the Ethernet II source field of the malicious packets.
4. **Hostname:** filtered DHCP by the MAC (`dhcp and eth.src == 00:19:d1:b2:4d:ad`).
   Filtering by MAC catches the DHCP Discover/Request, which happen before the host has
   an IP. Found in DHCP Option 12 (Host Name).
5. **User account:** filtered Kerberos login requests from the host
   (`ip.addr == 10.2.28.88 and kerberos`) and read the `CNameString` in the AS-REQ.
6. **Full name:** LDAP lookups were encrypted (SASL GSS-API), so I searched the whole
   capture's raw bytes for the username. That led to SAMR traffic (LookupNames →
   OpenUser → QueryUserInfo), where the QueryUserInfo response held the full name in
   plain text.

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 10.2.28.88 |
| MAC address | 00:19:d1:b2:4d:ad |
| Hostname | DESKTOP-TEYQ2NR |
| User account | brolf |
| Full name | Becka Rolf |

## What it means
The workstation was under remote control by an attacker. NetSupport Manager is a real
commercial tool, which helps it avoid detection, but the bare-IP destination, fake page
name and steady 60-second check-ins show it was being used maliciously. The attacker
could potentially see the screen, run commands and move files on this machine.

## MITRE ATT&CK mapping
- **T1219 — Remote Access Software** (Command and Control): abuse of NetSupport Manager.
- **T1071.001 — Application Layer Protocol: Web Protocols** (Command and Control):
  check-ins over HTTP POST.

## What I'd do next (if this were a real job)
1. **Contain:** isolate DESKTOP-TEYQ2NR from the network and block 45.131.214.85 at the
   firewall.
2. **Scope:** search other hosts' traffic and logs for the same IP and User-Agent.
3. **Eradicate:** remove NetSupport Manager and find how it was installed (likely a
   malicious download or phishing).
4. **Recover:** reset the `brolf` account password, reimage the machine if needed, and
   monitor for repeat beaconing.
