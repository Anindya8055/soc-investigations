# Investigation: Natureforce — CNCmachineRMS RAT

## Summary
A Windows workstation (10.10.1.128) downloaded a malicious executable over a non-standard
port (9000) and then showed RAT command-and-control activity. I identified the host and
user, and confirmed the file as malware by its SHA-256 hash without ever running it.

## Scenario
SOC alerts flagged an executable transferred over an unusual port and C2 traffic tied to
CNCmachineRMS RAT. Environment: 10.10.1.0/24 LAN, AD domain `natureforce.com`, domain
controller 10.10.1.10.
Source: malware-traffic-analysis.net exercise "Natureforce" (2026-10-01).

## Tools used
Wireshark, tshark, sha256sum, VirusTotal (hash lookup only), in an isolated
low-privilege Linux account.

## How I found it
1. **Started from the alert's IP.** `ip.addr == 107.175.82.242` showed 10.10.1.128
   requesting `GET /wilow/runner_ilove.exe` over port 9000.
2. **MAC:** from the Ethernet II source of that traffic.
3. **Hostname:** `dhcp and eth.src == <mac>`, Option 12 (Host Name).
4. **User account:** Kerberos AS-REQ `CNameString`. The first results were
   `desktop-4vgyqx7$`, a computer account (the trailing `$` marks machine accounts in
   Active Directory), so I kept looking until I found the human account.
5. **File hash:** extracted the executable from the HTTP traffic with
   `tshark --export-objects`, calculated its SHA-256 with `sha256sum`, then deleted the
   extracted file. The file was never opened or run.
6. **Verified on VirusTotal** by looking up the hash only (the file was not uploaded).

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 10.10.1.128 |
| MAC address | 00:22:fb:ec:7e:e7 |
| Hostname | DESKTOP-4VGYQX7 |
| User account | bdiaz |
| Executable SHA-256 | b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061 |

VirusTotal: 42/66 engines flagged it as malicious (label `trojan.capdoor/zusy`), with
behavior tags including `detect-debug-environment` (tries to evade analysis).

## What it means
The host downloaded a confirmed trojan with a harmless-sounding name. Using port 9000
instead of a normal web port is a common way to slip past basic monitoring.

## MITRE ATT&CK mapping
- **T1105 — Ingress Tool Transfer:** executable downloaded from the attacker's server.
- **T1571 — Non-Standard Port:** transfer over port 9000.

## What I'd do next (if this were a real job)
1. Isolate DESKTOP-4VGYQX7 and block 107.175.82.242.
2. Add the SHA-256 hash to endpoint blocklists and search other machines for it.
3. Reset the `bdiaz` account credentials and reimage the machine.
