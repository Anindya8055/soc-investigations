# Investigation: "It's a Trap!" — Cold Start, No Lead

## Summary
The hardest case so far: no malware name, no flagged IP, and no published answers. Working
only from the traffic itself, I found a lure website, a cluster of fake Microsoft
domains, and a PowerShell script on 10.6.13.133 sending system information to an
attacker-controlled server.

## Scenario
A capture from a Windows network with no alert details at all.
Source: malware-traffic-analysis.net exercise "It's a Trap!" (2025-06-13).

## Tools used
Wireshark, in an isolated low-privilege Linux account.

## How I found it
1. **Started from DNS, because there was no lead.** I listed every domain lookup and
   separated normal Windows noise (WPAD, Microsoft telemetry and similar) from anything
   unusual.
2. **Spotted a likely lure site:** `www.truglomedspa.com`, a small business website that
   looked out of place, which fits a compromised site that sends visitors onward.
3. **Found brand-impersonation domains:** `dng-microsoftds.com`,
   `event-time-microsoft.org` and `eventdata-microsoft.live`. They use Microsoft's name
   but on domains Microsoft doesn't use (`.org`, `.live`, odd spellings).
4. **SNI filter came up empty, so I checked plain HTTP.**
   `tls.handshake.extensions_server_name == "eventdata-microsoft.live"` returned nothing,
   so I tried `http.host == "eventdata-microsoft.live"` and found an unencrypted
   **HTTP POST** from 10.6.13.133.
5. **The User-Agent gave it away:** `WindowsPowerShell`, a script rather than a web
   browser. The POST body contained system details (for example "Execution Prevention
   Available: Yes"), which is the victim machine being fingerprinted.
6. **Identified the host and user:** MAC from the Ethernet layer, hostname from DHCP
   Option 12, username from Kerberos AS-REQ, full name from the SAMR `QueryUserInfo`
   response (packet 332).

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 10.6.13.133 |
| MAC address | 24:77:03:ac:97:df |
| Hostname | DESKTOP-5AVE44C |
| User account | rgaines |
| Full name | Roman Gaines |
| Lure site | `www.truglomedspa.com` |
| Suspicious domains | `dng-microsoftds.com`, `event-time-microsoft.org`, `eventdata-microsoft.live` |

## What it means
A PowerShell script quietly sending system details to a fake "Microsoft" domain is a
strong sign that the user was tricked into running something, a common pattern in fake
browser-update or fake-CAPTCHA lures. Collecting system information is usually the
attacker's first step before deciding what to install next.

## MITRE ATT&CK mapping
- **T1059.001 — Command and Scripting Interpreter: PowerShell:** the POST came from
  PowerShell, not a browser.
- **T1082 — System Information Discovery:** the POST body contained system details.
- **T1071.001 — Application Layer Protocol: Web Protocols:** data sent over HTTP.

I did not claim *how* the script started (for example, which lure page the user clicked).
The network data shows the result, not the user's click.

## What I'd do next (if this were a real job)
1. Isolate DESKTOP-5AVE44C.
2. Block the three fake Microsoft domains and the lure site at DNS and the web proxy.
3. Check the endpoint's PowerShell logs to see exactly what ran and what it downloaded.
4. Search DNS logs company-wide for the same domains, to find other victims.
5. Reset `rgaines` credentials and reimage the machine.

## What I learned
- With no lead, DNS is the best starting point: filter out normal noise and look for
  what doesn't belong.
- Brand impersonation (a real company's name on the wrong domain) is a quick red flag.
- If a TLS/SNI filter finds nothing, check plain HTTP. Attackers don't always encrypt.
