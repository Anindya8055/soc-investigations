# Investigation: First to Last — FormBook

## Summary
A Windows workstation (172.16.8.49) checked in to a FormBook command-and-control (C2)
server over plain HTTP. Starting from an alert time window and a list of flagged IPs, I
identified the infected host, its user account and the user's full name.

## Scenario
SOC alerts flagged "CnC Checkin (GET)" activity between 02:13 and 02:16 UTC, involving six
external IP addresses. FormBook is a well-known information stealer.
Source: malware-traffic-analysis.net exercise "First to Last" (2026-08-09).

## Tools used
Wireshark, in an isolated low-privilege Linux account.

## How I found it
1. **Used every lead at once.** Instead of checking the six flagged IPs one by one, I
   combined them in a single filter (`ip.addr == A or ip.addr == B or ...`). Only one
   internal host talked to them: 172.16.8.49, sending HTTP GET requests to 172.64.155.76.
   That matches the "CnC Checkin (GET)" alert.
2. **MAC address:** read from the Ethernet II layer of the same packet, so no extra
   step was needed.
3. **Hostname:** this capture included the DHCP exchange, so `dhcp` plus Option 12
   (Host Name) gave the hostname directly.
4. **User account:** `kerberos.msg_type == 10` (AS-REQ). I skipped the computer account
   `desktop-5nlv63k$` (a trailing `$` marks machine accounts in Active Directory) and kept
   going until I found the human account.
5. **Full name:** I cleared all filters and searched the raw packet bytes for the
   username. That led to SAMR traffic (`Connect5` → … → `QueryUserInfo`), and the
   `QueryUserInfo` response contains the account's full name in clear text.

## What I found
| Question | Answer |
|---|---|
| Infected host IP | 172.16.8.49 |
| C2 server contacted | 172.64.155.76 (HTTP) |
| Hostname | DESKTOP-5NLV63K |
| User account | rvance |
| Full name | Raymond Vance |

## What it means
The host was beaconing to a FormBook C2 server, which means the stealer was very likely
running and able to send stolen data (saved passwords, form data, keystrokes) out of the
network. Because the check-in used plain HTTP, the traffic was easy to spot and read.

## MITRE ATT&CK mapping
- **T1071.001 — Application Layer Protocol: Web Protocols:** C2 check-ins over HTTP.

I did not tag specific data-theft techniques. The capture shows the check-in, but not
exactly what was stolen.

## What I'd do next (if this were a real job)
1. Isolate DESKTOP-5NLV63K and block 172.64.155.76 and the other flagged IPs.
2. Reset the `rvance` account password and any passwords saved in that machine's
   browsers, since FormBook targets stored credentials.
3. Search proxy and firewall logs for other hosts contacting the same IPs.
4. Reimage the machine before returning it to the user.

## What I learned
Read the original alert carefully. I first had only the time window, and the full list
of six IPs on the source page turned a slow search into a single filter.
