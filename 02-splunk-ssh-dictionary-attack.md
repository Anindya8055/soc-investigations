# Investigation Write-Up: SSH Dictionary Attack - Security Overview Dashboard

## Summary
A dictionary attack against SSH logins (948 failed attempts from one IP,
87.194.216.51, targeting generic accounts like root and admin) was identified and
confirmed blocked - no account was compromised. The same attacker was also found
active on the web server, confirmed by cross-referencing Splunk logs from both systems.

## Data source
Splunk's official tutorial dataset (fictional "Buttercup Games" company, ~110,000
events: SSH, web server and sales logs). Not real company data.

## Tools used
Splunk

## How I found it
1. Ran a filter for the known attacker IP (87.194.216.51) to confirm it was actually
   generating failed SSH logins.
2. Checked the top targeted usernames to see what the attacker was actually trying.
3. Checked for any successful logins from that same IP, to confirm whether the attack
   actually succeeded.
4. Matched the attacker's IP against the top 404 sources on the web server, to see if
   the same attacker showed up in a different system too.

## What I found
**Panel 1 - Failed Logins Over Time:** On Oct 4 there were the minimum login attempts
(1667), and on Oct 7 there was the maximum number of login attempts (5034).

**Panel 2 - Top Attacking IPs:** a ranked list of external IPs by number of failed
login attempts, with 87.194.216.51 at the top (948 attempts).

**Panel 3 - Top Targeted Usernames:** the top username was `root`, tried about 1493
times. The top of the list (root, administrator, admin, operator...) are all generic
service/default account names, not random guesses - this tells us it was an automated
dictionary attack, not someone targeting a specific real person.

**Panel 4 - Legitimate Logins by User:** only 3 real employee accounts had successful
logins - djohnson (955), nsharpe (478), and myuan (166). This is a small, real list
compared to the much longer list of fake usernames being tried in panel 3.

**Panel 5 - Top 404 Sources (Web):** a list of external IPs generating the most "page
not found" errors on the website. This list overlaps with panel 2 (Top Attacking IPs) -
the same top IP, 87.194.216.51, appears in both, meaning the same attacker was active
across two different systems (SSH and the web server).

## What it means
The attack failed. The top attacker (87.194.216.51) was blocked - checking for any
successful logins from that specific IP returned 0 results, despite 948 failed
attempts. The brute-force/dictionary attack did not get in, and no real account was
compromised during this period.

## MITRE ATT&CK mapping
- **T1110 - Brute Force** (Tactic: Credential Access) - the SSH login attempts match
  this technique. Not tagging a specific sub-technique (Password Guessing, Password
  Spraying, etc.) since the evidence (many usernames, each tried hundreds of times)
  doesn't clearly match one specific sub-technique definition - tagging only what the
  evidence actually supports.
- The web 404 activity from the same IP was deliberately NOT tagged with T1595 (Active
  Scanning), even though it would be the obvious-looking match. The actual pages
  requested looked like normal site browsing (and a Googlebot user-agent appeared in
  the data), not deliberate vulnerability scanning - tagging it as reconnaissance would
  overstate what the evidence actually shows.

## What I'd do next (if this were a real job)
1. Block 87.194.216.51 at the firewall so it can't even reach our servers anymore.
2. Set up an alert in Splunk so we get automatically notified if an IP hits a certain
   number of failed logins, instead of having to manually check.
3. Check if other company systems saw the same IP, since we only checked SSH and web logs.
4. Consider disabling direct root login over SSH - root was the #1 targeted username,
   so this would remove that specific attack path entirely.
