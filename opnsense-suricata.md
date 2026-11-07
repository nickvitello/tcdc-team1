# Suricata on OPNsense (alert-only)

OPNsense has Suricata built in. Turned on in **detection-only (IDS) mode**, it
watches traffic passing through the firewall and logs alerts for exploit attempts,
scans, webshell traffic and known malware/C2 signatures. It's the network-side
view; every other tool we have looks at the boxes themselves.

- **Owner:** whoever runs OPNsense.
- **Time:** about 10 minutes.
- **When:** after the 08:00 lockdown (passwords rotated, GUI restricted).

**If you can't get into OPNsense:** the store sells extra Xen Orchestra
*console* access; the web GUI is a different thing, reached at
`https://10.(100+X).40.1` from the jumpbox browser. If even the GUI is
unavailable, skip this guide and use host firewalls instead:
- **Every Linux box:** `ufw` with allow rules for its scored ports first, then
  `ufw default deny incoming`.
- **ad and mqtt:** Windows Firewall, per `firewall-windows.md`.
- **The jumpbox:** `ufw` denying inbound from the server subnets (`.10`, `.20`,
  `.30`), after allowing your own VPN path. Don't touch the browser/RDP
  containers' ports.
- **Network visibility:** comes from agentless Wazuh (`==OUTBOUND==`,
  `==LISTENERS==`), sampling `./fleet.sh run "ss -tnH state established"`, and one
  short `tcpdump`.

## Why it's safe

- **Nothing on the scored boxes changes.** It runs on the firewall only.
- **Detection only.** In IDS mode Suricata can't drop traffic, so it can't block
  the scorer or break a service.
- **Rules:** it adds no firewall rules (R18), doesn't touch Wazuh or auditd (R7),
  and its logs stay on OPNsense, inside competition infrastructure (R23).
- **Hands-on time only** (R10), like every other change.

**Don't switch it to IPS mode** ("Netmap" or "Divert" capture) unless Black Team
has OK'd it and you follow the "Optional: dropping" section below. A false
positive would silently drop scorer traffic.

## Setup

In the OPNsense GUI (through the jumpbox), go to **Services ▸ Intrusion Detection ▸
Administration**.

1. **Settings** tab:
   - **Enabled**: ✓
   - **Capture mode**: **PCAP live mode (IDS)**. Not Netmap, not Divert.
   - **Promiscuous mode**: ✓
   - **Interfaces**: the inside interfaces, which are the DMZ (10.(100+X).10.0/24),
     internal servers (.20), users (.30) and management (.40). Leave WAN off: it's
     mostly internet noise. ipcam is outside the firewall, so this doesn't cover it.
   - **Pattern matcher**: leave the default (Hyperscan, if offered, is faster).
   - **Enable syslog alerts**: ✓ (harmless, and needed if you ever forward alerts).
   - **Apply**.
2. **Download** tab: select **ET open**, either all of it or at least the
   `emerging-exploit`, `emerging-web_server`, `emerging-web_specific_apps`,
   `emerging-attack_response`, `emerging-malware`, `emerging-trojan`,
   `emerging-shellcode` and `emerging-scan` sets. Then click **Download & Update
   Rules**. This needs internet access from OPNsense; if it fails, Suricata has
   no rules and this guide stops here.
3. **Policy** tab: add one policy that sets the action to **alert** for all ET open
   rulesets, so no rule is ever set to drop, even if someone later changes the
   capture mode.
4. **Alerts** tab: within a few minutes you should see entries, starting with
   rival teams' scans.

## Optional, only with Black Team's OK: dropping (IPS)

Dropping by **signature** applies to every source equally, which arguably fits R18.
But R18's wording is about firewall rules, so **ask Black Team first** (R17):
*"Is Suricata IPS on OPNsense, dropping by signature for all sources, with no
IP-based rules, allowed under R18?"* Only continue if the answer is yes.

**Risks:**
- **The firewall itself.** IPS mode uses netmap and needs hardware offloading
  disabled (**Interfaces ▸ Settings**). On a VM's virtual network cards, netmap
  may be unsupported or unstable, and then the firewall stops passing traffic:
  **every scored service drops at once.**
- **False positives.** A signature that fires on the scorer's traffic silently
  costs you ticks.

**Suricata doesn't learn "normal"; you do.** Steps:
1. Run **alert-only for an hour or more** first. Note every signature that fires on
   the scorer's or normal traffic (NetFlow shows which traffic is the scorer).
   Those must never drop.
2. Under **Policy**, set the action to **drop** only for a few high-confidence
   groups that never fired on normal traffic: `ATTACK_RESPONSE` (shell output
   leaving a box) and specific exploit or webshell-command signatures. Leave
   everything else on **alert**.
3. **Never set the IP-reputation rulesets to drop** (`emerging-drop`,
   `emerging-compromised`, `ciarmy`, `dshield`, `tor`). They match lists of
   addresses, which makes them per-IP blocks, and R18 forbids those inbound.
4. Disable hardware offloading, switch **Capture mode** to **Netmap (IPS)**, apply,
   and **watch the scoreboard for the next 5 minutes**, with someone ready to
   undo.
5. **Rollback:** set Capture mode back to **PCAP live mode (IDS)** and apply. Do
   that immediately on any red tick you can't explain.

## Watch the cost

For the first 15 minutes, check OPNsense's CPU (**Lobby ▸ Dashboard**, or
**System ▸ Diagnostics ▸ Activity**) and the scoreboard.

**If CPU stays above about 80%, or scoring gets flaky,** untick **Enabled** and
**Apply**. Losing uptime is worse than losing alerts.

## Using the alerts

The first 30 minutes are your baseline: scans from other teams and the scorer's
regular traffic. After that, look for:

| alert category | meaning | do |
|---|---|---|
| `ET SCAN …` | someone is scanning you | usually just note it; expected all day |
| `ET WEB_SERVER …`, `ET WEB_SPECIFIC_APPS …` aimed at artifactorium | web exploit attempt | check the web root for new files (`fleet.sh diff`, Wazuh `==WEB-SCRIPTS==`) |
| `ET ATTACK_RESPONSE …` from one of **your** boxes | an exploit probably **worked** (the box is answering with shell output, `id` results, etc.) | treat that box as popped: playbook section 7 |
| `ET MALWARE …`, `ET TROJAN …`, anything mentioning CnC, from **your** box outward | the box is talking to a C2 server | find the program (`ss -tnp`), kill it, and remove its persistence; block that exact destination IP + port outbound (the only outbound block R18 allows) |

Alert details (the info button) show source, destination and the matched rule.
Screenshots of alerts are fine to keep (R23).

## Network baseline (same owner, same 5 minutes)

**Reporting ▸ NetFlow**: enable capture on the same inside interfaces, then use
**Reporting ▸ Insight** after about 30 minutes to see top talkers and ports per
interface. Together with Suricata's alerts, that answers two questions:

- **Which inbound ports does anyone actually use?** Close everything else for all
  sources (R18-compliant).
- **Which outbound destinations are normal?** Any new one is suspicious.

## Optional: OPNsense logs into our Wazuh (syslog)

This sends OPNsense's logs (Suricata alerts, the firewall log, GUI logins and
config changes) to our Wazuh, so they sit next to the box checks. OPNsense only
gets a log destination added: **no package is installed** and nothing of the
organizers' is touched. A Wazuh *agent* on OPNsense isn't used, because it may
conflict with an organizer agent (R7).

**R23:** this moves firewall logs to wherever Wazuh runs. On the jumpbox that's
fine; on a personal laptop, get Black Team's OK first.

1. **Turn on the listener** on the Wazuh machine. Allow only OPNsense's address as
   seen by that machine:
   - **Wazuh on the jumpbox:** OPNsense's management address,
     `10.(100+X).40.1`, which is the default:
     `.\setup.ps1 -Team X -User <user> -AsRoot -AcceptSyslog`
   - **Wazuh on a laptop over the VPN:** the traffic leaves through OPNsense's WAN,
     so use its WAN address (`100.64.0.X` on the network diagram):
     `... -AcceptSyslog -SyslogFrom 100.64.0.X/32`
   - Windows may ask to let Docker through its firewall; allow it.
2. **Test the path before changing anything else.** In OPNsense, open
   **Interfaces ▸ Diagnostics ▸ Port Probe** (named Test Port in some versions)
   and probe the Wazuh machine's IP on TCP **514**. If it fails, stop here: the
   network doesn't route that way (common over a VPN), and the Alerts tab is
   still all you need.
3. **Add the log destination** under **System ▸ Settings ▸ Logging** (Remote /
   Targets):
   - Enabled ✓
   - Transport: **TCP(4)**
   - Applications: `suricata`, `filterlog` and `audit` (or leave empty for
     everything)
   - Levels: info and up
   - Hostname: the Wazuh machine's IP
   - Port: `514`

   Save and apply.
4. **Verify:** in the Wazuh dashboard (Threat Hunting ▸ Events), search for
   OPNsense's IP or `suricata`. Events should appear within a minute of new
   traffic.

**What to expect:** Wazuh has decoders for pf-style firewall logs and for Suricata,
but this exact path (OPNsense to Wazuh over syslog) hasn't been tested on a live
OPNsense. If Wazuh's rules don't match some events, they still arrive and are
searchable as text.

**Rollback (either side, independently):**
- OPNsense: untick the target's **Enabled**, and apply.
- Wazuh: re-run `setup.ps1` **without** `-AcceptSyslog`. The listener and the
  published port are removed.
