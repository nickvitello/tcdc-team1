# OPNsense 26.7 playbook (10.101.40.1) — network/firewall lead

NOT scored, but it gates every scored box. Do NOT lock yourself (or the checker) out.

## First 10 min
1. Log in via jumpbox Chromium (https). Change the admin/root password → record in vault.
2. System > Access > Users: audit accounts, disable anything not yours (keep blackteam/whiteteam — R8).
3. Firewall > Rules: SCREENSHOT current rules first (rollback + evidence).
4. Diagnostics > States: watch for weird established flows (C2 egress).

## Rules (conservative — uptime first)
- Keep scored service ports reachable from the checker subnet. Do NOT blanket-deny.
- Block OUTBOUND to known C2 ports from server VLANs (4444,5555,8081,9001,1337,31337) — R18 lets
  you block, but each rule names one dest+port; log hits.
- Mgmt (SSH/GUI): R18 wants outside-subnet inbound blocks to apply to every source. BUT a blanket
  "deny mgmt from all outside" can also block YOUR recovery path, and do not assume a jumpbox-hosted
  browser (10.99.1.2, itself OUTSIDE the defended service subnets) is exempt: unless its traffic is
  NAT'd/proxied to an allowed source, its packets arrive as an outside source and the deny drops them.
  Existing GUI states can mask this until they expire, then you are locked out. Before you deploy that
  deny:
  1. Establish the ACTUAL packet source the firewall sees for your management traffic (Diagnostics >
     States / packet capture), do not guess. Find out whether the jumpbox is routed or NAT'd.
  2. Keep an independent fallback that the deny does NOT cut — OPNsense console (physical/hypervisor),
     or a LAN/internal-interface management rule — and TEST it works first.
  3. Apply the deny, then immediately confirm the GUI is still reachable by your intended path. If not,
     roll back from the screenshot in step 3 above (or console) right away.
  R18 compliance (does the block cover all sources) is a SEPARATE question from whether management
  still works. A source-based allow for 10.99.1.2 is selective policy R18's internal-subnet exception
  may not cover — get an explicit staff ruling before relying on it as compliant.
- Leave ICMP to the test box alone; never touch competition infra (R7/R9).

## Trap
- R19: no DoS / no ARP spoofing. Firewall rules only, no active disruption of other teams.
- A too-aggressive deny that breaks DNS/AD replication = self-inflicted uptime loss. Change one
  rule, watch Watchtower 2 ticks, then the next.
