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
- Deny inbound to mgmt (SSH/GUI) except from jumpbox 10.99.1.2.
- Leave ICMP to the test box alone; never touch competition infra (R7/R9).

## Trap
- R19: no DoS / no ARP spoofing. Firewall rules only, no active disruption of other teams.
- A too-aggressive deny that breaks DNS/AD replication = self-inflicted uptime loss. Change one
  rule, watch Watchtower 2 ticks, then the next.
