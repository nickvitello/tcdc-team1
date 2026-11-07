# OPNsense playbook — network lead

The packet lists OPNsense management at `10.(100+X).40.1`. It is unscored but routes scored services. Do not infer the actual management path from one address alone.

## Inspect before changing

1. Use the approved jumpbox path. Record the current configuration locally and verify a usable configuration backup plus independent recovery access before changing rules.
2. Inventory accounts and service dependencies. Never change blackteam/whiteteam; retain packet OS accounts. Do not disable unfamiliar accounts solely because they are unfamiliar.
3. Inspect current firewall rules and states. Determine the interface and source address seen for a NEW management connection.
4. Inspect service transactions and the official scoreboard before and after each proposed change.

## Jumpbox source and recovery

PDF p. 14 shows the jumpbox with **both `10.99.X.2` and `10.(100+X).40.22`**, the latter inside the management subnet. Its actual GUI traffic may use that internal interface; do not assume either that it arrives from the VPN address or that NAT makes it internal. Check the actual packet source/interface and test a fresh session. Existing states can hide an accidental lockout until they expire.

The R6 text/scored-service table lists eight defended boxes, while the diagram also depicts this access jumpbox. R16 explicitly prohibits attack infrastructure on the jumpbox. Treat it as an access dependency; follow staff rulings for any broader defense scope. Do not change its policy or services based on this toolkit.

Keep independently tested console or other allowed recovery access. If it is unavailable, obtain staff assistance before a change that could cut your only management path.

## Packet R18 constraints

- Rules between your four team subnets are allowed under the packet's internal-traffic exception.
- An inbound block for outside sources must apply to **all source IPs**, not selected outside teams or staff ranges.
- An outbound block to an outside destination must specify **one destination IP and one port**. A blanket outbound block of ports 4444/5555/etc. for every destination does not satisfy this condition. Port numbers alone do not establish malicious activity.
- Preserve DNS, AD, MQTT, HTTP, FTP, SSH, management, staff, and scoring dependencies. No default-deny outbound, subnet-wide outbound blocks, DoS, or ARP spoofing.

Apply one reviewed change, test new management connections and relevant service transactions, observe official scoring, and restore the prior configuration on failure. Watchtower provides supporting observations, not proof of scorer access or rules compliance. If scope or policy is unclear, R17 directs you to Black Team.
