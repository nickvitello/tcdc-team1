# Windows firewall: manual policy change only

`harden.ps1` reports profiles and leaves policy untouched. The former `-EnableFirewall` and `-EnableDefaultDeny` switches now fail before mutations. Scored-port compatibility parameters are accepted but do not create rules.

Enabling a previously disabled profile can activate an existing block policy. An allow rule with a matching display name is not proof of access, and explicit block rules override conflicting allow rules. See [Microsoft's precedence documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

Before changing policy:

1. Identify the effective profiles, GPO policy, existing blocks, and actual service dependencies. MQTT uses 1883 in this configuration; AD needs more than a short list of static TCP ports, including UDP and potentially dynamic RPC. Preserve the access methods used by staff and the checker.
2. Export and verify a local policy backup with `netsh advfirewall export <local-path>`. Check the exit status and nonempty file. This is evidence and a rollback aid, not a tested recovery path by itself.
3. Establish and test independent console recovery. If unavailable, leave current policy unchanged until staff helps establish recovery. A current RDP connection may survive while new connections fail.
4. Prepare narrowly scoped rules based on observed services and effective filters. Apply the packet's R18 restrictions: outside-source blocks must apply to all sources; outside-destination blocks name one destination IP and one port. Never add blanket outbound deny.
5. Make one change, test new management connections and service transactions from the actual allowed access/checker paths, observe official scoring, and roll back immediately on failure. A local open-port check or matching rule name is insufficient.

This toolkit intentionally does not claim an automatic safe-enable gate. Test a policy on disposable local Windows images before competition use.
