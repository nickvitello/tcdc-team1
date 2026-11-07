# Validation record

## Local preparation checks

- Eight retained dashboard/protocol/vault regression checks pass.
- Fifteen unittest cases pass on macOS: DNS names/CNAMEs/compression/source, LDAP structure, HTTP redirect scope, corrupt vault/schema preservation, protected accounts, command quoting, concurrent writers, and Linux integrity/installer fixtures.
- Linux fixtures redirect all privileged paths into temporary trees and stub system commands. They exercise first installation, old-baseline refusal, explicit archive/rebaseline, own-unit integrity, rerun preservation, file modes, symlink retargeting/target changes, and new/deleted paths.
- Python parsing, JSON example parsing, and Bash syntax are checked separately.

## CI

`.github/workflows/checks.yml` runs the Python checks on Ubuntu and Windows. `tests/windows.ps1` parses every PowerShell file using Windows PowerShell 5.1, exercises real read-only service/task/admin enumeration and the ADSI fallback, and checks snapshot comparison, archive/schema behavior, bootstrap download failures, and rejection of legacy firewall activation. Separate guarded CI smoke tests install the actual Linux/Windows watchers on disposable hosted runners, verify systemd/SYSTEM task execution, preserve accepted state on rerun, detect a harmless canary/module change, and restore the changed object. No attack operations or competition systems are involved.

Both jobs, including native installation smoke tests, passed for `c2ec1c4` in [run 42330156212](https://github.com/nickvitello/tcdc-team1/actions/runs/42330156212). See subsequent commit checks for the final revision.

CI status for each commit is authoritative; inspect its run before deployment. Full Windows 11/DC deployment, AD-domain behavior, OPNsense policy, live checker transactions, and staff/jumpbox reachability are not established by these tests. Test on disposable local images and verify the official scorer after deployment. No competition infrastructure was contacted during this preparation.

## Deliberate behavior changes

- Host installers no longer automatically change firewall or SSH policy. The Windows firewall switches fail before mutation; see firewall-windows.md.
- Linux and Windows file/configuration snapshots use a versioned format. Old accepted evidence is retained until explicit reviewed rebaseline, then archived before replacement.
- Windows monitoring records full task definitions rather than one action; first baseline is taken after watcher installation.
- Linux snapshots use JSON paths, track symlinks and metadata, and include the watcher files and units.
- Account census totals were removed in favor of identity-based review against the packet; built-in/staff accounts make simple totals misleading.
- Host watcher webhooks were removed. Watchtower's optional alert webhook remains off by default and requires staff permission for data export.
- Vault `sync` is manual attestation. Password prompting, storage, and service-credential updates do not perform a remote reset or scoreboard update.
