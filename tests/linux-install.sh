#!/usr/bin/env bash
# CI ONLY: installs the actual watcher on a disposable GitHub-hosted Ubuntu runner.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'Requires disposable GitHub Actions runner'; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'Run CI smoke check as root'; exit 2; }
[ ! -e /root/tcdc-baseline ] || { echo 'Refusing existing baseline'; exit 2; }
cleanup(){
  systemctl disable --now tcdc-watch.timer || true
  systemctl stop tcdc-watch.service || true
}
trap cleanup EXIT
bash linux/harden.sh ci-fixture
systemctl start tcdc-watch.service
result=$(systemctl show tcdc-watch.service -p Result --value)
[ "$result" = success ] || { echo "Watcher failed: $result"; exit 1; }
python3 /usr/local/lib/tcdc/baseline.py check /root/tcdc-baseline/integrity.json
original=$(sha256sum /root/tcdc-baseline/integrity.json)
bash linux/harden.sh ci-fixture
[ "$(sha256sum /root/tcdc-baseline/integrity.json)" = "$original" ]
# Verify a real new persistence file is logged, then restore only our harmless canary.
printf '# CI harmless canary\n' > /etc/cron.d/tcdc-ci-canary
systemctl start tcdc-watch.service
grep -q 'tcdc-ci-canary' /root/tcdc-baseline/drift.log
rm /etc/cron.d/tcdc-ci-canary
python3 /usr/local/lib/tcdc/baseline.py check /root/tcdc-baseline/integrity.json
echo 'PASS: real Linux install, systemd run, rerun preservation, canary detection and cleanup'
