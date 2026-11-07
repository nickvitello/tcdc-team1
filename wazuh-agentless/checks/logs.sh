# Recent system log lines, ANALYZED by Wazuh's ruleset (state "periodic", not a
# diff): SSH brute force, new users, sudo use, service crashes. Every DiffSeconds
# (default 5 min). Needs root to read other users' logs; harmless without it.
# Lines from these checks themselves are filtered out.
journalctl --since=-5min --no-pager -o short -q 2>/dev/null | grep -v 'tcdc-agentless'
