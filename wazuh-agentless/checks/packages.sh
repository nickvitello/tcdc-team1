# Installed packages (an attacker installing netcat, nmap, a compiler...).
# Diffed every SlowSeconds (default 15 min).
dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort
echo ==END==
