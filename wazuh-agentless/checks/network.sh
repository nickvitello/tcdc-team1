# Listening ports and OUTBOUND connections (where C2 usually shows up).
# Diffed every ActivitySeconds (default 2 min). Inbound client connections (the
# scorer, your own SSH) are left out on purpose: they come and go every tick.
export LC_ALL=C
echo ==LISTENERS==; ss -tulnpH 2>/dev/null | sed -E 's/,pid=[0-9]+//g; s/,fd=[0-9]+//g' | awk '{print $1, $5, $7}' | sort -u
echo ==OUTBOUND==
L=" $(ss -tlnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -u | tr '\n' ' ') "
ss -tnH state established 2>/dev/null | awk -v L="$L" '{n=split($3,a,":"); if (index(L, " " a[n] " ")==0) print $4}' | sed -E 's/:[0-9]+$//' | sort -u
echo ==HOSTS==; grep -vE '^[[:space:]]*(#|$)' /etc/hosts
echo ==RESOLV==; grep -vE '^[[:space:]]*(#|$)' /etc/resolv.conf 2>/dev/null
echo ==END==
