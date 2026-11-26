#!/bin/bash
# The "internet": DNS for public names (everything else is NXDOMAIN) and HTTPS web sites.
# The C2 server is a separate container (ROLE=c2) at 10.77.0.250.
. /lab/common.sh
cat > /etc/dnsmasq.conf <<CONF
no-resolv
no-hosts
listen-address=0.0.0.0
bind-interfaces
local=/com/
local=/net/
local=/org/
local=/info/
local=/online/
local=/io/
address=/www.news-daily.com/$INTERNET_IP
address=/mail.office-cloud.com/$INTERNET_IP
address=/teams.office-cloud.com/$INTERNET_IP
address=/cdn.static-js.net/$INTERNET_IP
address=/api.weather-now.io/$INTERNET_IP
address=/www.search-engine.com/$INTERNET_IP
address=/updates.vendor-soft.com/$INTERNET_IP
address=/cdn-update-check.online/10.77.0.250
CONF
# decoy addresses in the internal /25 (not the workstation range): the attacker's sweep of "empty"
# IPs reaches this host, which has no listener, so the kernel RSTs each -> Zeek logs them as rejected.
for i in $(seq 65 95); do ip addr add 10.77.0.$i/24 dev eth0 2>/dev/null; done
dnsmasq --keep-in-foreground --log-facility=- >/dev/null 2>&1 &
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=lab" -keyout /tmp/k.pem -out /tmp/c.pem 2>/dev/null
exec python3 /lab/traffic/web.py
