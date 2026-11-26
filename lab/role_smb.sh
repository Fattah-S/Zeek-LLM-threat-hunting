#!/bin/bash
# Standalone SMB server with admin shares, so ADMIN$ / C$ / svcctl / NTLM traffic exists on
# the file server and on every workstation (deployment tool, PsExec, pass-the-hash targets).
. /lab/common.sh
mkdir -p /srv/admin /srv/c /srv/data && chmod 777 /srv/admin /srv/c /srv/data
echo "sales,42" > /srv/data/sales.csv
cat > /etc/samba/smb.conf <<CONF
[global]
  workgroup = CORP
  server role = standalone server
  ntlm auth = yes
  server smb encrypt = off
  server signing = auto
  map to guest = never
[ADMIN\$]
  path = /srv/admin
  read only = no
[C\$]
  path = /srv/c
  read only = no
[data]
  path = /srv/data
  read only = no
CONF
add() { id $1 >/dev/null 2>&1 || useradd -M $1; printf '%s\n%s\n' "$2" "$2" | smbpasswd -a -s $1 >/dev/null; }
add adm_it 'Adm-Passw0rd!'          # same local admin password everywhere: what pass-the-hash abuses
add svc_deploy 'Deploy-Passw0rd!'   # the deployment tool's account
for u in user01 user02 user03 user04 user05; do add $u 'User-Passw0rd!'; done
exec smbd -F --no-process-group
