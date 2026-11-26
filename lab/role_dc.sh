#!/bin/bash
# Samba Active Directory domain controller: Kerberos, LDAP, DNS, SMB, DRSUAPI (DCSync is real here).
. /lab/common.sh
PASS='Lab-Passw0rd!'
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=$REALM --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$PASS" --host-ip=$DC_IP \
    --option="dns forwarder = $INTERNET_IP" --option="ntlm auth = yes" \
    --option="kerberos encryption types = all" --option="interfaces = lo eth0" --option="bind interfaces only = yes" --option="server smb encrypt = off" >/dev/null
  cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
  # file share on the DC (Kerberos SMB traffic from every workstation)
  mkdir -p /srv/shares && echo "Q3 numbers" > /srv/shares/report.txt && chmod -R 777 /srv/shares
  printf '\n[shares]\n  path = /srv/shares\n  read only = no\n' >> /etc/samba/smb.conf
fi
samba -i -M single &
for i in $(seq 1 60); do samba-tool user list >/dev/null 2>&1 && break; sleep 1; done
if ! samba-tool user show user01 >/dev/null 2>&1; then
  for u in user01 user02 user03 user04 user05; do samba-tool user create $u 'User-Passw0rd!' >/dev/null; done
  samba-tool user create adm_it 'Adm-Passw0rd!' >/dev/null
  samba-tool group addmembers "Domain Admins" adm_it >/dev/null
  # service accounts with SPNs: the Kerberoasting targets
  for s in sql web backup report crm bi; do
    samba-tool user create svc_$s 'Svc-Passw0rd!' >/dev/null
    samba-tool spn add "MSSQLSvc/$s.corp.lab:1433" svc_$s >/dev/null
  done
  samba-tool user setexpiry Administrator --noexpiry >/dev/null
fi
echo ready > /control/dc_ready
echo "[dc] ready"
wait
