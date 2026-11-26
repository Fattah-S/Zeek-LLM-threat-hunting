# One image for every simulated host in the lab: domain controller, file server,
# workstations, the deployment server, the "internet" and the C2 server.
# The ROLE environment variable picks what the container does (see entrypoint.sh).
ARG BASE=ubuntu:24.04
FROM ${BASE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient krb5-user winbind python3 python3-impacket \
      python3-requests python3-dnspython dnsmasq tcpdump iproute2 dnsutils \
      ldap-utils openssl curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY . /lab
RUN chmod +x /lab/*.sh
ENTRYPOINT ["/lab/entrypoint.sh"]
