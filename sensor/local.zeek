# Protocol logs the hunts need. All of these analyzers ship with Zeek and are on by default;
# loading them explicitly documents the dependency.
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/krb
@load base/protocols/ntlm
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/rdp
@load base/protocols/http
# Keep a connection's duration accurate for long tunnels
redef tcp_inactivity_timeout = 2 hrs;
