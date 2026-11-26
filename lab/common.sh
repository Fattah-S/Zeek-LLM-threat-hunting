# shared helpers for every role
CONTROL=/control          # shared volume: the orchestrator writes the current session here
PCAP=/pcap                # shared volume: every host mirrors its inbound packets here
DOMAIN=corp.lab
REALM=CORP.LAB
DC_IP=10.77.0.10
INTERNET_IP=10.77.0.240

current_session() { cat "$CONTROL/session" 2>/dev/null || echo idle; }

# Virtual SPAN port: each host captures only packets it RECEIVES (-Q in), so every packet
# on the lab network is captured exactly once. The sensor merges all files per session.
capture_loop() {
  local last=idle pid=""
  while true; do
    s=$(current_session)
    if [ "$s" != "$last" ]; then
      [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
      pid=""
      if [ "$s" != idle ] && [ "$s" != done ]; then
        mkdir -p "$PCAP/$s"
        tcpdump -i eth0 -Q in -s 0 -U -w "$PCAP/$s/$(hostname).pcap" not port 9 2>/dev/null &
        pid=$!
      fi
      last=$s
    fi
    sleep 0.5
  done
}
