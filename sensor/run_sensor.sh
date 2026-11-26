#!/bin/bash
# Zeek sensor. Watches /pcap for finished capture sessions (and any PCAP you drop in /pcap/byo/),
# merges each session's per-host files, runs Zeek, and writes JSON logs to /logs/<session>/.
set -u
mkdir -p /logs /pcap/byo
zeek_run() {  # $1 = pcap file, $2 = output dir
  mkdir -p "$2" && cd "$2" && rm -f *.log
  zeek -C -r "$1" LogAscii::use_json=T /sensor/local.zeek
  echo "[sensor] $(basename "$2"): $(ls *.log 2>/dev/null | tr '\n' ' ')"
}
echo "[sensor] waiting for capture sessions in /pcap"
while true; do
  for d in /pcap/*/; do
    s=$(basename "$d")
    [ "$s" = byo ] && continue
    if [ -f "$d/CLOSED" ] && [ ! -f "/logs/$s/DONE" ]; then
      python3 /sensor/merge_pcaps.py "/tmp/$s.pcap" "$d"*.pcap
      zeek_run "/tmp/$s.pcap" "/logs/$s"
      [ -f "$d/ground_truth.json" ] && cp "$d/ground_truth.json" "/logs/$s/"
      rm -f "/tmp/$s.pcap"; touch "/logs/$s/DONE"
    fi
  done
  for p in /pcap/byo/*.pcap /pcap/byo/*.pcapng; do
    [ -f "$p" ] || continue
    s="byo-$(basename "${p%.*}")"
    [ -f "/logs/$s/DONE" ] || { zeek_run "$p" "/logs/$s"; touch "/logs/$s/DONE"; }
  done
  sleep 3
done
