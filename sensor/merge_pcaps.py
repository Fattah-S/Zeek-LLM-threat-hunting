"""Merge per-host pcap files into one time-ordered pcap (what a SPAN port would have seen).
Pure Python, classic pcap format (what tcpdump -w writes). Usage: merge_pcaps.py out.pcap in1.pcap in2.pcap ..."""
import heapq
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        end = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return  # truncated last packet (capture stopped mid-write)
            usec = frac // 1000 if nano else frac
            yield sec + usec / 1e6, sec, usec, orig, data


def main(out, inputs):
    n = 0
    with open(out, "wb") as o:
        o.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))  # Ethernet
        for ts, sec, usec, orig, data in heapq.merge(*(packets(p) for p in inputs), key=lambda x: x[0]):
            o.write(struct.pack("<IIII", sec, usec, len(data), orig) + data)
            n += 1
    print(f"merged {len(inputs)} files, {n} packets -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
