import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque


class LiveMonitor(object):
    def __init__(self, window=30):
        self.lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.hosts = set()
        self.last_packets = 0
        self.last_bytes = 0
        self.last_send = time.time()
        self.window = window
        self.tcp_events = deque()

    def record(self, frame, size):
        now = time.time()
        protocol = "Other"
        source = None
        destination = None
        tcp_event = None

        if len(frame) >= 14:
            ether_type = struct.unpack("!H", frame[12:14])[0]
            offset = 14
            while ether_type in (0x8100, 0x88a8, 0x9100):
                if len(frame) < offset + 4:
                    break
                ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
                offset += 4

            if ether_type == 0x0806:
                protocol = "ARP"
            elif ether_type == 0x0800 and len(frame) >= offset + 20:
                version_ihl = frame[offset]
                ip_header_length = (version_ihl & 15) * 4
                if (version_ihl >> 4) == 4 and ip_header_length >= 20 and len(frame) >= offset + ip_header_length:
                    source = socket.inet_ntoa(frame[offset + 12:offset + 16])
                    destination = socket.inet_ntoa(frame[offset + 16:offset + 20])
                    ip_protocol = frame[offset + 9]
                    fragment_offset = struct.unpack("!H", frame[offset + 6:offset + 8])[0] & 0x1fff
                    tcp_start = offset + ip_header_length
                    if ip_protocol == 6:
                        protocol = "TCP"
                        if fragment_offset == 0 and len(frame) >= tcp_start + 14:
                            destination_port = struct.unpack("!H", frame[tcp_start + 2:tcp_start + 4])[0]
                            flags = frame[tcp_start + 13]
                            syn = bool(flags & 0x02)
                            ack = bool(flags & 0x10)
                            if syn:
                                tcp_event = (now, source, destination, destination_port, ack)
                    elif ip_protocol == 17:
                        protocol = "UDP"
                    elif ip_protocol == 1:
                        protocol = "ICMP"
                    else:
                        protocol = "Other"

        with self.lock:
            self.total_packets += 1
            self.total_bytes += size
            self.protocols[protocol] += 1
            if source:
                self.hosts.add(source)
            if destination:
                self.hosts.add(destination)
            if tcp_event:
                self.tcp_events.append(tcp_event)
                if len(self.tcp_events) > 200000:
                    self.tcp_events.popleft()

    def snapshot(self):
        with self.lock:
            now = time.time()
            interval = max(now - self.last_send, 0.001)
            packet_rate = round((self.total_packets - self.last_packets) / interval, 2)
            byte_rate = round((self.total_bytes - self.last_bytes) / interval, 2)
            self.last_packets = self.total_packets
            self.last_bytes = self.total_bytes
            self.last_send = now

            while self.tcp_events and self.tcp_events[0][0] < now - self.window:
                self.tcp_events.popleft()

            ports_by_pair = {}
            syn_by_port = Counter()
            syn_ack_by_port = Counter()
            for _, src, dst, port, is_ack in self.tcp_events:
                key = (src, dst, port)
                if is_ack:
                    syn_ack_by_port[key] += 1
                else:
                    ports_by_pair.setdefault((src, dst), set()).add(port)
                    syn_by_port[key] += 1

            alerts = []
            for (src, dst), ports in sorted(ports_by_pair.items()):
                if len(ports) >= 8:
                    alerts.append({
                        "type": "Possible Port Scan", "severity": "Medium",
                        "source": src, "destination": dst,
                        "description": "{} unique destination ports in the last {} seconds".format(
                            len(ports), self.window),
                    })

            for (src, dst, port), count in syn_by_port.items():
                if count >= 100:
                    severity = "High" if count >= 200 else "Medium"
                    alerts.append({
                        "type": "High TCP SYN Activity", "severity": severity,
                        "source": src, "destination": dst, "port": port,
                        "description": "{} initial SYN packets to port {} in {} seconds; investigate possible SYN flood".format(
                            count, port, self.window),
                    })

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "active_hosts": sorted(self.hosts),
                "protocols": dict(self.protocols),
                "alerts": alerts[:30],
            }


def read_exact(stream, length):
    chunks = []
    remaining = length
    while remaining > 0:
        part = stream.read(remaining)
        if not part:
            return None
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def capture_packets(monitor, interface):
    command = ["tcpdump", "-i", interface, "-nn", "-U", "-s", "0", "-w", "-"]
    print("Starting capture:", " ".join(command))
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        header = read_exact(process.stdout, 24)
        if header is None:
            raise RuntimeError("tcpdump exited before writing a PCAP header")

        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise RuntimeError("Unknown tcpdump PCAP format")

        link_type = struct.unpack(endian + "I", header[20:24])[0] & 0xffff
        if link_type != 1:
            raise RuntimeError("Expected Ethernet PCAP, received link type {}".format(link_type))

        while True:
            record = read_exact(process.stdout, 16)
            if record is None:
                raise RuntimeError("tcpdump stopped reading packets")
            _, _, captured_length, original_length = struct.unpack(endian + "IIII", record)
            if captured_length > 2000000:
                raise RuntimeError("Invalid PCAP record length")
            frame = read_exact(process.stdout, captured_length)
            if frame is None:
                raise RuntimeError("Incomplete PCAP packet")
            monitor.record(frame, original_length)
    finally:
        process.terminate()
        try:
            process.wait()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Stream Mininet traffic to PacketSense")
    parser.add_argument("--interface", default="s1-eth3", help="Mininet switch port to capture")
    parser.add_argument("--server", required=True, help="Windows Flask base URL, e.g. http://192.168.139.1:5001")
    parser.add_argument("--window", type=int, default=30, help="Detection window in seconds")
    args = parser.parse_args()

    token = os.environ.get("PACKETSENSE_LIVE_TOKEN", "")
    if not token:
        parser.error("Set PACKETSENSE_LIVE_TOKEN before starting the monitor")

    monitor = LiveMonitor(window=max(1, args.window))
    worker = threading.Thread(target=capture_packets, args=(monitor, args.interface))
    worker.daemon = True
    worker.start()

    url = args.server.rstrip("/") + "/api/live-update"
    print("Sending live statistics to", url)
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
            if not worker.is_alive():
                raise RuntimeError("Capture thread stopped; check tcpdump and interface name")

            payload = monitor.snapshot()
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-PacketSense-Token": token,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    response.read()
                print("Packets: {} | {:.1f}/s | alerts: {}".format(
                    payload["total_packets"], payload["packet_rate"], len(payload["alerts"])
                ))
            except urllib.error.URLError as error:
                print("Cannot send live data: {}".format(error))
    except KeyboardInterrupt:
        print("Stopping PacketSense live monitor")
    except Exception as error:
        print("Live monitor error: {}".format(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
