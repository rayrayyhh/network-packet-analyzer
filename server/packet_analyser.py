from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
import json
import sys
from collections import Counter


def analyse_pcap(filename):
    packets = rdpcap(filename)

    total_packets = len(packets)
    total_bytes = sum(len(packet) for packet in packets)

    timestamps = []
    packet_sizes = []

    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    source_ports = Counter()
    destination_ports = Counter()
    communication_pairs = Counter()
    tcp_flags = Counter(syn=0, syn_ack=0, rst=0, ack=0, fin=0)
    probe_ports = {}

    for packet in packets:

        packet_sizes.append(len(packet))

        if hasattr(packet, "time"):
            timestamps.append(float(packet.time))

        if ARP in packet:
            protocols["ARP"] += 1

        elif IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            source_ips[source_ip] += 1
            destination_ips[destination_ip] += 1

            pair = source_ip + " -> " + destination_ip
            communication_pairs[pair] += 1

            if TCP in packet:
                protocols["TCP"] += 1
                source_ports[str(packet[TCP].sport)] += 1
                destination_ports[str(packet[TCP].dport)] += 1
                flags = int(packet[TCP].flags)
                if flags & 2:
                    if flags & 16:
                        tcp_flags["syn_ack"] += 1
                    else:
                        tcp_flags["syn"] += 1
                        probe_ports.setdefault(source_ip, set()).add(int(packet[TCP].dport))
                for flag, mask in (("rst", 4), ("ack", 16), ("fin", 1)):
                    if flags & mask:
                        tcp_flags[flag] += 1

            elif UDP in packet:
                protocols["UDP"] += 1
                source_ports[str(packet[UDP].sport)] += 1
                destination_ports[str(packet[UDP].dport)] += 1

            elif ICMP in packet:
                protocols["ICMP"] += 1

            else:
                protocols["Other IP"] += 1

        else:
            protocols["Other"] += 1

    if timestamps:
        start_time = min(timestamps)
        end_time = max(timestamps)

        # Scapy normalises both microsecond and nanosecond PCAP times to seconds.
        duration = end_time - start_time
    else:
        start_time = None
        end_time = None
        duration = 0

    if duration > 0:
        packets_per_second = total_packets / duration
        bytes_per_second = total_bytes / duration
    else:
        packets_per_second = 0
        bytes_per_second = 0

    if packet_sizes:
        average_packet_size = total_bytes / total_packets
        minimum_packet_size = min(packet_sizes)
        maximum_packet_size = max(packet_sizes)
    else:
        average_packet_size = 0
        minimum_packet_size = 0
        maximum_packet_size = 0

    if total_packets > 0:
        protocol_percentages = {
            protocol: round((count / total_packets) * 100, 2)
            for protocol, count in protocols.items()
        }
    else:
        protocol_percentages = {}

    result = {
        "capture_file": filename,
        "total_packets": total_packets,
        "total_bytes": total_bytes,

        "capture_duration_seconds": round(duration, 3),
        "packets_per_second": round(packets_per_second, 3),
        "bytes_per_second": round(bytes_per_second, 3),

        "packet_size": {
            "average_bytes": round(average_packet_size, 3),
            "minimum_bytes": minimum_packet_size,
            "maximum_bytes": maximum_packet_size
        },

        "start_timestamp": start_time,
        "end_timestamp": end_time,

        "protocols": dict(protocols),
        "protocol_percentages": protocol_percentages,

        "source_ips": dict(source_ips),
        "destination_ips": dict(destination_ips),

        "communication_pairs": dict(communication_pairs),

        "source_ports": dict(source_ports),
        "destination_ports": dict(destination_ports),
        "tcp_flags": dict(tcp_flags),
        "unique_source_ports": len(source_ports),
        "unique_destination_ports": len(destination_ports),
        "unique_destination_ports_per_source": {
            source: len(ports) for source, ports in probe_ports.items()
        },
    }

    return result


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 packet_analyser.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    analysis = analyse_pcap(pcap_file)

    with open("traffic_analysis.json", "w") as output_file:
        json.dump(analysis, output_file, indent=4)

    print(json.dumps(analysis, indent=4))
    print("\nAnalysis saved to traffic_analysis.json")
