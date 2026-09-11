import argparse
import random
import time

from scapy.all import (
    IP,
    ICMP,
    UDP,
    TCP,
    DNS,
    DNSQR,
    Raw,
    send,
)


MIN_DELAY = 0.2
MAX_DELAY = 1.5



def generate_icmp(source_ip, target_IP, source_name):
    #So this one for generating an ICMP echo request to h3 (host), coming from h1.

    packet = (
        IP(src=source_ip, dst=target_IP) / ICMP()
    )

    send(packet, verbose=False)

    print(f"ICMP echo request: {source_name} -> h3")


def generate_udp(source_ip, target_IP, source_name):
    #This one to generate a UDP data packet from h1 to h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=source_ip, dst=target_IP)
        / UDP(
            sport=source_port,
            dport=5000
        )
        / Raw(load=b"normal-test-data")
    )

    send(packet, verbose=False)

    print(f"UDP packet: {source_name} to h3")


def generate_dns(source_ip, target_IP, source_name):
    #anddd this one generates a DNS query to h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=source_ip, dst=target_IP)
        / UDP(
            sport=source_port,
            dport=53
        )
        / DNS(
            rd=1,
            qd=DNSQR(qname="example.com")
        )
    )

    send(packet, verbose=False)

    print(f"DNS query: {source_name} to h3")


def generate_tcp_syn(source_ip, target_IP, source_name):
    #This is to generate a TCP SYN toward a service on h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=source_ip, dst=target_IP)
        / TCP(
            sport=source_port,
            dport=8000,
            flags="S"
        )
    )

    send(packet, verbose=False)

    print(f"TCP SYN: {source_name} to h3")




def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--target-ip", default="10.0.0.3")

    args = parser.parse_args()

    print("Starting normal traffic generation...")
    print(f"Source: {args.source_name} ({args.source_ip})")
    print(f"Target: ({args.target_ip})")

    try:
        while True:
            traffic_type = random.choice([
                "icmp",
                "udp",
                "dns",
                "tcp"
            ])

            try:
                if traffic_type == "icmp":
                    generate_icmp(
                        args.source_ip,
                        args.target_ip,
                        args.source_name
                    )

                elif traffic_type == "udp":
                    generate_udp(
                        args.source_ip,
                        args.target_ip,
                        args.source_name
                    )

                elif traffic_type == "dns":
                    generate_dns(
                        args.source_ip,
                        args.target_ip,
                        args.source_name
                    )

                elif traffic_type == "tcp":
                    generate_tcp_syn(
                        args.source_ip,
                        args.target_ip,
                        args.source_name
                    )

            except Exception as error:
                print(
                    f"Traffic generation error: {error}",
                    flush=True
                )

            time.sleep(
                random.uniform(MIN_DELAY, MAX_DELAY)
            )

    except KeyboardInterrupt:
        print("Traffic generation stopped.")

if __name__ == "__main__":
    main()

