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




SOURCE_IP = "10.0.0.1"


TARGET_IP = "10.0.0.3"


DNS_SERVER = "10.0.0.3"

PACKETS_TO_SEND = 30

MIN_DELAY = 0.2
MAX_DELAY = 1.5



def generate_icmp():
    #So this one for generating an ICMP echo request to h3 (host), coming from h1.

    packet = (
        IP(src=SOURCE_IP, dst=TARGET_IP)
        / ICMP()
    )

    send(packet, verbose=False)

    print("ICMP echo request: h1 to h3")


def generate_udp():
    #This one to generate a UDP data packet from h1 to h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=SOURCE_IP, dst=TARGET_IP)
        / UDP(
            sport=source_port,
            dport=5000
        )
        / Raw(load=b"normal-test-data")
    )

    send(packet, verbose=False)

    print("UDP packet: h1 to h3")


def generate_dns():
    #anddd this one generates a DNS query to h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=SOURCE_IP, dst=DNS_SERVER)
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

    print("DNS query: h1 to h3")


def generate_tcp_syn():
    #This is to generate a TCP SYN toward a service on h3.

    source_port = random.randint(40000, 50000)

    packet = (
        IP(src=SOURCE_IP, dst=TARGET_IP)
        / TCP(
            sport=source_port,
            dport=8000,
            flags="S"
        )
    )

    send(packet, verbose=False)

    print("TCP SYN: h1 to h3")




def main():

    print("Starting normal traffic generation...")
    print(f"Source (h1): {SOURCE_IP}")
    print(f"Target (h3): {TARGET_IP}")
    print()

    for _ in range(PACKETS_TO_SEND):

        traffic_type = random.choice([
            "icmp",
            "udp",
            "dns",
            "tcp"
        ])

        try:

            if traffic_type == "icmp":
                generate_icmp()

            elif traffic_type == "udp":
                generate_udp()

            elif traffic_type == "dns":
                generate_dns()

            elif traffic_type == "tcp":
                generate_tcp_syn()

        except Exception as error:
            print(f"Unfortunately, there was a traffic generation error. Here is the error: {error}")

        # Random delay between packets
        delay = random.uniform(
            MIN_DELAY,
            MAX_DELAY
        )

        time.sleep(delay)

    print()
    print("Traffic generation is now complete.")


if __name__ == "__main__":
    main()

