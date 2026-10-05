import argparse
import random
import socket
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




TARGET_IP = "10.0.0.3"
DNS_SERVER = "10.0.0.3"

HTTP_PORT = 8000
UDP_PORT = 5000

EXPERIMENT_DURATION = 300

MIN_DELAY = 0.2
MAX_DELAY = 1.0



# Command line arguments defined here


def get_arguments():

    parser = argparse.ArgumentParser(
        description="Generate normal network traffic"
    )

    parser.add_argument(
        "--source-ip",
        required=True,
        help="Source IP address of the Mininet host"
    )

    parser.add_argument(
        "--source-name",
        required=True,
        help="Name of the Mininet host"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=EXPERIMENT_DURATION,
        help="Traffic generation duration in seconds"
    )

    return parser.parse_args()



# ICMP generator defined


def generate_icmp(source_ip):

    packet = (
        IP(
            src=source_ip,
            dst=TARGET_IP
        )
        / ICMP()
    )

    send(packet, verbose=False)

    print(
        f"[ICMP] {source_ip} -> {TARGET_IP}"
    )



# DNS generation defined


def generate_dns(source_ip):

    source_port = random.randint(40000, 50000)

    domain_names = [
        "example.com",
        "example.org",
        "example.net",
        "test.local",
    ]

    domain = random.choice(domain_names)

    packet = (
        IP(
            src=source_ip,
            dst=DNS_SERVER
        )
        / UDP(
            sport=source_port,
            dport=53
        )
        / DNS(
            rd=1,
            qd=DNSQR(
                qname=domain
            )
        )
    )

    send(packet, verbose=False)

    print(
        f"[DNS] {source_ip} -> {DNS_SERVER}:53 "
        f"query={domain}"
    )



# UDP traffic defined


def generate_udp(source_ip):

    source_port = random.randint(40000, 50000)

    messages = [
        b"normal-test-data",
        b"application-message",
        b"status-update",
        b"heartbeat",
        b"normal-network-data",
    ]

    message = random.choice(messages)

    packet = (
        IP(
            src=source_ip,
            dst=TARGET_IP
        )
        / UDP(
            sport=source_port,
            dport=UDP_PORT
        )
        / Raw(
            load=message
        )
    )

    send(packet, verbose=False)

    print(
        f"[UDP] {source_ip}:{source_port} "
        f"-> {TARGET_IP}:{UDP_PORT}"
    )



# HTTP traffic defined


def generate_http(source_ip):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect(
            (TARGET_IP, HTTP_PORT)
        )

        request = (
            "GET / HTTP/1.1\r\n"
            f"Host: {TARGET_IP}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        sock.recv(4096)

        sock.close()

        print(
            f"[HTTP] {source_ip} "
            f"-> {TARGET_IP}:{HTTP_PORT}"
        )

    except Exception as error:

        print(
            f"[HTTP] connection error: {error}"
        )



#tcp syn stuff


def generate_tcp_syn(source_ip):

    source_port = random.randint(40000, 50000)

    packet = (
        IP(
            src=source_ip,
            dst=TARGET_IP
        )
        / TCP(
            sport=source_port,
            dport=HTTP_PORT,
            flags="S"
        )
    )

    send(packet, verbose=False)

    print(
        f"[TCP SYN] {source_ip}:{source_port} "
        f"-> {TARGET_IP}:{HTTP_PORT}"
    )



# Randomly select traffic here


def generate_random_traffic(source_ip):

    traffic_type = random.choices(
        [
            "icmp",
            "dns",
            "udp",
            "http",
            "tcp_syn",
        ],
        weights=[
            25,
            15,
            20,
            30,
            10,
        ],
        k=1
    )[0]

    if traffic_type == "icmp":
        generate_icmp(source_ip)

    elif traffic_type == "dns":
        generate_dns(source_ip)

    elif traffic_type == "udp":
        generate_udp(source_ip)

    elif traffic_type == "http":
        generate_http(source_ip)

    elif traffic_type == "tcp_syn":
        generate_tcp_syn(source_ip)






def main():

    args = get_arguments()

    print()
    print(" Generic Network Traffic Generator 2")
    print()

    print(f"Host: {args.source_name}")
    print(f"Source IP: {args.source_ip}")
    print(f"Destination: {TARGET_IP}")
    print(f"Duration: {args.duration} seconds")
    print()

    print("Traffic types:")
    print("ICMP")
    print("DNS")
    print("UDP")
    print("HTTP")
    print("TCP SYN")
    print()

    start_time = time.time()

    traffic_count = 0

    while time.time() - start_time < args.duration:

        try:

            generate_random_traffic(
                args.source_ip
            )

            traffic_count += 1

        except Exception as error:

            print(
                f"[ERROR] Traffic generation error: {error}"
            )

        delay = random.uniform(
            MIN_DELAY,
            MAX_DELAY
        )

        time.sleep(delay)

    print()
    print(" Normal traffic generation complete")
    print(f"Host: {args.source_name}")
    print(f"Traffic events: {traffic_count}")
    print()


if __name__ == "__main__":
    main()

