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

EXPERIMENT_DURATION = 60


MIN_DELAY = 0.3
MAX_DELAY = 1




def get_arguments():
    parser = argparse.ArgumentParser(
        description="Generate realistic normal network traffic"
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
        help="Traffic generation duration in seconds; 0 runs until stopped"
    )

    return parser.parse_args()


# ICMP traffic defined here

def generate_icmp(source_ip):
    packet = (
        IP(src=source_ip, dst=TARGET_IP)
        / ICMP()
    )

    send(packet, verbose=False)

    print(
        f"[ICMP] {source_ip} -> {TARGET_IP}"
    )


# DNS traffic defined here

def generate_dns(source_ip):
    source_port = random.randint(40000, 50000)

    domain_names = [
        "example.com",
        "example.org",
        "example.net",
        "google.com",
        "facebook.com",
        "example.com",
        "test.local",
    ]

    domain = random.choice(domain_names)

    packet = (
        IP(src=source_ip, dst=DNS_SERVER)
        / UDP(
            sport=source_port,
            dport=53
        )
        / DNS(
            rd=1,
            qd=DNSQR(qname=domain)
        )
    )

    send(packet, verbose=False)

    print(
        f"[DNS] {source_ip}:{source_port} "
        f"-> {DNS_SERVER}:53 "
        f"query={domain}"
    )


# UDP traffic defined here

def generate_udp(source_ip):
    source_port = random.randint(40000, 50000)

    messages = [
        b"heartbeat",
        b"status-update",
        b"normal-test-data",
        b"application-message",
        b"sensor-data",
        b"user-request",
        b"network-status",
        b"periodic-update",
    ]

    message = random.choice(messages)


    extra_data = random.choice([
        b"",
        b" OK",
        b" 1234",
        b" normal-data",
        b" packet-data"
    ])

    payload = message + extra_data

    packet = (
        IP(src=source_ip, dst=TARGET_IP)
        / UDP(
            sport=source_port,
            dport=UDP_PORT
        )
        / Raw(load=payload)
    )

    send(packet, verbose=False)

    print(
        f"[UDP] {source_ip}:{source_port} "
        f"-> {TARGET_IP}:{UDP_PORT} "
        f"bytes={len(payload)}"
    )


# HTTP traffic define

def generate_http(source_ip):
    paths = [
        "/",
        "/index.html",
        "/status",
        "/about",
        "/data",
    ]

    path = random.choice(paths)

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
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET_IP}\r\n"
            "User-Agent: PacketSense-NormalClient/1.0\r\n"
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
            f"-> {TARGET_IP}:{HTTP_PORT} "
            f"path={path}"
        )

    except Exception as error:
        print(
            f"[HTTP] connection error: {error}"
        )


# TCP SYN traffic

def generate_tcp_syn(source_ip):
    source_port = random.randint(
        40000,
        50000
    )

    packet = (
        IP(src=source_ip, dst=TARGET_IP)
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


# Random choice of traffic to be generated
# (note that weights match order of traffic_type)

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
            20,
            15,
            20,
            30,
            5,
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
    print(" PacketSense normal traffic generator")
    print()

    print(f"Host: {args.source_name}")
    print(f"Source IP: {args.source_ip}")
    print(f"Destination: {TARGET_IP}")
    print(f"Duration: {args.duration} seconds")
    print()

    print("Traffic types:")
    print("ICMP")
    print("DNS")
    print("UDP application data")
    print("HTTP")
    print("TCP SYN")
    print()

    print(
        f"Event interval: {MIN_DELAY}-{MAX_DELAY} seconds"
    )

    print(
        "Expected rate:  approximately 2-3 events/second"
    )

    print()

    start_time = time.time()

    traffic_count = 0

    while args.duration == 0 or time.time() - start_time < args.duration:

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

    print(
        f"Host: {args.source_name}"
    )

    print(
        f"Traffic events: {traffic_count}"
    )

    print()


if __name__ == "__main__":
    main()

