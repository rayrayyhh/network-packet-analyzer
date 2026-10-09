from scapy.all import IP, TCP, sr1
import time


SOURCE_IP = "10.0.0.1"
TARGET_IP = "10.0.0.3"

TARGET_PORTS = [
    22,
    23,
    25,
    53,
    80,
    443,
    8000,
    8080,
]

SCAN_DELAY = 0.2


def port_scan():
    print("Starting controlled TCP port scan")
    print(f"Source: {SOURCE_IP}")
    print(f"Target: {TARGET_IP}")
    print(f"Ports: {TARGET_PORTS}")

    for port in TARGET_PORTS:

        packet = (
            IP(src=SOURCE_IP, dst=TARGET_IP)
            / TCP(
                sport=40000,
                dport=port,
                flags="S"
            )
        )

        response = sr1(
            packet,
            timeout=1,
            verbose=False
        )

        if response is None:
            print(f"Port {port}: NO RESPONSE")

        elif response.haslayer(TCP):

            flags = response[TCP].flags

            if flags & 0x12 == 0x12:
                print(f"Port {port}: OPEN")

            elif flags & 0x14 == 0x14:
                print(f"Port {port}: CLOSED")

            else:
                print(f"Port {port}: response flags {flags}")

        time.sleep(SCAN_DELAY)

    print("Port scan complete")


if __name__ == "__main__":
    port_scan()
