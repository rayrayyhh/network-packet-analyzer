# PacketSense

To run PacketSense, download all of the files within the PacketSense and copy it to the MiniNet VM using SCP. 
Use ip addr in the MiniNet VM to find its IP address (typically starting with 192.168.xx.xx).  
Afterwards, use scp -r (directory of the folder) mininet@192.168.xx.xx:~/ to save it to the home directory of MiniNet. 
From here you can easily CD to the folder and use sudo python3 main.py to run the code.  
In order to start listening and generate a PCAP file, use: h3 tcpdump -i h3-eth0 -nn -w /tmp/generated_traffic.pcap  
In order to stop listening: Ctrl+C  
In order to read the PCAP file: h3 tcpdump -nn -r /tmp/generated_traffic.pcap
