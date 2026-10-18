Download everything in the packetsense folder and also download .gitignore, package-lock.json and package.json

Installation

Once mininet has been setup

Step 1 Once you see mininet> h3 tcpdump -i h3-eth0 -nn -w /tmp/generated_traffic.pcap &

Step 2 Still at the mininet> prompt, run: h1 ping -c 10 h3

Step 3 Start Flask Open PowerShell and navigate to your PacketSense server folder (VS Code):

Set the live monitoring token: $env:PACKETSENSE_LIVE_TOKEN="packetsenselab"

Start Flask: py api.py

Step 4 Start React Website In VS Code cd to packetsense folder then in terminal run npm run dev

Then open the website through link such as http://localhost:5173

Step 5 Find Windows IP Find the IPv4 address of the Windows network adapter connected to your Mininet VM In Powershell run ipconfig

Step 6 Open another PowerShell on Windows Enter: ssh mininet@192.168.139.132

Step 7 Run Curl using the IPv4 Address of the Windows network adapter connected to your Mininet VM (Try VMNet 8 before VMNet 1).

Example curl http://192.168.139.1:5001/api/status

This should say { "service": "PacketSense API", "status": "online"}

Step 8 Check that live_monitor.py is in Mininet In the Mininet Powershell terminal cd to PacketSense folder containing live_monitor.py cd PacketSense

Then Check the Mininet network interface ip link show s1-eth3

If it displays information about s1-eth3, the interface exists and can be used for monitoring traffic to h3.

Step 9 Start Live Monitoring export PACKETSENSE_LIVE_TOKEN='packetsenselab'

Then start the monitor (Replace WINDOWS_IP with the previous working curl IP):

sudo -E python3 live_monitor.py --interface s1-eth3 --server http://WINDOWS_IP:5001

Step 10 Generate traffic in Mininet Return to Mininet and run

h1 ping -c 20 h3

Step 11

Test automatic attack detection Generate a controlled port-scan test against your own simulated host h3

In Mininet Type

h1 python3 /home/mininet/PacketSense/port-scan-generator.py OR h1 bash -c 'for p in 22 23 25 53 80 443 8000 8080; do (echo > /dev/tcp/10.0.0.3/$p) 2>/dev/null; done'

Generate simulated TCP SYN flood traffic

h1 python3 /home/mininet/PacketSense/tcp-syn-flood-generator.py OR h1 bash -c 'for i in $(seq 1 150); do (echo > /dev/tcp/10.0.0.3/8000) 2>/dev/null; done'
