ENSURE YOU ARE USING
https://github.com/mininet/mininet/releases/download/2.3.0/mininet-2.3.0-210211-ubuntu-20.04.1-legacy-server-amd64-ovf.zip

Import the folder into the MiniNet VM, you can achieve this by using scp.
scp -r <location of folder> mininet@VM_IP

First run: bash setup.sh
After the program installs all of its dependencies, you can run bash run.sh.

After seeing mininet> in the terminal, you can now access the dashboard at http://VM_IP:5001.
Use either of these two commands to test an attack.
h1 .venv/bin/python attack_simulation/port-scan-generator.py
h1 .venv/bin/python attack_simulation/tcp-syn-flood-generator.py