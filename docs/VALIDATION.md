# Validation — 28 October 2026

## Completed

| Check | Result |
| --- | --- |
| Python regression suite, CPython 3.8.20 | 25 passed |
| Python regression suite, CPython 3.12.14 | 25 passed |
| JavaScript PCAP-reader suite, Node 24.22.1 | 11 passed |
| React production build, Vite 8.3.0 | Passed; built assets included |
| Frontend lint, oxlint | Passed with no warnings/errors |
| Bash syntax (`bash -n setup.sh run.sh`) | Passed |
| All Python files parsed with Python 3.8 grammar | Passed |
| Read-only prerequisite checker, saved mode | Passed |
| Runtime dependency installation on Python 3.8 | Passed |

The Python tests cover all six bundled captures, duration/rate calculations,
TCP direction and flags, live packet previews, VLAN/ARP/UDP/ICMP parsing,
fragment handling, detection thresholds/expiry, token authentication, invalid
updates, waiting/stale states, focused-alert questions, serving the built page
and PCAP files, launcher port/token handling, startup failures, and child/network
cleanup including SIGTERM. Mininet and process lifecycle tests use doubles.
The API tests use Flask's in-process test client. Packet tests disable Scapy's
interface discovery, since this environment restricts raw/netlink sockets.

JavaScript tests read all six actual PCAP files and check both byte orders,
microsecond/nanosecond timestamps, wire lengths, and malformed/truncated inputs.

## Still requires the actual VM

A real Mininet lab could not be launched in this workspace: it lacks the target
VM's Mininet, Open vSwitch services, and network-namespace privileges. The setup
script's real apt/service operations were not run here. Host-to-VM connectivity,
real tcpdump streaming, and actual model inference also remain unverified.
Ollama calls were mocked; a model was not downloaded.

After extracting on the official VM, complete this smoke check:

1. Run `bash setup.sh` as the normal VM user; every prerequisite should show OK.
2. Run `bash run.sh`; wait for `mininet>` and open `http://<VM-IP>:5001` on your host.
3. Confirm live counters increase and Server Traffic shows recent records.
   Run `h1 ping -c 5 h3` if needed.
4. Run `h1 .venv/bin/python attack_simulation/port-scan-generator.py`; confirm
   a possible-scan alert and the expected source/destination ports.
5. Switch each relevant page to saved mode and open a bundled capture.
6. Type `exit`; verify the dashboard process and this lab's interfaces stop.
7. Restart with `bash run.sh --saved`; check saved captures without sudo.
8. If Ollama is configured, ask one saved-capture and one live-snapshot question.

## Upstream references

- [Official releases and recommended Focal VM](https://github.com/mininet/mininet/releases/)
- [Mininet 2.3.0 Python 3 support and VM contents](https://github.com/mininet/mininet/wiki/Mininet-2.3.0-Release-Notes)
- [Mininet installation guide](https://mininet.org/download/)
- [Scapy PCAP timestamp API](https://scapy.readthedocs.io/en/latest/api/scapy.utils.html)
