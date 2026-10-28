# Changes in this repair

- Replaced the multi-terminal Windows/VM setup with `setup.sh` and `run.sh`.
  The dashboard and API are served together on port 5001 inside the VM.
- Added a Python 3.8-compatible pinned environment that can import the official
  VM's preinstalled Mininet. Added prerequisite diagnostics and a saved-only mode.
- Automatically generate a private per-run token and start the live monitor on
  the correct switch port. The API runs as the normal user; Mininet uses sudo.
- Corrected the missing `GenericNetworkTraffic1.py` reference to the actual
  generator, passed the venv interpreter into host namespaces, and run background
  traffic continuously. Removed a dead TCP-data branch that targeted no service.
- Use an OVS standalone learning bridge, avoiding a separate controller dependency
  for this simple three-host LAN. All child processes are tracked and stopped on
  normal exit; no automatic global `mn -c` cleanup occurs.
- Added the missing bounded recent-packet records to live updates. Added usable
  ports/counts/timestamps and stable alert identities for focused AI questions.
  Capture shutdown terminates/reaps tcpdump, including startup failures.
- Removed hard-coded browser loopback API URLs. Added same-origin capture routes
  and development proxies. Corrected live alert timestamp rendering.
- Fixed PCAP duration conversion (Scapy timestamps are already seconds), added
  TCP flags and initial-SYN destination-port statistics for saved detection/AI,
  and exposed all six included captures consistently.
- Tightened live-update validation and use constant-time token comparison.
- Extracted the reusable browser PCAP reader, added truncated-header validation,
  and report wire length rather than captured length in the packet size column.
- Lazy-load dashboard pages to reduce the initial JavaScript bundle.
- Separated frontend, API, network, samples, docs, and tests. Removed duplicate
  capture copies and the unrelated root Recharts dependency; retained older
  analysis scripts/reports under `archive/`.

Monitoring limitations are documented in the README. Ollama remains optional;
model installation is never performed by the setup script.
