#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${EUID} -eq 0 ]]; then
  echo "Run bash setup.sh as your normal VM user; it asks for sudo when needed." >&2
  exit 1
fi
if ! command -v apt-get >/dev/null; then
  echo "This setup targets the official Ubuntu Mininet VM. See docs/DEVELOPMENT.md for other systems." >&2
  exit 1
fi
sudo apt-get update
sudo apt-get install -y python3-venv tcpdump openvswitch-switch
# Keep access to Mininet installed by the official VM, without changing system Python.
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
if ! .venv/bin/python -c 'from mininet.net import Mininet'; then
  echo "Python 3 Mininet is missing. Use the official Mininet 2.3.0 Focal VM (see README)." >&2
  exit 1
fi
sudo systemctl start openvswitch-switch
.venv/bin/python scripts/doctor.py
printf '\nSetup complete. Start PacketSense with: bash run.sh\n'
