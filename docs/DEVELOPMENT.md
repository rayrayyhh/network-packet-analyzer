# Development

## Python

Python 3.8+ is supported by the application. Mininet itself is a VM/system
installation, deliberately not a PyPI dependency. The VM setup uses
`--system-site-packages` so its venv can import the VM's existing Mininet bindings.
All other runtime packages are pinned in `requirements.txt`.

For saved captures and API development without Mininet, on Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
bash run.sh --saved
```

The supervisor is POSIX-only. Windows users should use the Mininet VM.
To run just the API for development (no live monitor, loopback bind by default):

```bash
.venv/bin/python -m server.api
```

For a manually run monitor, set the same `PACKETSENSE_LIVE_TOKEN` environment
variable in the API and monitor processes. The normal launcher handles this.

## React

Node.js **22.12+** is needed only to modify/rebuild the dashboard. The bundled
Vite 8 toolchain is incompatible with Ubuntu 20.04's original Node packages.
Build on a machine with a suitable Node installation, or install a compatible
Node release in the VM yourself; VM setup does not install Node.

From the project root:

```bash
npm --prefix frontend ci
npm run dev
```

Open the Vite URL while the API runs on localhost:5001 on the same machine.
Vite proxies `/api` and `/captures` to that address. For separate machines,
use SSH port forwarding, or change the two development proxy targets in
`frontend/vite.config.js`. The release uses the API's same-origin address and
requires no frontend URL configuration.

After changing frontend code:

```bash
npm test
npm run lint
npm run build
```

The API serves `frontend/dist/`; rebuild before distributing or testing the
release UI. `dist/` is ignored in source control and must be included in a
release ZIP. All samples live in `samples/` and are served through allowlisted
`/captures/<filename>` routes; there are no duplicated public PCAP assets.

## Checks

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/doctor.py
bash -n setup.sh run.sh
```

Use `scripts/doctor.py --saved` to skip Mininet prerequisites. Python packet
unit tests deliberately disable Scapy interface/route discovery: they read and
construct packets entirely in memory, so no raw sockets or sudo are required.
They do not exercise actual Mininet network namespaces.

`archive/` preserves previous experiments, including generated reports. Those
files are historical and may contain obsolete paths or assumptions; the active
application uses only `server/`, `network/`, and `frontend/`.
