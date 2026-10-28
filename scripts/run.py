"""Start the unprivileged web API and a privileged, isolated Mininet lab."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.doctor import check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saved", action="store_true", help="Dashboard and saved PCAPs only; no sudo")
    parser.add_argument("--host", default=os.environ.get("PACKETSENSE_BIND", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PACKETSENSE_PORT", "5001")))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if os.geteuid() == 0:
        parser.error("Run as your normal user. Only the Mininet lab needs sudo.")
    if not check(args.saved):
        return 1
    if not args.saved and subprocess.call(["sudo", "-v"]) != 0:
        return 1
    # Reserve/check the listening address before launching a second application.
    with socket.socket() as probe:
        try:
            probe.bind((args.host, args.port))
        except OSError as error:
            parser.error("Cannot listen on {}:{}: {}".format(args.host, args.port, error))
    runtime = ROOT / ".runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    token_file = runtime / "live-token"
    token = secrets.token_hex(32)
    descriptor = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(token)
    env = os.environ.copy()
    env.update(PACKETSENSE_LIVE_TOKEN=token, PACKETSENSE_BIND=args.host,
               PACKETSENSE_PORT=str(args.port), PYTHONUNBUFFERED="1")
    api = None
    lab = None
    # Keep the supervisor alive on TERM so its finally block reaps both children.
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with (runtime / "api.log").open("w") as log:
            api = subprocess.Popen([sys.executable, "-m", "server.api"], cwd=str(ROOT),
                                   env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
            local_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
            base = "http://{}:{}".format(local_host, args.port)
            for _ in range(100):
                if api.poll() is not None:
                    raise RuntimeError("API exited; see .runtime/api.log")
                try:
                    with urllib.request.urlopen(base + "/api/status", timeout=0.5) as response:
                        if json.load(response).get("service") == "PacketSense API":
                            break
                except (OSError, ValueError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("API did not become ready; see .runtime/api.log")
            print("\nDashboard: {}".format(base), flush=True)
            if args.host == "0.0.0.0":
                print("From your computer: http://<VM-IP>:{} (find VM-IP with hostname -I)".format(args.port), flush=True)
            print("Logs: .runtime/ | Stop with Ctrl+C or 'exit' in Mininet.\n", flush=True)
            if args.saved:
                return api.wait()
            lab = subprocess.Popen(["sudo", sys.executable, str(ROOT / "main.py"),
                                    "--monitor", "--server", base,
                                    "--token-file", str(token_file)], cwd=str(ROOT))
            while lab.poll() is None:
                if api.poll() is not None:
                    raise RuntimeError("API stopped; see .runtime/api.log")
                time.sleep(0.25)
            return lab.returncode
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError) as error:
        print("PacketSense: {}".format(error), file=sys.stderr)
        return 1
    finally:
        if lab is not None and lab.poll() is None:
            # sudo forwards TERM to its child, which stops only this lab's processes.
            lab.terminate()
            try:
                lab.wait(timeout=15)
            except subprocess.TimeoutExpired:
                print("Mininet did not exit in time; inspect processes before using sudo mn -c.", file=sys.stderr)
        if api is not None and api.poll() is None:
            api.terminate()
            try:
                api.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api.kill()
                api.wait()
        token_file.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
