"""PacketSense's three-host lab. Usually started through bash run.sh."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", action="store_true")
    parser.add_argument("--server", default="http://127.0.0.1:5001")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--no-traffic", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Mininet requires sudo; normally use bash run.sh")
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    from network.topology import create_network

    setLogLevel("info")
    children = []
    logs = []
    net = None
    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)

    def interrupted(_signal, _frame):
        # Mininet CLI catches KeyboardInterrupt; SystemExit must reach finally.
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, interrupted)

    def start(command, name, host=None, env=None):
        log = (runtime / (name + ".log")).open("w")
        logs.append(log)
        options = dict(stdout=log, stderr=subprocess.STDOUT)
        process = host.popen(command, **options) if host else subprocess.Popen(command, env=env, **options)
        children.append(process)
        return process

    try:
        net, h1, h2, h3 = create_network()
        net.start()
        if net.pingAll() != 0:
            raise RuntimeError("Mininet connectivity failed. Check Open vSwitch; see README troubleshooting.")
        if args.monitor:
            token = args.token_file.read_text().strip() if args.token_file else os.environ.get("PACKETSENSE_LIVE_TOKEN", "")
            if not token:
                raise RuntimeError("Live token missing. Start with bash run.sh.")
            env = os.environ.copy()
            env["PACKETSENSE_LIVE_TOKEN"] = token
            monitor = start([sys.executable, "-u", str(ROOT / "network/live_monitor.py"),
                             "--interface", "s1-eth3", "--server", args.server], "monitor", env=env)
            time.sleep(0.5)
            if monitor.poll() is not None:
                raise RuntimeError("Monitor failed; see .runtime/monitor.log")
        start([sys.executable, "-m", "http.server", "8000", "--bind", "10.0.0.3",
               "--directory", str(ROOT / "samples")], "h3-server", host=h3)
        if not args.no_traffic:
            for host in (h1, h2):
                start([sys.executable, "-u", str(ROOT / "traffic_generator/normal_traffic.py"),
                       "--source-ip", host.IP(), "--source-name", host.name, "--duration", "0"],
                      host.name + "-traffic", host=host)
        time.sleep(0.5)
        if any(process.poll() is not None for process in children):
            raise RuntimeError("A lab process exited at startup; see .runtime/*.log")
        info("*** PacketSense running: h1/h2 clients -> h3 server\n")
        info("*** Controlled tests: h1 " + sys.executable + " attack_simulation/port-scan-generator.py\n")
        info("*** Type exit to stop the lab and dashboard\n")
        CLI(net)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as error:
        print("PacketSense lab: {}".format(error), file=sys.stderr)
        return 1
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
        for process in reversed(children):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if net is not None:
            net.stop()
        for log in logs:
            log.close()


if __name__ == "__main__":
    sys.exit(main())
