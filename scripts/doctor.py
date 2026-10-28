"""Read-only prerequisites check; works without starting or cleaning a network."""
import argparse
import importlib
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(saved=False):
    checks = [("Python 3.8+", sys.version_info >= (3, 8))]
    for name in ("flask", "scapy") + (() if saved else ("mininet.net",)):
        try:
            importlib.import_module(name)
            ok = True
        except ImportError:
            ok = False
        checks.append((name, ok))
    checks.append(("dashboard build", (ROOT / "frontend/dist/index.html").is_file()))
    checks.append(("sample captures", len(list((ROOT / "samples").glob("*.pcap"))) == 6))
    if not saved:
        checks.extend((command, shutil.which(command) is not None)
                      for command in ("tcpdump", "ovs-vsctl", "mnexec", "sudo"))
    for label, ok in checks:
        print("[{}] {}".format("OK" if ok else "MISSING", label))
    return all(ok for _, ok in checks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--saved", action="store_true", help="Skip live Mininet prerequisites")
    sys.exit(0 if check(parser.parse_args().saved) else 1)
