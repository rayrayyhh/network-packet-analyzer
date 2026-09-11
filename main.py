import os
import shlex

from mininet.cli import CLI
from mininet.log import setLogLevel, info

from topology import create_network


def main():
    setLogLevel("info")

    net, h1, h2, h3 = create_network()

    try:
        net.start()

        info("*** Network started\n")

        info("*** Testing connectivity\n")
        net.pingAll()


        info("*** Starting server on h3\n")

        h3.cmd(
            "python3 -m http.server 8000 "
            "--bind 10.0.0.3 "
            "> /tmp/h3-server.log 2>&1 &"
        )

        current_directory = os.path.dirname(
            os.path.abspath(__file__)
        )

        traffic_script = os.path.join(
            current_directory,
            "GenericNetworkTraffic1.py"
        )

        traffic_script = shlex.quote(traffic_script)


        info("*** Starting continuous traffic from h1\n")

        h1.cmd(
            f"python3 -u {traffic_script} "
            "--source-ip 10.0.0.1 "
            "--source-name h1 "
            "--target-ip 10.0.0.3 "
            "> /tmp/h1-traffic.log 2>&1 &"
        )

        info("*** Starting continuous traffic from h2\n")

        h2.cmd(
            f"python3 -u {traffic_script} "
            "--source-ip 10.0.0.2 "
            "--source-name h2 "
            "--target-ip 10.0.0.3 "
            "> /tmp/h2-traffic.log 2>&1 &"
        )

        info("*** Traffic generators started\n")
        info("*** h1 and h2 are clients\n")
        info("*** h3 is the server\n")
        info("*** Entering Mininet CLI\n")

        CLI(net)

    finally:
        info("*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    main()