import json
import sys


def create_llm_input(analysis_file):
    with open(analysis_file, "r") as file:
        analysis = json.load(file)
        tcp_flags = analysis.get("tcp_flags", {})

    syn = tcp_flags.get("syn", 0)
    syn_ack = tcp_flags.get("syn_ack", 0)
    rst = tcp_flags.get("rst", 0)

    total_packets = analysis.get("total_packets", 0)
    unique_source_ports = analysis.get("unique_source_ports", 0)
    unique_destination_ports = analysis.get("unique_destination_ports", 0)

    syn_response_ratio = (
        round(syn_ack / syn, 3) if syn > 0 else None
    )

    rst_ratio = (
        round(rst / total_packets, 3) if total_packets > 0 else None
    )

    source_port_diversity = (
        round(unique_source_ports / total_packets, 3)
        if total_packets > 0 else None
    )

    destination_port_diversity = (
        round(unique_destination_ports / total_packets, 3)
        if total_packets > 0 else None
    )

    detection_features = {
        "total_packets": analysis.get("total_packets"),
        "capture_duration_seconds": analysis.get("capture_duration_seconds"),
        "packets_per_second": analysis.get("packets_per_second"),
        "protocols": analysis.get("protocols", {}),
        "protocol_percentages": analysis.get("protocol_percentages", {}),
        "source_ips": analysis.get("source_ips", {}),
        "destination_ips": analysis.get("destination_ips", {}),
        "tcp_flags": analysis.get("tcp_flags", {}),
        "unique_source_ports": analysis.get("unique_source_ports"),
        "unique_destination_ports": analysis.get("unique_destination_ports"),
        "top_source_ports": analysis.get("top_source_ports", {}),
        "top_destination_ports": analysis.get("top_destination_ports", {}),
        "unique_destination_ports_per_source": analysis.get(
            "unique_destination_ports_per_source", {}
        )
    }

    detection_features["derived_indicators"] = {
        "syn_response_ratio": syn_response_ratio,
        "rst_ratio": rst_ratio,
        "source_port_diversity": source_port_diversity,
        "destination_port_diversity": destination_port_diversity
    }

    detection_features["interpretation_guidance"] = {
    "syn_response_ratio": (
        f"The observed SYN-ACK to SYN ratio is "
        f"{syn_response_ratio:.3f}. "
        "This compares aggregate packet counts and does not "
        "prove that individual connections completed."
    ),
    "port_scanning": (
        "A source contacting many different destination ports "
        "may indicate potential port scanning. "
        "Review unique_destination_ports_per_source."
    ),
    "syn_flood": (
        "Do not conclude SYN flooding solely from high SYN "
        "or RST counts. Additional connection-level evidence "
        "is required."
    )
}

    llm_input = {
        "task": "Analyse the captured network traffic and identify any suspicious or anomalous behaviour.",
        "instructions": [
            "Review the network traffic statistics provided below.",
            "Identify unusual traffic patterns or indicators of suspicious activity.",
            "Explain the reasoning behind any identified anomaly.",
            "If no clear anomaly is present, state that the traffic appears normal.",
            "Do not invent information that is not present in the traffic data."
        ],
        "network_analysis": detection_features
    }

    return llm_input


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 llm_input.py <analysis_json>")
        sys.exit(1)

    analysis_file = sys.argv[1]

    try:
        llm_input = create_llm_input(analysis_file)

        with open("llm_input.json", "w") as output_file:
            json.dump(llm_input, output_file, indent=4)

        print(json.dumps(llm_input, indent=4))
        print("\nLLM input saved to llm_input.json")

    except FileNotFoundError:
        print("Error: Analysis file not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: The analysis file is not valid JSON.")
        sys.exit(1)

    except Exception as error:
        print("Error:", error)
        sys.exit(1)
