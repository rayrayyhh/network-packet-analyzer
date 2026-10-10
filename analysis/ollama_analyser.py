import json
import sys
import urllib.error
import urllib.request


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:latest"


def detect_suspicious_patterns(llm_input):
    analysis = llm_input.get("network_analysis", {})
    flags = analysis.get("tcp_flags", {})
    ports_per_source = analysis.get(
        "unique_destination_ports_per_source", {}
    )

    syn = flags.get("syn", 0)
    syn_ack = flags.get("syn_ack", 0)

    findings = []

    for source_ip, port_count in ports_per_source.items():
        if port_count >= 20:
            findings.append({
                "type": "potential_port_scan",
                "source_ip": source_ip,
                "observed_unique_destination_ports": port_count,
                "threshold_unique_destination_ports": 20,
                "evidence": (
                    f"Source {source_ip} contacted {port_count} unique "
                    "destination ports, meeting the provisional 20-port "
                    "screening threshold."
                )
            })

    if syn >= 100 and syn_ack / max(syn, 1) < 0.2:
        findings.append({
            "type": "potential_syn_flood",
            "observed_syn_packets": syn,
            "observed_syn_ack_packets": syn_ack,
            "evidence": (
                f"Observed {syn} SYN packets and {syn_ack} SYN-ACK packets."
            )
        })

    return findings


def build_system_prompt():
    return """
You are a network-security decision-support assistant operating only
in a controlled and simulated environment.

Analyse only the supplied network statistics and preliminary Python
detection findings. Preliminary findings are indicators, not confirmed
attacks. Do not invent facts, packet counts, IP addresses, ports,
thresholds, attack attribution or outcomes that are not supplied.

Interpretation rules:
- A source contacting many unique destination ports may be consistent
  with potential port scanning.
- A high SYN count with a low aggregate SYN-ACK-to-SYN ratio may warrant
  further investigation for possible SYN-flood-like behaviour.
- Aggregate TCP flag counts do not prove whether individual TCP
  handshakes completed.
- If evidence is incomplete or ambiguous, clearly state the uncertainty.
- Only reference numerical thresholds explicitly provided in the
  preliminary detection findings.

Use cautious language such as "potential", "may be consistent with",
"requires investigation", or "insufficient evidence" unless the data
explicitly confirms the event.

Use exactly this output format:

Classification: NORMAL, SUSPICIOUS, or INSUFFICIENT_EVIDENCE
Potential attack: <potential event type or unknown>
Risk level: LOW, MEDIUM, or HIGH

Evidence:
- <exact evidence item from supplied statistics>
- <exact evidence item from supplied statistics>

Reasoning:
<Brief explanation based only on the supplied evidence.>

RECOMMENDED COURSE OF ACTION:
1. <Safe defensive investigation or containment step.>
2. <Safe monitoring, verification, or evidence-preservation step.>
3. <Safe escalation or human-review step.>

Human approval required: YES

Recommendation rules:
- For potential port scanning, recommend verifying whether the source
  IP is an authorised vulnerability scanner or administrative host,
  reviewing affected destination ports, preserving PCAP/log evidence
  and monitoring the source.
- If port-scanning activity is unauthorised or continues, recommend
  requesting human approval for a temporary monitored block or rate
  limit only in the simulated environment.
- For possible SYN-flood-like behaviour, recommend reviewing
  connection-state evidence, monitoring service availability,
  preserving PCAP/log evidence and requesting human approval before
  considering a temporary rate limit or SYN-protection control in the
  simulated environment.
- For incomplete evidence, recommend collecting more traffic and
  escalating the event for analyst review.
- Never provide executable commands, shell commands, firewall commands,
  iptables commands, tc commands or offensive instructions.
- Never recommend executing a network change automatically.
""".strip()


def analyse_with_ollama(input_file):
    with open(input_file, "r", encoding="utf-8") as file:
        llm_input = json.load(file)

    findings = detect_suspicious_patterns(llm_input)

    llm_input["preliminary_detection"] = {
        "status": "REVIEW_REQUIRED" if findings else "NO_RULE_MATCH",
        "findings": findings,
        "note": (
            "These are preliminary indicators, not confirmed attacks. "
            "NO_RULE_MATCH does not prove traffic is normal."
        )
    }

    prompt = json.dumps(llm_input, indent=2)

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": build_system_prompt()
            },
            {
                "role": "user",
                "content": (
                    "Analyse the following structured network data and "
                    "follow the exact required output format.\n\n"
                    f"{prompt}"
                )
            }
        ],
        "stream": False,
        "options": {
            "temperature": 0
        }
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            response_data = response.read().decode("utf-8")

        result = json.loads(response_data)
        return result["message"]["content"]

    except urllib.error.URLError as error:
        print("Error connecting to Ollama:")
        print(error)
        sys.exit(1)

    except KeyError:
        print("Error: Unexpected response received from Ollama.")
        print(response_data)
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: Ollama returned invalid JSON.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ollama_analyser.py <llm_input.json>")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        answer = analyse_with_ollama(input_file)

        print("\n" + "=" * 60)
        print("QWEN3 NETWORK TRAFFIC ANALYSIS")
        print("=" * 60)

        safe_answer = answer.encode(
            "ascii",
            errors="replace"
        ).decode("ascii")

        print(safe_answer)
        print("=" * 60)

        with open(
            "llm_analysis.txt",
            "w",
            encoding="utf-8"
        ) as output_file:
            output_file.write(answer)

        print("\nAnalysis saved to llm_analysis.txt")

    except FileNotFoundError:
        print("Error: LLM input file not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: LLM input file is not valid JSON.")
        sys.exit(1)

    except Exception as error:
        print("Error:", error)
        sys.exit(1)