import json
import urllib.request
import urllib.error
import sys

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

    # Provisional port-scan indicator
    for source_ip, port_count in ports_per_source.items():
        if port_count >= 20:
            findings.append({
                "type": "potential_port_scan",
                "source_ip": source_ip,
                "observed_unique_destination_ports": port_count,
                "threshold_unique_destination_ports": 20,
                "evidence": (
                    f"Source {source_ip} contacted "
                    f"{port_count} unique destination ports, "
                    "meeting the provisional 20-port screening threshold."
                )
            })

    # Provisional SYN-flood indicator
    if syn >= 100 and syn_ack / max(syn, 1) < 0.2:
        findings.append({
            "type": "potential_syn_flood",
            "evidence": (
                f"Observed {syn} SYN packets and "
                f"{syn_ack} SYN-ACK packets."
            )
        })

    return findings

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
                    "content": (
                        "You are a network security detection assistant. "
                        "Analyse only the supplied network statistics and "
                        "preliminary Python detection findings. "
                        
                        "The preliminary findings are indicators, not confirmed attacks. "
                        "Explain whether the evidence supports potential suspicious activity. "
                        
                        "Pay particular attention to the unique destination ports "
                        "contacted by each source IP. "
                        "A source contacting many destination ports may indicate scanning. "
                        
                        "A SYN flood generally involves a high volume of SYN requests "
                        "targeting a service, often without completed handshakes. "
                        
                        "Interpret numerical values accurately. "
                        "A SYN-ACK to SYN ratio near 1 means the aggregate counts "
                        "are similar, not that responses are missing. "
                        "Do not treat aggregate counts as matched TCP handshakes. "
                        
                        "Do not invent statistics or assume an attack is confirmed. "
                        "If evidence is insufficient, explicitly state the uncertainty. "

                        "Only reference detection thresholds explicitly supplied "
                        "in the preliminary detection findings. "
                        "Do not invent numerical thresholds or compare unrelated metrics. "
                        "Unique destination ports and packets per second are different "
                        "measurements and must not be confused. "
                        "Quote numerical evidence exactly as supplied. "
                        
                        "Use this exact output format: "
                        "Classification: NORMAL, SUSPICIOUS, or INSUFFICIENT_EVIDENCE. "
                        "Potential attack: attack type or unknown. "
                        "Evidence: relevant statistics and preliminary findings. "
                        "Reasoning: explain the conclusion using the supplied evidence. "

                        "After the reasoning, include a section titled "
                        "'RECOMMENDED COURSE OF ACTION'. "

                        "Provide a safe, defensive and non-destructive recommendation "
                        "for the user. The recommendation must be based only on the "
                        "supplied evidence and must use cautious language when the "
                        "evidence is incomplete. "

                        "Use this decision logic: "
                        "If the evidence suggests potential port scanning, recommend "
                        "verifying whether the source is an authorised scanner, reviewing "
                        "the affected destination ports and monitoring the source. "
                        "If the source is not authorised or the scanning continues, "
                        "recommend a temporary monitored block or rate limit only in the "
                        "simulated environment and only after human approval. "

                        "If the evidence suggests possible SYN-flood behaviour, recommend "
                        "checking connection-state evidence, monitoring service availability, "
                        "applying a temporary rate limit or SYN-protection control in the "
                        "simulated environment after human approval, and preserving the "
                        "PCAP and logs for investigation. "

                        "If evidence is incomplete or ambiguous, recommend collecting more "
                        "traffic and escalating the event for review rather than claiming "
                        "that an attack is confirmed. "

                        "Never provide shell commands, iptables commands, tc commands, "
                        "or instructions to attack a system. "
                        "Always state that human approval is required before a network "
                        "control action is applied."
                        
                        "Do not recommend executing network changes automatically."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": False
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

        # The VM terminal may use latin-1. Print an ASCII-safe copy
        # so Unicode characters from Qwen3 cannot crash the terminal.
        safe_answer = answer.encode("ascii", errors="replace").decode("ascii")
        print(safe_answer)

        print("=" * 60)

        # Always save the original Qwen3 response as UTF-8.
        with open("llm_analysis.txt", "w", encoding="utf-8") as output_file:
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
