"""PacketSense: manual Llama 3.2 analysis with integrated LLM input features.

Works with api.py calling analyse_data_with_ollama(payload) and with
file-based usage: python ollama_analyser.py llm_input.json
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")


def safe_number(value):
    """Return a numeric statistic if available; never treat missing data as zero."""
    try:
        if value is None or isinstance(value, bool):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def build_network_features(network_analysis):
    """Integrate the calculations from llm_input.py into existing analysis data.

    Keep all fields supplied by Flask, particularly focused_alert, live alerts,
    and recent packet metadata. Some calculations only apply to saved PCAPs.
    """
    analysis = dict(network_analysis)
    flags = analysis.get("tcp_flags") or {}
    if not isinstance(flags, dict):
        flags = {}

    syn = safe_number(flags.get("syn"))
    syn_ack = safe_number(flags.get("syn_ack"))
    rst = safe_number(flags.get("rst"))
    total = safe_number(analysis.get("total_packets"))
    unique_source = safe_number(analysis.get("unique_source_ports"))
    unique_destination = safe_number(analysis.get("unique_destination_ports"))

    syn_ratio = round(syn_ack / syn, 3) if syn is not None and syn > 0 and syn_ack is not None else None
    rst_ratio = round(rst / total, 3) if rst is not None and total is not None and total > 0 else None
    source_diversity = round(unique_source / total, 3) if unique_source is not None and total is not None and total > 0 else None
    destination_diversity = round(unique_destination / total, 3) if unique_destination is not None and total is not None and total > 0 else None

    derived = dict(analysis.get("derived_indicators") or {})
    derived.update({
        "syn_response_ratio": syn_ratio,
        "rst_ratio": rst_ratio,
        "source_port_diversity": source_diversity,
        "destination_port_diversity": destination_diversity,
    })
    analysis["derived_indicators"] = derived

    if syn_ratio is not None:
        syn_guidance = (
            "The observed SYN-ACK to SYN ratio is {:.3f}. "
            "This compares aggregate packet counts and does not "
            "prove that individual connections completed."
        ).format(syn_ratio)
    else:
        syn_guidance = (
            "SYN-ACK to SYN ratio is unavailable because initial SYN "
            "counts are zero or necessary TCP flag statistics are missing."
        )

    guidance = dict(analysis.get("interpretation_guidance") or {})
    guidance.update({
        "syn_response_ratio": syn_guidance,
        "port_scanning": (
            "A source contacting many different destination ports may indicate "
            "potential port scanning. Review unique_destination_ports_per_source, "
            "but verify the direction of initial SYN probes; replies to ephemeral "
            "ports can inflate aggregate counts."
        ),
        "syn_flood": (
            "Do not conclude SYN flooding solely from high SYN or RST counts. "
            "Additional connection-level, response and timing evidence is required."
        ),
    })
    analysis["interpretation_guidance"] = guidance
    return analysis


def detect_suspicious_patterns(llm_input):
    """Produce provisional indicators; never treat them as confirmed attacks."""
    analysis = llm_input.get("network_analysis") or {}
    findings = []

    focused = analysis.get("focused_alert")
    live_alerts = analysis.get("preliminary_security_alerts") or []
    if isinstance(focused, dict):
        live_alerts = [focused] + [
            alert for alert in live_alerts
            if isinstance(alert, dict) and alert != focused
        ]
    for alert in live_alerts:
        if isinstance(alert, dict):
            findings.append({
                "type": alert.get("type", "Unknown live alert"),
                "source": alert.get("source"),
                "destination": alert.get("destination"),
                "port": alert.get("port"),
                "severity": alert.get("severity"),
                "evidence": alert.get("description", "Live monitor alert"),
                "status": "PRELIMINARY",
            })

    for ip, value in (analysis.get("unique_destination_ports_per_source") or {}).items():
        count = safe_number(value)
        if count is not None and count >= 8:
            threshold = 20 if count >= 20 else 8
            findings.append({
                "type": "potential_port_scan",
                "source": ip,
                "observed_unique_destination_ports": int(count),
                "screening_threshold": threshold,
                "evidence": "Source {} had {} unique TCP destination ports in aggregate statistics.".format(ip, int(count)),
                "limitation": (
                    "Aggregate counts may include replies to ephemeral ports. "
                    "Verify the direction of initial SYN probes before attributing a scan."
                ),
                "status": "PRELIMINARY",
            })

    flags = analysis.get("tcp_flags") or {}
    syn = safe_number(flags.get("syn"))
    syn_ack = safe_number(flags.get("syn_ack"))
    if syn is not None and syn >= 100:
        few_responses = syn_ack is not None and syn_ack / syn < 0.2
        findings.append({
            "type": "potential_syn_flood" if few_responses else "high_syn_activity",
            "observed_syn_packets": int(syn),
            "observed_syn_ack_packets": int(syn_ack) if syn_ack is not None else None,
            "evidence": "Observed {} initial SYN packets{}.".format(
                int(syn),
                " and {} SYN-ACK packets".format(int(syn_ack)) if syn_ack is not None else ""
            ),
            "limitation": "Aggregate counts alone do not confirm a SYN flood or service disruption.",
            "status": "PRELIMINARY",
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


def render_report(report):
    """Render JSON from Ollama as the plain-text layout used in the chat UI."""
    if not isinstance(report, dict):
        raise ValueError("Ollama returned an unexpected analysis format")

    classification = str(report.get("classification", "INCONCLUSIVE")).upper().strip()
    if classification not in ("NORMAL", "SUSPICIOUS", "INCONCLUSIVE"):
        classification = "INCONCLUSIVE"

    risk = str(report.get("risk_level", "LOW")).upper().strip()
    if risk not in ("LOW", "MEDIUM", "HIGH"):
        risk = "LOW"

    attack = str(report.get("potential_attack") or "None").strip()
    reasoning = str(report.get("reasoning") or "Insufficient information to explain the observed traffic.").strip()

    evidence = report.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = [str(evidence)]
    evidence = [str(item).strip().lstrip("- ") for item in evidence if str(item).strip()]
    if not evidence:
        evidence = ["No specific evidence was supplied for this analysis."]

    actions = report.get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = [str(actions)]
    actions = [re.sub(r"^\s*\d+[.)]\s*", "", str(item)).strip() for item in actions]
    actions = [action for action in actions if action]
    fallbacks = [
        "Review the observed network statistics and verify whether activity is authorised.",
        "Preserve relevant PCAP and log evidence for investigation.",
        "Escalate the findings for analyst review before changing security controls.",
    ]
    for item in fallbacks:
        if len(actions) == 3:
            break
        if item not in actions:
            actions.append(item)

    approval = str(report.get("human_approval_required", "YES")).upper().strip()
    if approval not in ("YES", "NO"):
        approval = "YES"

    return "\n".join([
        "Classification: " + classification,
        "Potential attack: " + attack,
        "Risk level: " + risk,
        "",
        "Evidence:",
        *["- " + item for item in evidence],
        "",
        "Reasoning:",
        reasoning,
        "",
        "RECOMMENDED COURSE OF ACTION:",
        *["{}. {}".format(i + 1, item) for i, item in enumerate(actions[:3])],
        "",
        "Human approval required: " + approval,
    ])


def analyse_data_with_ollama(llm_input):
    """Called by Flask only after a user presses Send in Network Monitoring Assistant."""
    if not isinstance(llm_input, dict):
        raise ValueError("Expected a dictionary containing network_analysis")

    prepared = dict(llm_input)
    analysis = prepared.get("network_analysis") or {}
    if not isinstance(analysis, dict):
        raise ValueError("network_analysis must be a dictionary")
    prepared["network_analysis"] = build_network_features(analysis)

    findings = detect_suspicious_patterns(prepared)
    prepared["preliminary_detection"] = {
        "status": "REVIEW_REQUIRED" if findings else "NO_RULE_MATCH",
        "findings": findings,
        "note": (
            "Preliminary indicators do not prove an attack; "
            "no rule match does not prove traffic is safe."
        ),
    }

    request_data = {
        "model": MODEL,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": (
                "Analyse this network traffic and answer the user's question "
                "using the required JSON fields:\n" +
                json.dumps(prepared, indent=2, default=str)
            )},
        ],
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(request_data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            reply = json.load(response)
        content = reply.get("message", {}).get("content", "")
        return render_report(json.loads(content))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError("Ollama returned HTTP {}: {}".format(error.code, detail)) from error
    except urllib.error.URLError as error:
        raise RuntimeError("Cannot connect to Ollama at {}: {}".format(OLLAMA_URL, error)) from error
    except (ValueError, TypeError, KeyError) as error:
        raise RuntimeError("Ollama returned invalid structured analysis: {}".format(error)) from error


def analyse_with_ollama(input_file):
    """Keep compatibility with the original JSON-file-based Ollama workflow."""
    with open(input_file, "r", encoding="utf-8") as handle:
        return analyse_data_with_ollama(json.load(handle))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ollama_analyser.py <llm_input.json>")
        sys.exit(1)
    try:
        print(analyse_with_ollama(sys.argv[1]))
    except Exception as error:
        print("Analysis failed:", error)
        sys.exit(1)
