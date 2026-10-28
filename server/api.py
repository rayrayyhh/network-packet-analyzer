import os
import time
import json
import tempfile
import threading
import hmac
import math
from collections import Counter
from functools import lru_cache

from flask import Flask, jsonify, request, send_from_directory
from .packet_analyser import analyse_pcap

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, "samples")
WEB = os.path.join(ROOT, "frontend", "dist")
CAPTURES = (
    "mixed-traffic-1.pcap",
    "mixed-traffic-2.pcap",
    "mixed-traffic-3.pcap",
    "port-scan.pcap",
    "tcp-syn-flood.pcap",
    "sample-packets.pcap",
)

LIVE_TOKEN = os.environ.get("PACKETSENSE_LIVE_TOKEN", "")
LIVE_TIMEOUT_SECONDS = 5
live_lock = threading.Lock()
live_data = None
live_updated = 0.0


def capture_names():
    return [name for name in CAPTURES if os.path.isfile(os.path.join(PUBLIC, name))]


@lru_cache(maxsize=16)
def cached_analysis(path, modified_ns):
    return analyse_pcap(path)


def detect_saved_alerts(analysis, filename):
    results = []
    flags = analysis.get("tcp_flags", {})
    syn = flags.get("syn", 0)
    syn_ack = flags.get("syn_ack", 0)
    if syn >= 100 and syn_ack / max(syn, 1) < 0.2:
        results.append({
            "type": "Potential SYN Flood", "severity": "High",
            "description": "{} SYN packets and {} SYN-ACK packets in {}".format(
                syn, syn_ack, filename
            ),
        })
    for source, port_count in analysis.get(
        "unique_destination_ports_per_source", {}
    ).items():
        if port_count >= 8:
            results.append({
                "type": "Possible Port Scan",
                "severity": "High" if port_count >= 20 else "Medium",
                "source": source,
                "description": "{} contacted {} different destination ports in {}".format(
                    source, port_count, filename
                ),
            })
    return results


def saved_dashboard():
    total_packets = 0
    total_bytes = 0
    protocols = Counter()
    hosts = set()
    alerts = []
    names = capture_names()

    for name in names:
        path = os.path.join(PUBLIC, name)
        result = cached_analysis(path, os.stat(path).st_mtime_ns)
        total_packets += result.get("total_packets", 0)
        total_bytes += result.get("total_bytes", 0)
        protocols.update(result.get("protocols", {}))
        hosts.update(result.get("source_ips", {}).keys())
        hosts.update(result.get("destination_ips", {}).keys())
        alerts.extend(detect_saved_alerts(result, name))

    return {
        "mode": "saved", "capture_files": names,
        "missing_capture_files": [n for n in CAPTURES if n not in names],
        "total_packets": total_packets, "total_bytes": total_bytes,
        "packet_rate": 0, "byte_rate": 0,
        "active_hosts": sorted(hosts), "active_host_count": len(hosts),
        "protocols": dict(protocols), "alerts": alerts,
        "alert_count": len(alerts),
    }


def live_dashboard():
    with live_lock:
        data = dict(live_data) if live_data is not None else None
        updated = live_updated

    freshness = (
        "waiting" if data is None
        else "online" if time.time() - updated < LIVE_TIMEOUT_SECONDS
        else "stale"
    )
    if freshness != "online":
        return {
            "mode": "live", "live_status": freshness,
            "total_packets": 0, "total_bytes": 0,
            "packet_rate": 0, "byte_rate": 0,
            "active_hosts": [], "active_host_count": 0,
            "protocols": {}, "alerts": [], "alert_count": 0,
        }

    data.pop("recent_packets", None)
    data["alerts"] = [
        alert for alert in data.get("alerts", []) if isinstance(alert, dict)
    ]
    data["mode"] = "live"
    data["live_status"] = "online"
    data["active_host_count"] = len(data.get("active_hosts", []))
    data["alert_count"] = len(data.get("alerts", []))
    return data


@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({"status": "online", "service": "PacketSense API"})


@app.route("/")
def index():
    if not os.path.isfile(os.path.join(WEB, "index.html")):
        return jsonify({"error": "Dashboard build missing. Run npm ci and npm run build in frontend/."}), 503
    return send_from_directory(WEB, "index.html")


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(WEB, "assets"), filename)


@app.route("/favicon.svg")
def favicon():
    return send_from_directory(WEB, "favicon.svg")


@app.route("/captures/<filename>")
def capture_file(filename):
    if filename not in CAPTURES:
        return jsonify({"error": "Unknown capture"}), 404
    return send_from_directory(PUBLIC, filename)


@app.route("/api/captures", methods=["GET"])
def captures():
    return jsonify({"captures": capture_names()})


@app.route("/api/live-update", methods=["POST"])
def receive_live_update():
    global live_data, live_updated

    if not LIVE_TOKEN:
        return jsonify({"error": "PACKETSENSE_LIVE_TOKEN is not set"}), 503
    if not hmac.compare_digest(request.headers.get("X-PacketSense-Token", "").encode(), LIVE_TOKEN.encode()):
        return jsonify({"error": "Unauthorised"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400
    count = data.get("total_packets")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return jsonify({"error": "Invalid total_packets"}), 400
    if not isinstance(data.get("active_hosts", []), list):
        return jsonify({"error": "Invalid active_hosts"}), 400
    if not isinstance(data.get("alerts", []), list):
        return jsonify({"error": "Invalid alerts"}), 400
    if not isinstance(data.get("protocols", {}), dict):
        return jsonify({"error": "Invalid protocols"}), 400
    preview = data.get("recent_packets", [])
    if not isinstance(preview, list) or len(preview) > 200:
        return jsonify({"error": "Invalid recent_packets (maximum 200)"}), 400
    if any(not isinstance(item, dict) for item in preview):
        return jsonify({"error": "Invalid recent packet"}), 400

    for field in ("total_bytes", "packet_rate", "byte_rate"):
        value = data.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            return jsonify({"error": "Invalid " + field}), 400
    if len(data.get("active_hosts", [])) > 1000 or any(not isinstance(host, str) for host in data.get("active_hosts", [])):
        return jsonify({"error": "Invalid active_hosts"}), 400
    if len(data.get("alerts", [])) > 30 or any(not isinstance(alert, dict) for alert in data.get("alerts", [])):
        return jsonify({"error": "Invalid alerts"}), 400
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0
           for value in data.get("protocols", {}).values()):
        return jsonify({"error": "Invalid protocol counts"}), 400

    with live_lock:
        live_data = data
        live_updated = time.time()

    return jsonify({"status": "updated"})


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    mode = request.args.get("mode", "auto").lower()
    if mode not in ("live", "saved", "auto"):
        return jsonify({"error": "mode must be live, saved, or auto"}), 400

    live = live_dashboard()
    if mode == "live":
        return jsonify(live)

    if mode == "auto" and live["live_status"] == "online":
        return jsonify(live)

    try:
        data = saved_dashboard()
        data["live_status"] = live["live_status"]
        return jsonify(data)
    except Exception as error:
        app.logger.exception("Saved capture analysis failed")
        return jsonify({"error": str(error)}), 500



@app.route("/api/live/packets", methods=["GET"])
def live_packets():
    """Recent live packet metadata for the Server Traffic page."""
    try:
        limit = int(request.args.get("limit", "200"))
    except ValueError:
        return jsonify({"error": "limit must be a number"}), 400
    if limit < 1 or limit > 200:
        return jsonify({"error": "limit must be between 1 and 200"}), 400

    with live_lock:
        snapshot = dict(live_data) if live_data is not None else None
        updated = live_updated

    status = (
        "waiting" if snapshot is None
        else "online" if time.time() - updated < LIVE_TIMEOUT_SECONDS
        else "stale"
    )
    if status != "online":
        return jsonify({
            "mode": "live", "live_status": status,
            "total_packets": 0, "packets": [], "preview_limit": 200,
        })
    preview = snapshot.get("recent_packets", [])
    return jsonify({
        "mode": "live", "live_status": "online",
        "total_packets": snapshot.get("total_packets", 0),
        "packets": preview[-limit:], "preview_limit": 200,
    })

def send_to_ollama(payload):
    """Support both current dict-based and older file-based Ollama helpers."""
    from . import ollama_analyser

    if hasattr(ollama_analyser, "analyse_data_with_ollama"):
        return ollama_analyser.analyse_data_with_ollama(payload)

    if hasattr(ollama_analyser, "analyse_with_ollama"):
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", encoding="utf-8", delete=False
            ) as temporary_file:
                json.dump(payload, temporary_file)
                temporary_path = temporary_file.name
            try:
                return ollama_analyser.analyse_with_ollama(temporary_path)
            except SystemExit:
                raise RuntimeError("Ollama analysis failed; check Ollama is running")
        finally:
            if temporary_path and os.path.isfile(temporary_path):
                os.unlink(temporary_path)

    raise RuntimeError("ollama_analyser.py needs an Ollama analysis function")


@app.route("/api/analyse", methods=["POST"])
def analyse():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    filename = body.get("capture_file")
    if filename not in CAPTURES:
        return jsonify({"error": "Select a valid capture file"}), 400

    path = os.path.join(PUBLIC, filename)
    if not os.path.isfile(path):
        return jsonify({"error": "Capture file not found: " + filename}), 404

    try:
        analysis = cached_analysis(path, os.stat(path).st_mtime_ns)
        payload = {
            "task": "Analyse the captured network traffic for anomalies.",
            "network_analysis": analysis,
            "user_question": str(body.get("question", "")),
        }
        answer = send_to_ollama(payload)
        return jsonify({
            "capture_file": filename, "analysis": analysis, "answer": answer,
        })
    except Exception as error:
        app.logger.exception("Ollama analysis failed")
        return jsonify({"error": str(error)}), 500


@app.route("/api/live/ask", methods=["POST"])
def ask_live_question():
    """Answer a user's question using a bounded snapshot of current live Mininet data."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    question = body.get("question", "")
    if not isinstance(question, str) or not question.strip():
        return jsonify({"error": "Please enter a question"}), 400
    question = question.strip()
    if len(question) > 2000:
        return jsonify({"error": "Question is too long (maximum 2000 characters)"}), 400

    with live_lock:
        snapshot = dict(live_data) if live_data is not None else None
        last_update = live_updated

    if snapshot is None or time.time() - last_update >= LIVE_TIMEOUT_SECONDS:
        return jsonify({
            "error": "No current Mininet data. Start live_monitor.py, then try again."
        }), 503

    requested_alert = body.get("selected_alert")
    focused_alert = None
    all_alerts = [a for a in snapshot.get("alerts", []) if isinstance(a, dict)]
    if requested_alert is not None:
        if not isinstance(requested_alert, dict):
            return jsonify({"error": "selected_alert must be an object"}), 400
        identity_fields = ("type", "source", "destination", "port", "first_seen")
        focused_alert = next(
            (
                alert for alert in all_alerts
                if all(
                    str(alert.get(key)) == str(requested_alert.get(key))
                    for key in identity_fields
                )
            ),
            None,
        )
        if focused_alert is None:
            return jsonify({
                "error": (
                    "The selected alert is no longer in the live monitor's alert history. "
                    "Generate the test traffic again, or clear the selected alert "
                    "to ask about current traffic generally."
                )
            }), 409

    alerts = ([focused_alert] if focused_alert else []) + [
        a for a in all_alerts if a is not focused_alert
    ][:15 if focused_alert is None else 14]
    recent_packets = [p for p in snapshot.get("recent_packets", []) if isinstance(p, dict)][-30:]
    analysis = {
        "source": "Live Mininet monitoring",
        "total_packets_since_monitor_start": snapshot.get("total_packets", 0),
        "total_bytes_since_monitor_start": snapshot.get("total_bytes", 0),
        "current_packets_per_second": snapshot.get("packet_rate", 0),
        "current_bytes_per_second": snapshot.get("byte_rate", 0),
        "protocols": snapshot.get("protocols", {}),
        "active_hosts": snapshot.get("active_hosts", []),
        "preliminary_security_alerts": alerts,
        "focused_alert": focused_alert,
        "recent_packet_metadata_sample": recent_packets,
        "data_limitations": (
            "A current snapshot, not the full traffic history. "
            "Only the 30 most recent packet metadata records and up to 15 "
            "active preliminary alerts are supplied. Do not treat unobserved "
            "activity as absent or provisional alerts as confirmed attacks."
        ),
    }
    payload = {
        "task": (
            "Answer the user's question about live Mininet network traffic. "
            "If focused_alert is provided, analyse THAT alert specifically "
            "in the required structured report, using its verified evidence. "
            "Other alerts are context, not the focus. "
            "Use only the supplied snapshot. Explain uncertainty, avoid "
            "invented packet counts and do not perform automatic containment."
        ),
        "network_analysis": analysis,
        "user_question": question,
    }

    try:
        answer = send_to_ollama(payload)
        return jsonify({"mode": "live", "answer": answer})
    except Exception as error:
        app.logger.exception("Live Mininet Q&A failed")
        return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    print("PacketSense API listening on port 5001")
    print("PCAP folder:", PUBLIC)
    print("Available captures:", capture_names())
    print("Live updates configured:", bool(LIVE_TOKEN))
    print("Ollama analysis: manual questions only")
    app.run(host=os.environ.get("PACKETSENSE_BIND", "127.0.0.1"),
            port=int(os.environ.get("PACKETSENSE_PORT", "5001")),
            debug=False, use_reloader=False)
