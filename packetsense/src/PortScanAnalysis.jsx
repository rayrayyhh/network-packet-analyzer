import { useEffect, useMemo, useState } from "react";
import { parsePcap } from "./ServerTraffic";

const CAPTURES = [
    { file: "mixed-traffic-1.pcap", label: "Mixed Traffic 1" },
    { file: "mixed-traffic-2.pcap", label: "Mixed Traffic 2" },
    { file: "mixed-traffic-3.pcap", label: "Mixed Traffic 3" },
    { file: "port-scan.pcap", label: "Port Scan" },
];

function PortScanAnalysis({ onNavigate }) {
    const [mode, setMode] = useState("live");
    const [selectedCapture, setSelectedCapture] = useState(CAPTURES[0].file);
    const [packets, setPackets] = useState([]);
    const [liveAlerts, setLiveAlerts] = useState([]);
    const [liveTotal, setLiveTotal] = useState(0);
    const [liveStatus, setLiveStatus] = useState("waiting");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const controller = new AbortController();
        let timer;
        let inFlight = false;
        setPackets([]);
        setLiveAlerts([]);
        setLiveTotal(0);
        setLiveStatus("waiting");
        setLoading(true);
        setError("");

        async function load() {
            if (inFlight) return;
            inFlight = true;
            try {
                if (mode === "live") {
                    const response = await fetch(
                        "http://127.0.0.1:5001/api/dashboard?mode=live",
                        { cache: "no-store", signal: controller.signal }
                    );
                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || "Cannot retrieve live detections.");
                    if (controller.signal.aborted) return;
                    setLiveStatus(data.live_status || "waiting");
                    setLiveTotal(Number(data.total_packets) || 0);
                    setLiveAlerts(Array.isArray(data.alerts) ? data.alerts : []);
                } else {
                    const response = await fetch(`/${encodeURIComponent(selectedCapture)}`, {
                        signal: controller.signal, cache: "no-store",
                    });
                    if (!response.ok) throw new Error(`Cannot load ${selectedCapture}; check the public folder.`);
                    const buffer = await response.arrayBuffer();
                    const result = parsePcap(buffer, selectedCapture);
                    if (controller.signal.aborted) return;
                    setPackets(result);
                }
                setError("");
            } catch (err) {
                if (!controller.signal.aborted) {
                    setError(err.message || "Analysis failed.");
                    if (mode === "live") {
                        setLiveStatus("offline");
                        setLiveAlerts([]);
                        setLiveTotal(0);
                    }
                }
            } finally {
                inFlight = false;
                if (!controller.signal.aborted) setLoading(false);
            }
        }

        load();
        if (mode === "live") timer = setInterval(load, 1000);
        return () => {
            controller.abort();
            if (timer) clearInterval(timer);
        };
    }, [mode, selectedCapture]);

    const savedDetections = useMemo(() => analyseTraffic(packets), [packets]);
    const detections = mode === "live"
        ? liveAlerts.map((alert) => ({
            type: alert.type || "Network Activity",
            source: alert.source || "-",
            target: alert.destination || "-",
            synCount: Number(alert.syn_count) || 0,
            ports: Array.isArray(alert.ports) ? alert.ports :
                (alert.port != null ? [alert.port] : []),
            portCount: Number(alert.port_count) ||
                (Array.isArray(alert.ports) ? alert.ports.length : (alert.port != null ? 1 : 0)),
            severity: alert.severity || "Medium",
            description: alert.description || "",
            lastSeen: alert.last_seen || "",
        }))
        : savedDetections;

    const capturedCount = mode === "live"
        ? liveTotal
        : packets.filter((packet) => packet.ipVersion === 4).length;

    const synCount = mode === "live"
        ? null 
        : packets.filter((packet) => packet.protocol === "TCP" && packet.syn && !packet.ack).length;

    const suspiciousSources = new Set(detections.map((alert) => alert.source)).size;
    const waiting = mode === "live" && liveStatus !== "online";

    return (
        <div className="w-full">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-800">Port Scan Analysis</h1>
                <p className="mt-2 text-gray-500"></p>
            </div>

            <div className="mb-6 rounded-xl border border-gray-200 bg-white p-5">
                <label htmlFor="portscan-mode" className="mb-2 block text-sm font-medium text-gray-700">Analysis Mode</label>
                <select
                    id="portscan-mode"
                    value={mode}
                    onChange={(event) => setMode(event.target.value)}
                    className="w-full rounded-lg border border-gray-200 bg-white px-4 py-3 outline-none focus:border-blue-500 md:w-80"
                >
                    <option value="live">Live Mininet</option>
                    <option value="saved">Saved PCAP Files</option>
                </select>
                {mode === "saved" && (
                    <div className="mt-4">
                        <label htmlFor="portscan-capture" className="mb-2 block text-sm font-medium text-gray-700">Capture File</label>
                        <select
                            id="portscan-capture"
                            value={selectedCapture}
                            onChange={(event) => setSelectedCapture(event.target.value)}
                            className="w-full rounded-lg border border-gray-200 bg-white px-4 py-3 outline-none focus:border-blue-500 md:w-80"
                        >
                            {CAPTURES.map((capture) => (
                                <option key={capture.file} value={capture.file}>{capture.label}</option>
                            ))}
                        </select>
                    </div>
                )}
            </div>

            {waiting && !error && (
                <div className="mb-5 rounded-lg bg-yellow-50 p-4 text-sm text-yellow-800">
                    {liveStatus === "stale"
                        ? "Live updates stopped. Check live_monitor.py in Ubuntu."
                        : "Waiting for live Mininet updates. Start live_monitor.py in Ubuntu."}
                </div>
            )}
            {error && <div className="mb-5 rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>}

            <div className="grid grid-cols-1 gap-5 md:grid-cols-4">
                <StatCard title={mode === "live" ? "Live Packets Captured" : "IPv4 Packets Analysed"} value={capturedCount} />
                <StatCard title={mode === "live" ? "Detection Window" : "TCP SYN Packets"} value={mode === "live" ? "Live" : synCount} />
                <StatCard title="Detections" value={detections.length} />
                <StatCard title="Suspicious Sources" value={suspiciousSources} />
            </div>

            <div className="mt-6 overflow-hidden rounded-xl border border-gray-200 bg-white">
                <div className="flex items-center justify-between gap-3 border-b border-gray-200 p-5">
                    <div>
                        <h2 className="text-lg font-semibold text-gray-800">
                            Traffic Analysis
                        </h2>
                        <p className="mt-1 text-sm text-gray-500">
                            {mode === "live" ? "Automatic threat detections" : `Results from ${selectedCapture}`}
                        </p>
                    </div>
                    <span className="text-sm text-gray-500">
                        {loading ? "Analysing..." : waiting ? "Waiting" : error ? "Error" : "Analysis Complete"}
                    </span>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-gray-50 text-sm text-gray-500">
                            <tr>
                                <th className="px-5 py-3">Detection</th>
                                <th className="px-5 py-3">Source</th>
                                <th className="px-5 py-3">Target</th>
                                <th className="px-5 py-3">SYN Packets</th>
                                <th className="px-5 py-3">Unique Ports</th>
                                <th className="px-5 py-3">Ports</th>
                                <th className="px-5 py-3">Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && <StatusRow text="Analysing traffic..." />}
                            {!loading && !error && detections.length === 0 && (
                                <StatusRow text={waiting ? "Waiting for live updates." : "No traffic matched the current detection thresholds."} />
                            )}
                            {!loading && !error && detections.map((item, index) => (
                                <tr
                                    key={`${item.type}-${item.source}-${item.target}-${index}`}
                                    onClick={() => onNavigate?.("Analytics")}
                                    onKeyDown={(event) => {
                                        if (event.key === "Enter" || event.key === " ") {
                                            event.preventDefault();
                                            onNavigate?.("Analytics");
                                        }
                                    }}
                                    role="button"
                                    tabIndex={0}
                                    title="Open this detection in Network Monitoring Assistant"
                                    aria-label={`Open Network Monitoring Assistant for ${item.type} from ${item.source} to ${item.target}`}
                                    className="cursor-pointer border-t border-gray-100 text-sm transition-colors hover:bg-blue-50 focus-visible:bg-blue-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500"
                                >
                                    <td className="px-5 py-4 font-medium text-gray-800">
                                        {item.type}
                                        {item.lastSeen && (
                                            <p className="mt-1 text-xs font-normal text-gray-500">
                                                Last detected {new Date(item.lastSeen).toLocaleTimeString()}
                                            </p>
                                        )}
                                    </td>
                                    <td className="px-5 py-4 text-gray-700">{item.source}</td>
                                    <td className="px-5 py-4 text-gray-700">{item.target}</td>
                                    <td className="px-5 py-4 text-gray-700">{Number(item.synCount).toLocaleString()}</td>
                                    <td className="px-5 py-4 text-gray-700">{item.portCount ?? item.ports.length}</td>
                                    <td className="px-5 py-4 text-gray-700">{item.ports.length ? item.ports.join(", ") : "-"}</td>
                                    <td className="px-5 py-4"><SeverityBadge severity={item.severity} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>


        </div>
    );
}

function StatCard({ title, value }) {
    return (
        <div className="rounded-xl border border-gray-200 bg-white p-5">
            <p className="text-sm text-gray-500">{title}</p>
            <h2 className="mt-2 break-words text-2xl font-bold text-gray-800">
                {typeof value === "number" ? value.toLocaleString() : value}
            </h2>
        </div>
    );
}

function StatusRow({ text }) {
    return <tr><td colSpan={7} className="px-5 py-10 text-center text-gray-400">{text}</td></tr>;
}

function SeverityBadge({ severity }) {
    return (
        <span className={`rounded-md px-2 py-1 text-sm font-medium ${severity === "High" ? "bg-red-50 text-red-600" : "bg-yellow-50 text-yellow-700"}`}>
            {severity}
        </span>
    );
}

function analyseTraffic(packets) {
    const groups = new Map();

    for (const packet of packets) {
        if (packet.protocol !== "TCP" || !packet.syn || packet.ack || packet.destinationPort === "-") continue;

        const key = `${packet.source}->${packet.destination}`;
        if (!groups.has(key)) {
            groups.set(key, {
                source: packet.source,
                target: packet.destination,
                synCount: 0,
                ports: new Set(),
                synByPort: new Map(),
            });
        }

        const group = groups.get(key);
        const port = packet.destinationPort;
        group.synCount++;
        group.ports.add(port);
        group.synByPort.set(port, (group.synByPort.get(port) || 0) + 1);
    }

    const detections = [];
    for (const group of groups.values()) {
        const ports = [...group.ports].sort((a, b) => a - b);
        if (ports.length >= 8) {
            detections.push({
                type: "Possible Port Scan",
                source: group.source,
                target: group.target,
                synCount: group.synCount,
                ports,
                severity: ports.length >= 20 ? "High" : "Medium",
            });
        }
        for (const [port, count] of group.synByPort.entries()) {
            if (count >= 100) {
                detections.push({
                    type: "High TCP SYN Activity",
                    source: group.source,
                    target: group.target,
                    synCount: count,
                    ports: [port],
                    severity: "Medium",
                });
            }
        }
    }
    return detections;
}


export default PortScanAnalysis;
