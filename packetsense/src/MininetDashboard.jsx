import { useEffect, useState } from "react";
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from "recharts";

const API = "http://127.0.0.1:5001";

const EMPTY = {
    total_packets: 0,
    total_bytes: 0,
    packet_rate: 0,
    byte_rate: 0,
    active_hosts: [],
    alerts: [],
    protocols: {},
    live_status: "waiting",
};

function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value >= 1e9) return `${(value / 1e9).toFixed(2)} GB`;
    if (value >= 1e6) return `${(value / 1e6).toFixed(2)} MB`;
    if (value >= 1e3) return `${(value / 1e3).toFixed(2)} KB`;
    return `${value} B`;
}

function hostName(ip) {
    return {
        "10.0.0.1": "h1",
        "10.0.0.2": "h2",
        "10.0.0.3": "h3",
    }[ip] || "Host";
}

function StatCard({ label, value, subtitle }) {
    return (
        <div className="rounded-xl border border-gray-200 bg-white p-5">
            <p className="text-sm text-gray-500">{label}</p>
            <h2 className="mt-2 text-2xl font-bold text-gray-800">{value}</h2>
            <p className="mt-2 text-sm text-gray-500">{subtitle}</p>
        </div>
    );
}

function MininetDashboard({ onNavigate }) {
    const [mode, setMode] = useState("live");
    const [data, setData] = useState(EMPTY);
    const [trafficData, setTrafficData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        let active = true;
        let inFlight = false;
        let interval;
        setData(EMPTY);
        setTrafficData([]);
        setLoading(true);
        setError("");

        async function load() {
            if (inFlight) return;
            inFlight = true;

            try {
                const response = await fetch(
                    `${API}/api/dashboard?mode=${mode}`,
                    { cache: "no-store" }
                );

                const result = await response.json();
                if (!response.ok) {
                    throw new Error(result.error || "Dashboard request failed");
                }
                if (!active) return;

                setData(result);
                setError("");

                if (mode === "live") {
                    setTrafficData((previous) => [
                        ...previous,
                        {
                            time: new Date().toLocaleTimeString(),
                            rate: Number(result.packet_rate) || 0,
                        },
                    ].slice(-30));
                }
            } catch (err) {
                if (active) {
                    setError(
                        `Cannot connect to PacketSense on port 5001: ${err.message}`
                    );
                }
            } finally {
                inFlight = false;
                if (active) setLoading(false);
            }
        }

        load();
        interval = setInterval(load, 1000);

        return () => {
            active = false;
            clearInterval(interval);
        };
    }, [mode]);

    const isLive = mode === "live";
    const liveStatus = data.live_status || "waiting";
    const waiting = isLive && liveStatus !== "online";
    const hosts = Array.isArray(data.active_hosts) ? data.active_hosts : [];
    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    const protocols = data.protocols || {};

    return (
        <div className="w-full">
            <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-bold text-gray-800">
                        Mininet Dashboard
                    </h1>
                    <p className="mt-2 text-gray-500">
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    <label htmlFor="dashboard-mode" className="text-sm text-gray-600">
                        Traffic Mode
                    </label>
                    <select
                        id="dashboard-mode"
                        value={mode}
                        onChange={(event) => setMode(event.target.value)}
                        className="rounded-lg border border-gray-200 bg-white px-4 py-2 text-sm outline-none focus:border-blue-500"
                    >
                        <option value="live">Live Mininet</option>
                        <option value="saved">Saved PCAP Files</option>
                    </select>
                </div>
            </div>

            {error && (
                <div className="mb-5 rounded-lg bg-red-50 p-4 text-sm text-red-700">
                    {error}
                </div>
            )}

            {!error && isLive && (
                <div className={`mb-5 rounded-lg p-4 text-sm ${
                    liveStatus === "online"
                        ? "bg-green-50 text-green-700"
                        : "bg-yellow-50 text-yellow-800"
                }`}>
                    {liveStatus === "online"
                        ? "Live Mininet Traffic — Updating Every Second."
                        : liveStatus === "stale"
                        ? "Live updates have stopped. Check the Mininet monitor in Ubuntu."
                        : "Waiting for Mininet traffic. Start live_monitor.py inside the Ubuntu VM."}
                </div>
            )}

            {loading && (
                <div className="mb-5 rounded-lg bg-blue-50 p-4 text-sm text-blue-700">
                    Loading network statistics...
                </div>
            )}

            <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
                <StatCard
                    label="Total Packets"
                    value={Number(data.total_packets || 0).toLocaleString()}
                    subtitle={isLive ? "Since live capture started" : "Across saved captures"}
                />
                <StatCard
                    label="Network Traffic"
                    value={formatBytes(data.total_bytes)}
                    subtitle="Total captured bytes"
                />
                <StatCard
                    label="Active Hosts"
                    value={hosts.length.toLocaleString()}
                    subtitle="Observed IP addresses"
                />
                <button
                    type="button"
                    onClick={() => onNavigate("Threats")}
                    aria-label="Open Port Scan Analysis from Security Alerts"
                    className="w-full rounded-xl text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                    <div className="rounded-xl transition-shadow hover:shadow-md">
                        <StatCard
                            label="Security Alerts"
                            value={alerts.length.toLocaleString()}
                            subtitle={alerts.length ? "Requires investigation" : "Click to view Port Scan Analysis"}
                        />
                    </div>
                </button>
            </div>

            <div className="mt-6 rounded-xl border border-gray-200 bg-white p-6">
                <h2 className="text-lg font-semibold text-gray-800">
                    Network Traffic
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                    {isLive
                        ? `Live packet rate: ${Number(data.packet_rate || 0).toFixed(1)} packets/second`
                        : "Saved captures do not have a live packet rate"}
                </p>

                {isLive ? (
                    <div className="mt-5 h-72 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={trafficData}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                                <XAxis dataKey="time" minTickGap={22} />
                                <YAxis allowDecimals={false} />
                                <Tooltip />
                                <Line
                                    type="monotone"
                                    dataKey="rate"
                                    stroke="#2563eb"
                                    strokeWidth={2}
                                    dot={false}
                                    isAnimationActive={false}
                                    name="Packets/sec"
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                ) : (
                    <p className="mt-5 text-sm text-gray-500">
                        Switch to Live Mininet to display a continuously updating graph.
                    </p>
                )}
            </div>

            <div className="mt-6 rounded-xl border border-gray-200 bg-white p-6">
                <h2 className="mb-5 text-lg font-semibold text-gray-800">
                    Protocol Traffic
                </h2>
                {Object.keys(protocols).length === 0 ? (
                    <p className="text-sm text-gray-500">No protocol data available.</p>
                ) : (
                    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                        {Object.entries(protocols).map(([name, count]) => (
                            <div key={name} className="rounded-lg bg-gray-50 p-4">
                                <p className="text-sm text-gray-500">{name}</p>
                                <p className="mt-1 text-xl font-semibold text-gray-800">
                                    {Number(count).toLocaleString()}
                                </p>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div className="rounded-xl border border-gray-200 bg-white p-6">
                    <h2 className="mb-5 text-lg font-semibold text-gray-800">
                        Active Hosts
                    </h2>
                    {hosts.length === 0 ? (
                        <p className="text-sm text-gray-500">No hosts observed yet.</p>
                    ) : (
                        <div className="space-y-3">
                            {hosts.map((ip) => (
                                <div
                                    key={ip}
                                    className="flex justify-between border-b border-gray-100 pb-3"
                                >
                                    <span className="font-medium text-gray-800">
                                        {hostName(ip)}
                                    </span>
                                    <span className="text-gray-500">{ip}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                <div className="rounded-xl border border-gray-200 bg-white p-6">
                    <h2 className="mb-5 text-lg font-semibold text-gray-800">
                        <button
                            type="button"
                            onClick={() => onNavigate("Threats")}
                            className="text-left hover:text-blue-600 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                        >
                            Security Alerts
                        </button>
                    </h2>
                    {alerts.length === 0 ? (
                        <p className="text-sm text-gray-500">
                            {waiting
                                ? "Waiting for live monitoring data."
                                : "No suspicious activity matched the current rules."}
                        </p>
                    ) : (
                        <div className="space-y-3">
                            {alerts.map((alert, index) => (
                                <button
                                    type="button"
                                    key={`${alert.type}-${alert.source || ""}-${index}`}
                                    onClick={() => onNavigate("Threats")}
                                    aria-label={`Open Port Scan Analysis for ${alert.type || "security alert"}`}
                                    className="block w-full rounded-lg bg-gray-50 p-4 text-left transition-colors hover:bg-blue-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                                >
                                    <div className="flex justify-between gap-3">
                                        <p className="font-medium text-gray-800">
                                            {alert.type}
                                        </p>
                                        <span className={`text-sm font-medium ${
                                            alert.severity === "High"
                                                ? "text-red-600"
                                                : "text-yellow-700"
                                        }`}>
                                            {alert.severity}
                                        </span>
                                    </div>
                                    <p className="mt-2 text-sm text-gray-600">
                                        {alert.description}
                                    </p>
                                    {alert.last_seen && (
                                        <p className="mt-2 text-xs text-gray-500">
                                            Last detected: {new Date(alert.last_seen).toLocaleString()}
                                        </p>
                                    )}
                                    {alert.source && (
                                        <p className="mt-1 text-xs text-gray-500">
                                            {alert.source}
                                            {alert.destination && ` → ${alert.destination}`}
                                            {alert.port != null && ` : ${alert.port}`}
                                        </p>
                                    )}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default MininetDashboard;
