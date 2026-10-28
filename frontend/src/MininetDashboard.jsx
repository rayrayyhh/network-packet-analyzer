import { useEffect, useMemo, useState } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import Icon from "./components/Icon";
import { aggregateConversations, formatBytes } from "./dashboardData";
import { CAPTURES } from "./captures";

const EMPTY = { total_packets: 0, total_bytes: 0, packet_rate: 0, byte_rate: 0, active_hosts: [], alerts: [], protocols: {}, live_status: "waiting" };
const COLORS = ["#72a7ff", "#73c9e8", "#a4a4f5", "#6dbca3", "#acb9cc", "#7793b6"];
const hostName = ip => ({ "10.0.0.1": "h1", "10.0.0.2": "h2", "10.0.0.3": "h3" }[ip] || "Host");
const timeLabel = value => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function SessionStat({ label, value, detail }) {
    return <div className="session-stat"><dt>{label}</dt><dd>{value}</dd><p>{detail}</p></div>;
}

function PanelTitle({ title, note, children }) {
    return <div className="panel-heading"><div><h2>{title}</h2>{note && <p>{note}</p>}</div>{children}</div>;
}

export default function MininetDashboard({ onNavigate }) {
    const [mode, setMode] = useState("live");
    const [data, setData] = useState(EMPTY);
    const [history, setHistory] = useState([]);
    const [preview, setPreview] = useState([]);
    const [range, setRange] = useState(60);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [previewError, setPreviewError] = useState("");
    function changeMode(next) {
        if (next === mode) return;
        setData(EMPTY); setHistory([]); setPreview([]); setLoading(true); setError(""); setPreviewError(""); setMode(next);
    }
    useEffect(() => {
        const controller = new AbortController();
        let inFlight = false;
        async function load() {
            if (inFlight) return;
            inFlight = true;
            try {
                const requests = [fetch(`/api/dashboard?mode=${mode}`, { signal: controller.signal, cache: "no-store" })];
                if (mode === "live") requests.push(fetch("/api/live/packets?limit=200", { signal: controller.signal, cache: "no-store" }));
                const results = await Promise.allSettled(requests);
                if (results[0].status !== "fulfilled") throw results[0].reason;
                const response = results[0].value;
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Dashboard request failed");
                if (controller.signal.aborted) return;
                setData(result); setError("");
                if (mode === "live") {
                    setHistory(previous => [...previous, { timestamp: Date.now(), rate: result.live_status === "online" ? Number(result.packet_rate) || 0 : null }].slice(-60));
                    try {
                        if (results[1].status !== "fulfilled") throw results[1].reason;
                        const packets = await results[1].value.json();
                        if (!results[1].value.ok) throw new Error(packets.error || "Packet preview unavailable");
                        if (!controller.signal.aborted) { setPreview(Array.isArray(packets.packets) ? packets.packets : []); setPreviewError(""); }
                    } catch (err) {
                        if (!controller.signal.aborted) { setPreview([]); setPreviewError(err.message); }
                    }
                }
            } catch (err) {
                if (!controller.signal.aborted) { setError(`Cannot connect to the PacketSense API: ${err.message}`); setData(EMPTY); setPreview([]); }
            } finally { inFlight = false; if (!controller.signal.aborted) setLoading(false); }
        }
        load();
        const timer = mode === "live" ? setInterval(load, 1000) : null;
        return () => { controller.abort(); if (timer) clearInterval(timer); };
    }, [mode]);

    const live = mode === "live";
    const online = live && !error && data.live_status === "online";
    const hosts = Array.isArray(data.active_hosts) ? data.active_hosts : [];
    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    const protocols = Object.entries(data.protocols || {}).sort((a, b) => b[1] - a[1]);
    const protocolTotal = protocols.reduce((total, [, count]) => total + Number(count), 0);
    const conversations = useMemo(() => aggregateConversations(preview), [preview]);
    const chartData = history.slice(-range);
    const observedRates = history.filter(sample => sample.rate !== null);
    const maxRate = Math.max(0, ...observedRates.map(sample => sample.rate));
    const captureFiles = data.capture_files || [];
    const statusLabel = loading ? "Connecting" : !live ? "Saved captures" : error ? "API unavailable" : online ? "Live capture" : data.live_status === "stale" ? "Capture stale" : "Awaiting capture";
    const tooltipStyle = { background: "#18263a", border: "1px solid #3d5372", borderRadius: 10, color: "#eef5ff", fontSize: 12 };

    return (
        <div className="dashboard-page">
            <div className="page-heading">
                <div><p className="eyebrow">CAPTURE WORKSPACE</p><h1>Network overview</h1><p className="page-description">Understand the flow. Follow the evidence.</p></div>
                <div className="page-heading-actions">
                    <div className="segmented-control" role="group" aria-label="Traffic mode">
                        <button aria-pressed={live} onClick={() => changeMode("live")}>Live Mininet</button>
                        <button aria-pressed={!live} onClick={() => changeMode("saved")}>Saved PCAPs</button>
                    </div>
                </div>
            </div>
            {error && <div className="notice notice--error" role="alert">{error}</div>}
            {!loading && live && !online && !error && <div className="notice"><Icon name="clock" size={16}/>{data.live_status === "stale" ? "Capture updates have stopped. Check the live monitor in your VM." : "Waiting for your Mininet monitor. Traffic will appear as soon as capture starts."}</div>}

            <div className="capture-layout">
                <section className="panel throughput-panel">
                    <PanelTitle title={live ? "Packet throughput" : "Capture composition"} note={live ? "Live packet rate · one update per second" : "Packet counts across your saved captures"}>
                        <span className={`status-pill ${online ? "status-pill--green" : ""}`} role="status"><i/>{statusLabel}</span>
                    </PanelTitle>
                    <div className="throughput-readout">
                        <div><strong>{live ? online ? Number(data.packet_rate || 0).toLocaleString(undefined, { maximumFractionDigits: 1 }) : "—" : protocols.length}</strong><span>{live ? "packets / second" : "protocols observed"}</span></div>
                        <div className="throughput-context">{live ? <><span>Peak in recent updates</span><strong>{observedRates.length ? `${maxRate.toLocaleString(undefined, { maximumFractionDigits: 1 })} pkts/s` : "No live samples"}</strong></> : <><span>Capture library</span><strong>{captureFiles.length} available files</strong></>}</div>
                    </div>
                    <div className="traffic-chart">
                        <ResponsiveContainer width="100%" height="100%">
                            {live ? <AreaChart data={chartData} margin={{ top: 10, right: 14, left: -14, bottom: 0 }}>
                                <defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#5796ff" stopOpacity={0.28}/><stop offset="100%" stopColor="#5796ff" stopOpacity={0}/></linearGradient></defs>
                                <CartesianGrid stroke="#26374f" vertical={false} strokeDasharray="2 6"/>
                                <XAxis dataKey="timestamp" tickFormatter={timeLabel} tick={{ fill: "#a8b8cc", fontSize: 10 }} minTickGap={65} axisLine={false} tickLine={false}/>
                                <YAxis tick={{ fill: "#a8b8cc", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false}/>
                                <Tooltip contentStyle={tooltipStyle} labelFormatter={timeLabel} formatter={value => [value, "Packets / second"]}/>
                                <Area type="linear" dataKey="rate" stroke="#72a7ff" strokeWidth={2.5} fill="url(#trafficFill)" connectNulls={false} isAnimationActive={false} dot={false}/>
                            </AreaChart> : <BarChart data={protocols.map(([name, count]) => ({ name, count }))} margin={{ top: 10, right: 14, left: -14, bottom: 0 }}>
                                <CartesianGrid stroke="#26374f" vertical={false} strokeDasharray="2 6"/>
                                <XAxis dataKey="name" tick={{ fill: "#a8b8cc", fontSize: 11 }} axisLine={false} tickLine={false}/>
                                <YAxis tick={{ fill: "#a8b8cc", fontSize: 11 }} axisLine={false} tickLine={false}/>
                                <Tooltip contentStyle={tooltipStyle} formatter={value => [value, "Packets"]}/>
                                <Bar dataKey="count" fill="#72a7ff" radius={[5, 5, 0, 0]} maxBarSize={46}/>
                            </BarChart>}
                        </ResponsiveContainer>
                    </div>
                    <div className="chart-bottom">{live ? <div className="range-control" role="group" aria-label="Chart history"><button aria-pressed={range === 30} onClick={() => setRange(30)}>30 updates</button><button aria-pressed={range === 60} onClick={() => setRange(60)}>60 updates</button></div> : <span>All available saved captures</span>}<span>{live ? `${observedRates.length} live samples` : "Counts from capture files"}</span></div>
                </section>

                <aside className="panel session-panel" aria-label="Capture session summary">
                    <PanelTitle title={live ? "Session totals" : "Library totals"} note={live ? "Since this monitor started" : "Across available capture files"}/>
                    <dl className="session-stats">
                        <SessionStat label="Captured packets" value={loading ? "—" : Number(data.total_packets || 0).toLocaleString()} detail={live ? "Cumulative packet count" : `${captureFiles.length} capture files`}/>
                        <SessionStat label="Traffic volume" value={loading ? "—" : formatBytes(data.total_bytes)} detail={live ? online ? `${formatBytes(data.byte_rate)} / second currently` : "No current byte rate" : "Total captured bytes"}/>
                        <SessionStat label="Observed addresses" value={loading ? "—" : hosts.length} detail={live ? "Unique IPs in this session" : "Unique IPs across captures"}/>
                    </dl>
                    <div className="session-scope"><span className="section-label">CAPTURE SCOPE</span><strong>{live ? "Server-facing link" : "Saved capture library"}</strong><p>{live ? "s1-eth3 · h3 traffic · 30s detection window" : "Offline inspection of bundled PCAP files"}</p></div>
                </aside>
            </div>

            <div className="analysis-layout">
                <section className="panel protocol-panel">
                    <PanelTitle title="Protocol distribution" note="Packet share by observed protocol"><span className="panel-counter">{protocols.length} types</span></PanelTitle>
                    <div className="protocol-list">{protocols.length ? protocols.map(([name, count], index) => {
                        const share = protocolTotal > 0 ? count / protocolTotal * 100 : 0;
                        return <div className="protocol-item" key={name}><div className="protocol-item-label"><strong>{name}</strong><span>{Number(count).toLocaleString()} packets</span><b>{share.toFixed(1)}%</b></div><div className="protocol-track"><span style={{ width: `${share}%`, background: COLORS[index % COLORS.length] }}/></div></div>;
                    }) : <p className="empty-inline">A protocol breakdown will appear when capture data is available.</p>}</div>
                </section>
                <section className="panel detection-panel">
                    <PanelTitle title="Detection inbox" note="Preliminary indicators for your review"><button className="text-action" onClick={() => onNavigate("Threats")}>View detections<Icon name="arrow" size={15}/></button></PanelTitle>
                    <div className="detection-summary"><strong>{loading ? "—" : alerts.length}</strong><div><span>{alerts.length === 1 ? "indicator to investigate" : "indicators to investigate"}</span><p>{alerts.length ? "Review the evidence before drawing conclusions." : online || !live ? "No activity matched the current rules." : "Waiting for current capture evidence."}</p></div></div>
                    <div className="alert-list">{alerts.slice(0, 3).map((alert, index) => <button key={`${alert.type}-${index}`} onClick={() => onNavigate("Threats")}><span><strong>{alert.type}</strong><small>{alert.source || "Capture indicator"}{alert.destination ? ` → ${alert.destination}` : ""}</small></span><span className={`severity severity--${alert.severity?.toLowerCase()}`}>{alert.severity}</span><Icon name="chevron" size={14}/></button>)}</div>
                    {alerts.length > 3 && <p className="inbox-note">{alerts.length - 3} more indicators in Detections.</p>}
                    <div className="host-roster"><span className="section-label">OBSERVED ADDRESSES</span><div>{hosts.length ? hosts.map(ip => <span className="host-label" key={ip}><strong>{hostName(ip)}</strong><code>{ip}</code></span>) : <p>No addresses observed yet.</p>}</div></div>
                </section>
            </div>

            <section className="panel conversations-panel">
                <PanelTitle title={live ? "Conversation ledger" : "Capture inventory"} note={live ? "Source → destination flows from the most recent 200 packet records" : "Capture files available for packet inspection"}><button className="text-action" onClick={() => onNavigate("Packets")}>Open packet explorer<Icon name="arrow" size={15}/></button></PanelTitle>
                <div className="table-scroll"><table className="data-table"><thead><tr>{(live ? ["Source address", "Destination address", "Protocol", "Port", "Packets", "Traffic"] : ["Capture file", "Label", "Format", "Availability"]).map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>
                    {loading ? <tr><td colSpan={live ? 6 : 4} className="empty-cell">Loading network data…</td></tr> : live ? conversations.length ? conversations.slice(0, 8).map(row => <tr key={row.key}><td><code>{row.source}</code></td><td><code>{row.destination}</code></td><td><span className="protocol-tag">{row.protocol}</span></td><td className="tabular">{row.port}</td><td className="tabular">{row.packets.toLocaleString()}</td><td className="traffic-amount tabular">{formatBytes(row.bytes)}</td></tr>) : <tr><td colSpan={6} className="empty-cell">{previewError || "Conversations will appear when packets reach the monitored server link."}</td></tr> : captureFiles.map(file => <tr key={file}><td><span className="file-name"><Icon name="file" size={14}/>{file}</span></td><td>{CAPTURES.find(capture => capture.file === file)?.label || "Capture"}</td><td><span className="protocol-tag">PCAP</span></td><td><span className="availability"><i/>Available</span></td></tr>)}
                </tbody></table></div>
                {live && <div className="table-footnote">{conversations.length > 8 ? `Showing 8 of ${conversations.length} sampled conversations. ` : ""}Conversation counts describe the recent packet sample; session totals include all captured packets.</div>}
            </section>
        </div>
    );
}
