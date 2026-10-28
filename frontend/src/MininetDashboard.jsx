import { useEffect, useMemo, useState } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import Icon from "./components/Icon";
import { aggregateConversations, formatBytes } from "./dashboardData";
import { CAPTURES } from "./captures";

const EMPTY = { total_packets: 0, total_bytes: 0, packet_rate: 0, byte_rate: 0, active_hosts: [], alerts: [], protocols: {}, live_status: "waiting" };
const COLORS = ["#f29259", "#72b9be", "#86ba9a", "#a99bce", "#d9bd79", "#a5a5a0"];
const hostName = ip => ({ "10.0.0.1": "h1", "10.0.0.2": "h2", "10.0.0.3": "h3" }[ip] || "Host");
const timeLabel = value => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function Metric({ icon, label, value, detail, onClick, alert }) {
    const content = <><div className="metric-label"><Icon name={icon} size={16}/>{label}{onClick && <Icon name="arrow" size={14}/>}</div><div className={`metric-value ${alert ? "metric-value--alert" : ""}`}>{value}</div><p>{detail}</p></>;
    return onClick ? <button className="metric-card metric-card--link" onClick={onClick}>{content}</button> : <div className="metric-card">{content}</div>;
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
    const cells = [...Array(Math.max(0, 60 - history.length)).fill(null), ...history];
    const captureFiles = data.capture_files || [];
    const statusLabel = loading ? "Connecting" : !live ? "Saved captures" : error ? "API unavailable" : online ? "Live capture" : data.live_status === "stale" ? "Capture stale" : "Awaiting capture";
    const tooltipStyle = { background: "#292927", border: "1px solid #41413b", borderRadius: 8, color: "#f3f2eb", fontSize: 12 };

    return (
        <div className="dashboard-page">
            <div className="page-heading">
                <div><p className="eyebrow">NETWORK OPERATIONS</p><h1>Traffic overview<span className="title-dot">.</span></h1><p className="page-description">Your Mininet network, at a glance.</p></div>
                <div className="page-heading-actions"><span className={`status-pill ${online ? "status-pill--green" : ""}`} role="status"><i/>{statusLabel}</span><div className="segmented-control" role="group" aria-label="Traffic mode"><button aria-pressed={live} onClick={() => changeMode("live")}><Icon name="pulse" size={14}/>Live Mininet</button><button aria-pressed={!live} onClick={() => changeMode("saved")}><Icon name="file" size={14}/>Saved PCAPs</button></div></div>
            </div>
            {error && <div className="notice notice--error" role="alert">{error}</div>}
            {!loading && live && !online && !error && <div className="notice"><Icon name="clock" size={16}/>{data.live_status === "stale" ? "Capture updates have stopped. Check the live monitor in your VM." : "Waiting for your Mininet monitor. Traffic will appear here as soon as capture starts."}</div>}
            <div className="metric-grid">
                <Metric icon="traffic" label="Total traffic" value={loading ? "—" : formatBytes(data.total_bytes)} detail={live ? "Since capture started" : "Across saved captures"}/>
                <Metric icon="packets" label="Captured packets" value={loading ? "—" : Number(data.total_packets || 0).toLocaleString()} detail={live ? "Cumulative packet count" : `${captureFiles.length} capture files`}/>
                <Metric icon="network" label="Observed hosts" value={loading ? "—" : hosts.length.toLocaleString()} detail={live ? "Unique IPs this session" : "Unique IPs in captures"}/>
                <Metric icon="shield" label="Security alerts" value={loading ? "—" : alerts.length.toLocaleString()} detail={alerts.length ? "Review preliminary detections" : "View detection results"} alert={alerts.length > 0} onClick={() => onNavigate("Threats")}/>
            </div>
            <div className="overview-grid">
                <section className="panel traffic-panel">
                    <PanelTitle title={live ? "Running traffic" : "Capture composition"} note={live ? "Packet rate over recent updates" : "Packets grouped by protocol"}><Icon name="pulse" size={17}/></PanelTitle>
                    <div className="chart-summary"><strong>{live ? online ? Number(data.packet_rate || 0).toLocaleString(undefined, { maximumFractionDigits: 1 }) : "—" : protocols.length}<span>{live ? "pkts / sec" : "protocols observed"}</span></strong>{live && <span className="chart-rate">{online ? `${formatBytes(data.byte_rate)} / sec` : "No current rate"}</span>}</div>
                    <div className="traffic-chart">
                        <ResponsiveContainer width="100%" height="100%">
                            {live ? <AreaChart data={chartData} margin={{ top: 12, right: 3, left: -25, bottom: 0 }}><defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f29259" stopOpacity={0.24}/><stop offset="100%" stopColor="#f29259" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#353530" vertical={false} strokeDasharray="3 5"/><XAxis dataKey="timestamp" tickFormatter={timeLabel} tick={{ fill: "#a4a49b", fontSize: 9 }} minTickGap={50} axisLine={false} tickLine={false}/><YAxis tick={{ fill: "#a4a49b", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false}/><Tooltip contentStyle={tooltipStyle} labelFormatter={timeLabel} formatter={value => [value, "Packets / sec"]}/><Area type="monotone" dataKey="rate" stroke="#f29259" strokeWidth={2} fill="url(#trafficFill)" connectNulls={false} isAnimationActive={false} dot={false}/></AreaChart> : <BarChart data={protocols.map(([name, count]) => ({ name, count }))} margin={{ top: 12, right: 0, left: -20, bottom: 0 }}><CartesianGrid stroke="#353530" vertical={false} strokeDasharray="3 5"/><XAxis dataKey="name" tick={{ fill: "#a4a49b", fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis tick={{ fill: "#a4a49b", fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={tooltipStyle} formatter={value => [value, "Packets"]}/><Bar dataKey="count" fill="#f29259" radius={[4, 4, 0, 0]} maxBarSize={32}/></BarChart>}
                        </ResponsiveContainer>
                    </div>
                    <div className="chart-bottom">{live ? <div className="range-control" role="group" aria-label="Chart history"><button aria-pressed={range === 30} onClick={() => setRange(30)}>30 updates</button><button aria-pressed={range === 60} onClick={() => setRange(60)}>60 updates</button></div> : <span>All available saved captures</span>}<span className="muted">{live ? `${observedRates.length} live samples` : "Packet counts"}</span></div>
                </section>
                <section className="panel protocol-panel">
                    <PanelTitle title="Traffic by protocol" note="Share of captured packets"><Icon name="packets" size={17}/></PanelTitle>
                    <div className="protocol-summary"><strong>{protocolTotal ? `${Math.round(Number(protocols[0][1]) / protocolTotal * 100)}%` : "—"}</strong><span>{protocols[0]?.[0] || "Waiting for data"}{protocolTotal > 0 && " · most observed"}</span></div>
                    <div className="protocol-stack" aria-hidden="true">{protocols.map(([name, count], index) => <span key={name} style={{ width: `${count / protocolTotal * 100}%`, background: COLORS[index % COLORS.length] }}/>)}</div>
                    <div className="protocol-table"><div className="protocol-table-header"><span>Protocol</span><span>Packets</span><span>Share</span></div>{protocols.length ? protocols.map(([name, count], index) => <div className="protocol-row" key={name}><span><i style={{ background: COLORS[index % COLORS.length] }}/>{name}</span><span>{Number(count).toLocaleString()}</span><strong>{(count / protocolTotal * 100).toFixed(1)}%</strong></div>) : <p className="empty-inline">Protocol distribution appears when packets arrive.</p>}</div>
                </section>
                <section className="panel activity-panel">
                    <PanelTitle title={live ? "Traffic activity" : "Observed hosts"} note={live ? "Latest 60 capture updates" : "Addresses found in saved captures"}><Icon name={live ? "overview" : "network"} size={17}/></PanelTitle>
                    {live ? <><div className="activity-summary"><span>Peak observed rate</span><strong>{observedRates.length ? maxRate.toLocaleString(undefined, { maximumFractionDigits: 1 }) : "—"}<small> pkts / sec</small></strong></div><div className="heatmap" aria-label="Packet rate per update, oldest at top left">{cells.map((sample, index) => { const level = sample?.rate == null ? "empty" : sample.rate === 0 ? 0 : Math.min(4, Math.max(1, Math.ceil(sample.rate / Math.max(1, maxRate) * 4))); return <div key={sample?.timestamp || `empty-${index}`} className={`heat-cell heat-cell--${level}`} title={sample?.rate == null ? "No live sample" : `${timeLabel(sample.timestamp)} · ${sample.rate} packets/sec`}/>; })}</div><div className="heatmap-axis"><span>Older</span><span>Newest</span></div><div className="heatmap-legend"><span>Less</span>{[0, 1, 2, 3, 4].map(level => <i key={level} className={`heat-cell--${level}`}/>)}<span>More</span><span className="heatmap-no-data"><i className="heat-cell--empty"/>No data</span></div></> : <div className="host-list">{hosts.length ? hosts.map(ip => <div className="host-row" key={ip}><span className="host-avatar"><Icon name="network" size={15}/></span><span><strong>{hostName(ip)}</strong><code>{ip}</code></span><span className="observed-dot" title="Present in saved captures"/></div>) : <p className="empty-inline">No hosts found.</p>}</div>}
                </section>
            </div>
            <div className="detail-grid">
                <section className="panel conversations-panel">
                    <PanelTitle title={live ? "Recent conversations" : "Capture inventory"} note={live ? "Grouped from the latest 200 packet records" : "Bundled PCAP files available for inspection"}><button className="text-action" onClick={() => onNavigate("Packets")}>View traffic<Icon name="arrow" size={14}/></button></PanelTitle>
                    <div className="table-scroll"><table className="data-table"><thead><tr>{(live ? ["Source address", "Destination address", "Protocol", "Port", "Packets", "Traffic"] : ["Capture file", "Label", "Format", "Availability"]).map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{loading ? <tr><td colSpan={live ? 6 : 4} className="empty-cell">Loading network data…</td></tr> : live ? conversations.length ? conversations.slice(0, 7).map(row => <tr key={row.key}><td><code>{row.source}</code></td><td><code>{row.destination}</code></td><td><span className="protocol-tag">{row.protocol}</span></td><td className="tabular">{row.port}</td><td className="tabular">{row.packets.toLocaleString()}</td><td className="traffic-amount tabular">{formatBytes(row.bytes)}</td></tr>) : <tr><td colSpan={6} className="empty-cell">{previewError || "Recent conversations will appear when packets reach the server link."}</td></tr> : captureFiles.map(file => <tr key={file}><td><span className="file-name"><Icon name="file" size={14}/>{file}</span></td><td>{CAPTURES.find(capture => capture.file === file)?.label || "Capture"}</td><td><span className="protocol-tag">PCAP</span></td><td><span className="availability"><i/>Available</span></td></tr>)}</tbody></table></div>
                    {live && conversations.length > 7 && <div className="table-footnote">Showing 7 of {conversations.length} conversations in the recent sample.</div>}
                </section>
                <section className="panel observations-panel">
                    <PanelTitle title="Network observations" note="Capture scope and preliminary alerts"><Icon name="shield" size={17}/></PanelTitle>
                    <div className="observation-stat"><span className={`observation-icon ${alerts.length ? "observation-icon--warning" : ""}`}><Icon name="shield" size={19}/></span><div><strong>{alerts.length ? `${alerts.length} alert${alerts.length === 1 ? "" : "s"} to review` : online || !live ? "No current rule matches" : "Awaiting live evidence"}</strong><p>Rule matches require investigation.</p></div></div>
                    <div className="alert-preview">{alerts.slice(0, 2).map((alert, index) => <button key={`${alert.type}-${index}`} onClick={() => onNavigate("Threats")}><span><strong>{alert.type}</strong><small>{alert.source || "Saved capture indicator"}</small></span><span className={`severity severity--${alert.severity?.toLowerCase()}`}>{alert.severity}</span></button>)}</div>
                    {live && <div className="host-chips">{hosts.length ? hosts.map(ip => <span key={ip}><i/>{hostName(ip)}<code>{ip}</code></span>) : <p>No IP addresses observed yet.</p>}</div>}
                    <div className="capture-scope"><Icon name="network" size={14}/><span>{live ? "Server link · s1-eth3 · 30s detection window" : "Saved captures · rules across each file"}</span></div>
                </section>
            </div>
        </div>
    );
}
