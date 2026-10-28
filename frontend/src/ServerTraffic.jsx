import { parsePcap } from "./pcap";
import { useEffect, useMemo, useState } from "react";

import { CAPTURES } from "./captures";

function ServerTraffic() {
    const [mode, setMode] = useState("live");
    const [selectedCapture, setSelectedCapture] = useState(CAPTURES[0].file);
    const [packets, setPackets] = useState([]);
    const [capturedTotal, setCapturedTotal] = useState(0);
    const [liveStatus, setLiveStatus] = useState("waiting");
    const [search, setSearch] = useState("");
    const [protocolFilter, setProtocolFilter] = useState("ALL");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    function resetSource() {
        setPackets([]);
        setCapturedTotal(0);
        setLiveStatus("waiting");
        setLoading(true);
        setError("");
    }

    useEffect(() => {
        const controller = new AbortController();
        let inFlight = false;
        let timer;



        async function load() {
            if (inFlight) return;
            inFlight = true;
            try {
                if (mode === "live") {
                    const response = await fetch(
                        "/api/live/packets?limit=200",
                        { cache: "no-store", signal: controller.signal }
                    );
                    const data = await response.json();
                    if (!response.ok) {
                        throw new Error(data.error || "Live packet request failed. Check the API connection.");
                    }
                    if (controller.signal.aborted) return;
                    setLiveStatus(data.live_status || "waiting");
                    setCapturedTotal(Number(data.total_packets) || 0);
                    setPackets(
                        (Array.isArray(data.packets) ? data.packets : []).map((packet) => ({
                            ...packet,
                            time: new Date(Number(packet.timestamp) * 1000).toLocaleTimeString(),
                        }))
                    );
                } else {
                    const response = await fetch(`/captures/${encodeURIComponent(selectedCapture)}`, {
                        signal: controller.signal,
                        cache: "no-store",
                    });
                    if (!response.ok) {
                        throw new Error(`Cannot load ${selectedCapture}; check the samples folder.`);
                    }
                    const buffer = await response.arrayBuffer();
                    const parsed = parsePcap(buffer, selectedCapture);
                    if (controller.signal.aborted) return;
                    setPackets(parsed);
                    setCapturedTotal(parsed.length);
                    setLiveStatus("waiting");
                }
                setError("");
            } catch (err) {
                if (!controller.signal.aborted) {
                    setError(err.message || "Could not load network traffic.");
                    if (mode === "live") {
                        setLiveStatus("offline");
                        setPackets([]);
                        setCapturedTotal(0);
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

    const filteredPackets = useMemo(() => {
        const query = search.trim().toLowerCase();
        return packets.filter((packet) => {
            const matchesText = [
                packet.source, packet.destination, packet.protocol,
                packet.sourcePort, packet.destinationPort,
            ].some((field) => String(field ?? "").toLowerCase().includes(query));
            return matchesText && (protocolFilter === "ALL" || packet.protocol === protocolFilter);
        });
    }, [packets, search, protocolFilter]);

    const live = mode === "live";
    const showMessage = live && liveStatus !== "online";

    return (
        <div className="w-full legacy-page">
            <div className="page-heading"><div><p className="eyebrow">PACKET INSPECTION</p><h1>Server traffic</h1><p className="page-description">Inspect live packet records or explore a saved capture.</p></div></div>

            <div className="source-toolbar">
                <div className="field-group"><label htmlFor="server-traffic-mode">Capture source</label><select id="server-traffic-mode" value={mode} onChange={event => { resetSource(); setMode(event.target.value); setSearch(""); setProtocolFilter("ALL"); }}><option value="live">Live Mininet</option><option value="saved">Saved PCAP Files</option></select></div>
                {!live && <div className="field-group"><label htmlFor="server-traffic-capture">Capture file</label><select id="server-traffic-capture" value={selectedCapture} onChange={event => { resetSource(); setSelectedCapture(event.target.value); setSearch(""); setProtocolFilter("ALL"); }}>{CAPTURES.map(capture => <option key={capture.file} value={capture.file}>{capture.label}</option>)}</select></div>}
                <p className="source-toolbar-note"><i/>{live ? "Latest 200 packet records" : "Local capture library"}</p>
            </div>

            {showMessage && !error && (
                <div className="mb-5 rounded-lg bg-yellow-50 p-4 text-sm text-yellow-800">
                    {liveStatus === "stale"
                        ? "Live updates stopped. Check the live capture in your VM."
                        : "Waiting for live Mininet data. Start the PacketSense lab in your VM."}
                </div>
            )}
            {error && (
                <div className="mb-5 rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>
            )}

            <div className="mb-6 grid grid-cols-1 gap-5 md:grid-cols-3">
                <StatCard title={live ? "Total Live Packets" : "Captured Packets"} value={capturedTotal.toLocaleString()} />
                <StatCard title="Displayed Packets" value={filteredPackets.length.toLocaleString()} />
                <StatCard title="Traffic Source" value={live ? "Live Mininet" : selectedCapture} small />
            </div>

            {live && (
                <p className="mb-5 text-sm text-gray-500">
                    Showing up to the latest 200 packet records; the total packet counter includes all captured packets.
                </p>
            )}

            <div className="mb-6 flex flex-col gap-4 md:flex-row">
                <input
                    type="text"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    aria-label="Search packet records"
                    placeholder="Search IP address, port or protocol..."
                    className="w-full rounded-lg border border-gray-200 bg-panel px-4 py-3 outline-none focus:border-blue-500"
                />
                <select
                    aria-label="Filter protocol"
                    value={protocolFilter}
                    onChange={(event) => setProtocolFilter(event.target.value)}
                    className="rounded-lg border border-gray-200 bg-panel px-4 py-3 outline-none focus:border-blue-500"
                >
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="ARP">ARP</option>
                    <option value="Other">Other</option>
                </select>
            </div>

            <div className="overflow-hidden rounded-xl border border-gray-200 bg-panel">
                <div className="border-b border-gray-200 p-5">
                    <h2 className="text-lg font-semibold text-gray-800">Packet Capture</h2>
                    <p className="mt-1 text-sm text-gray-500">
                        {live ? "Recent packets received from Mininet — refreshes every second" : `Packets from ${selectedCapture}`}
                    </p>
                </div>
                <div className="max-h-[580px] overflow-auto">
                    <table className="w-full text-left">
                        <thead className="sticky top-0 bg-gray-50 text-sm text-gray-500">
                            <tr>
                                <th className="px-5 py-3">#</th>
                                <th className="px-5 py-3">Time</th>
                                <th className="px-5 py-3">Source</th>
                                <th className="px-5 py-3">Destination</th>
                                <th className="px-5 py-3">Protocol</th>
                                <th className="px-5 py-3">Source Port</th>
                                <th className="px-5 py-3">Destination Port</th>
                                <th className="px-5 py-3">Size</th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && <MessageRow text="Loading packets..." />}
                            {!loading && !error && !filteredPackets.length && (
                                <MessageRow text={live ? "No live packets received yet." : "No packets found."} />
                            )}
                            {!loading && !error && filteredPackets.map((packet) => (
                                <tr key={packet.id} className="border-t border-gray-100 text-sm hover:bg-gray-50">
                                    <td className="px-5 py-4 text-gray-500">{packet.id}</td>
                                    <td className="px-5 py-4 text-gray-500">{packet.time}</td>
                                    <td className="px-5 py-4 font-medium text-gray-800">{packet.source}</td>
                                    <td className="px-5 py-4 text-gray-700">{packet.destination}</td>
                                    <td className="px-5 py-4 text-gray-700"><span className="protocol-tag">{packet.protocol}</span></td>
                                    <td className="px-5 py-4 text-gray-700">{packet.sourcePort}</td>
                                    <td className="px-5 py-4 text-gray-700">{packet.destinationPort}</td>
                                    <td className="px-5 py-4 text-gray-700">{packet.size} B</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

function MessageRow({ text }) {
    return (
        <tr><td colSpan={8} className="px-5 py-10 text-center text-gray-400">{text}</td></tr>
    );
}

function StatCard({ title, value, small = false }) {
    return (
        <div className="rounded-xl border border-gray-200 bg-panel p-5">
            <p className="text-sm text-gray-500">{title}</p>
            <h2 className={`mt-2 break-words font-bold text-gray-800 ${small ? "text-lg" : "text-2xl"}`}>
                {value}
            </h2>
        </div>
    );
}

export default ServerTraffic;
