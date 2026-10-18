import { useEffect, useState } from "react";

const API = "http://127.0.0.1:5001";

const CAPTURES = [
    { value: "mixed-traffic-1.pcap", label: "Mixed Traffic 1" },
    { value: "mixed-traffic-2.pcap", label: "Mixed Traffic 2" },
    { value: "mixed-traffic-3.pcap", label: "Mixed Traffic 3" },
    { value: "port-scan.pcap", label: "Port Scan" },
];

function identifyAlert(alert) {
    return JSON.stringify([
        alert.type,
        alert.source,
        alert.destination,
        alert.port,
        alert.first_seen,
    ]);
}

function PipelineStep({ number, text }) {
    return (
        <div className="flex items-center gap-3">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gray-100 text-xs font-semibold text-gray-600">
                {number}
            </span>
            <span className="text-sm text-gray-700">{text}</span>
        </div>
    );
}

function NetworkMonitoringAssistant() {
    const [mode, setMode] = useState("live");
    const [selectedCapture, setSelectedCapture] = useState("mixed-traffic-1.pcap");
    const [question, setQuestion] = useState("");
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [messages, setMessages] = useState([
        { role: "assistant", content: "Select a saved capture and ask me about the traffic." },
    ]);
    const [liveMessages, setLiveMessages] = useState([
        { role: "assistant", content: "Ask me anything about the current Mininet traffic or a detected alert." },
    ]);
    const [loading, setLoading] = useState(false);
    const [chatError, setChatError] = useState("");

    const [liveStatus, setLiveStatus] = useState("waiting");
    const [liveError, setLiveError] = useState("");
    const [livePackets, setLivePackets] = useState(0);
    const [events, setEvents] = useState([]);

    useEffect(() => {
        if (mode !== "live") return;

        const controller = new AbortController();
        let active = true;
        let inFlight = false;

        async function refreshLiveAnalysis() {
            if (inFlight) return;
            inFlight = true;

            try {
                const response = await fetch(`${API}/api/dashboard?mode=live`, {
                    signal: controller.signal,
                    cache: "no-store",
                });

                const contentType = response.headers.get("content-type") || "";
                if (!contentType.includes("application/json")) {
                    throw new Error("The API returned a webpage instead of JSON. Check Flask on port 5001.");
                }

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || "Could not retrieve live security alerts.");
                }
                if (!active) return;

                setLiveStatus(data.live_status || "waiting");
                setLivePackets(Number(data.total_packets) || 0);
                setLiveError("");

                if (data.live_status === "online" && Array.isArray(data.alerts)) {
                    setEvents((previous) => {
                        const byId = new Map(previous.map((event) => [event.id, event]));
                        for (const alert of data.alerts) {
                            if (!alert || typeof alert !== "object") continue;
                            const id = identifyAlert(alert);
                            const old = byId.get(id);
                            byId.set(id, {
                                id,
                                alert,
                                detectedAt: old?.detectedAt || new Date().toLocaleTimeString(),
                            });
                        }
                        return Array.from(byId.values()).slice(-30);
                    });
                }
            } catch (error) {
                if (active && error.name !== "AbortError") {
                    setLiveError(error.message || "Unable to connect to Flask.");
                    setLiveStatus("offline");
                }
            } finally {
                inFlight = false;
            }
        }

        refreshLiveAnalysis();
        const timer = setInterval(refreshLiveAnalysis, 1000);

        return () => {
            active = false;
            controller.abort();
            clearInterval(timer);
        };
    }, [mode]);

    async function askAssistant() {
        const currentQuestion = question.trim();
        if (!currentQuestion || loading) return;

        const askingLive = mode === "live";
        const appendMessage = askingLive ? setLiveMessages : setMessages;

        appendMessage((previous) => [
            ...previous,
            { role: "user", content: currentQuestion },
        ]);
        setQuestion("");
        setChatError("");
        setLoading(true);

        const focusedAlert = askingLive ? selectedAlert : null;
        setSelectedAlert(null);

        try {
            const endpoint = askingLive ? "/api/live/ask" : "/api/analyse";
            const payload = askingLive
                ? {
                    question: currentQuestion,
                    ...(focusedAlert ? { selected_alert: focusedAlert } : {}),
                }
                : { capture_file: selectedCapture, question: currentQuestion };

            const response = await fetch(`${API}${endpoint}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const contentType = response.headers.get("content-type") || "";
            if (!contentType.includes("application/json")) {
                throw new Error("Flask returned HTML instead of JSON. Check port 5001.");
            }
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Network analysis failed.");
            }

            appendMessage((previous) => [
                ...previous,
                { role: "assistant", content: data.answer || "Llama 3.2 returned no answer." },
            ]);
        } catch (error) {
            setChatError(error.message || "Unable to complete analysis.");
            appendMessage((previous) => [
                ...previous,
                { role: "assistant", content: `Unable to complete analysis: ${error.message}` },
            ]);
        } finally {
            setLoading(false);
        }
    }

    function clearChat() {
        if (mode === "live") {
            setLiveMessages([
                { role: "assistant", content: "Ask me anything about the current Mininet traffic or a detected alert." },
            ]);
        } else {
            setMessages([
                { role: "assistant", content: "Select a saved capture and ask me about the traffic." },
            ]);
        }
        setQuestion("");
        setSelectedAlert(null);
        setChatError("");
    }

    function askAboutAlert(alert) {
        setSelectedAlert({
            type: alert.type || null,
            source: alert.source || null,
            destination: alert.destination || null,
            port: alert.port ?? null,
            first_seen: alert.first_seen || null,
        });
        setQuestion(
            `Explain the ${alert.type || "security alert"} from ${alert.source || "the source"}` +
            `${alert.destination ? ` to ${alert.destination}` : ""}. ` +
            "Provide the classification, potential attack, risk level, evidence, " +
            "reasoning, recommended course of action, and human approval requirement."
        );
        setChatError("");
    }

    function onQuestionKeyDown(event) {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            askAssistant();
        }
    }

    const isLive = mode === "live";
    const recentEvents = [...events].reverse();

    return (
        <div className="w-full">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-800">
                    Network Monitoring Assistant
                </h1>
                <p className="mt-2 text-gray-500">
                </p>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
                {/* Settings */}
                <div className="lg:col-span-1 space-y-6">
                    <div className="rounded-xl border border-gray-200 bg-white p-5">
                        <h2 className="text-lg font-semibold text-gray-800">Analysis Settings</h2>

                        <label className="mt-5 mb-2 block text-sm font-medium text-gray-700">
                            Analysis Mode
                        </label>
                        <select
                            value={mode}
                            onChange={(event) => {
                                setMode(event.target.value);
                                setQuestion("");
                                setSelectedAlert(null);
                                setChatError("");
                            }}
                            className="w-full rounded-lg border border-gray-200 bg-white px-3 py-3 outline-none focus:border-blue-500"
                        >
                            <option value="live">Live Mininet </option>
                            <option value="saved">Saved PCAP </option>
                        </select>

                        {!isLive && (
                            <div className="mt-5">
                                <label className="mb-2 block text-sm font-medium text-gray-700">
                                    Capture File
                                </label>
                                <select
                                    value={selectedCapture}
                                    onChange={(event) => setSelectedCapture(event.target.value)}
                                    disabled={loading}
                                    className="w-full rounded-lg border border-gray-200 bg-white px-3 py-3 outline-none focus:border-blue-500"
                                >
                                    {CAPTURES.map((capture) => (
                                        <option key={capture.value} value={capture.value}>
                                            {capture.label}
                                        </option>
                                    ))}
                                </select>
                            </div>
                        )}

                        <div className="mt-6 border-t border-gray-100 pt-5">
                            <p className="text-sm text-gray-500">AI Model</p>
                            <p className="mt-1 font-semibold text-gray-800">Llama 3.2</p>
                        </div>
                        <div className="mt-5">
                            <p className="text-sm text-gray-500">Provider</p>
                            <p className="mt-1 font-semibold text-gray-800">Ollama</p>
                        </div>
                        <div className="mt-5">
                            <p className="text-sm text-gray-500">Status</p>
                            <div className="mt-2 flex items-center gap-2">
                                <span className={`h-2 w-2 rounded-full ${
                                    isLive
                                        ? liveStatus === "online" ? "bg-green-500" : "bg-yellow-500"
                                        : loading ? "bg-yellow-500" : "bg-green-500"
                                }`} />
                                <span className="text-sm font-medium text-gray-700">
                                    {isLive
                                        ? liveStatus === "online" ? "Live Monitor" : `Live Monitor ${liveStatus}`
                                        : loading ? "Analysing saved capture..." : "Ready"}
                                </span>
                            </div>
                            {isLive && (
                                <p className="mt-2 text-xs text-gray-500">
                                    {livePackets.toLocaleString()} live packets observed
                                </p>
                            )}
                        </div>

                        <button
                                type="button"
                                onClick={clearChat}
                                disabled={loading}
                                className="mt-6 w-full rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50 disabled:bg-gray-100"
                            >
                                Clear Chat
                        </button>
                    </div>

                    <div>
                        <h2 className="text-lg font-semibold text-gray-800"></h2>
                        <p className="mt-1 text-sm text-gray-500">
                        
                        </p>

                    </div>
                </div>


                <div className="lg:col-span-3">
                    <div className="flex h-[700px] flex-col rounded-xl border border-gray-200 bg-white">
                        <div className="border-b border-gray-200 p-5">
                            <h2 className="text-lg font-semibold text-gray-800">
                                {isLive ? "Live Mininet Threat Assistant" : "PacketSense Assistant"}
                            </h2>
                            <p className="mt-1 text-sm text-gray-500">
                                {isLive
                                    ? ""
                                    : `Analysing ${selectedCapture}`}
                            </p>
                        </div>

                        <div className="flex-1 overflow-y-auto p-6">
                            {isLive ? (
                                <div className="space-y-5">
                                    {liveError && (
                                        <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">
                                            {liveError}
                                        </div>
                                    )}
                                    {!liveError && liveStatus !== "online" && (
                                        <p className="text-sm text-gray-500">
                                            {liveStatus === "stale"
                                                ? "Live updates stopped. Waiting for the Mininet monitor to reconnect."
                                                : "Waiting for live Mininet data from Flask..."}
                                        </p>
                                    )}
                                    {recentEvents.length === 0 && (
                                        <div className="rounded-xl bg-gray-50 p-5 text-sm text-gray-500">
                                            No live security alerts yet. Generate a controlled port scan or TCP SYN test in your Mininet VM; new detections will appear here automatically.
                                        </div>
                                    )}
                                    {recentEvents.map(({ id, alert, detectedAt }) => {
                                        return (
                                            <div key={id} className="rounded-xl border border-gray-200 bg-white p-5">
                                                <div className="flex flex-wrap items-center justify-between gap-3">
                                                    <p className="font-semibold text-gray-800">
                                                        {alert.type || "Suspicious Activity"}
                                                    </p>
                                                    <span className={`rounded-md px-2 py-1 text-xs font-semibold ${
                                                        alert.severity === "High"
                                                            ? "bg-red-50 text-red-700"
                                                            : "bg-yellow-50 text-yellow-700"
                                                    }`}>
                                                        {alert.severity || "Review"}
                                                    </span>
                                                </div>
                                                <p className="mt-2 text-sm text-gray-600">
                                                    {alert.description || "Network activity matched a detection rule."}
                                                </p>
                                                <p className="mt-2 text-xs text-gray-500">
                                                    {alert.source || "Unknown source"}
                                                    {alert.destination ? ` → ${alert.destination}` : ""}
                                                    {alert.port != null ? ` : ${alert.port}` : ""}
                                                    {` · Detected at ${detectedAt}`}
                                                </p>
                                                <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg bg-gray-50 p-4">
                                                    <p className="text-sm text-gray-600">
                                                        Ask Llama 3.2 for an Analysis
                                                    </p>
                                                    <button
                                                        type="button"
                                                        onClick={() => askAboutAlert(alert)}
                                                        className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs font-medium text-blue-700 hover:bg-blue-50"
                                                    >
                                                        Ask about this detection
                                                    </button>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            ) : null}

                            <div className={`${isLive ? "mt-6 border-t border-gray-200 pt-5" : ""} space-y-5`}>
                                {isLive && (
                                    <h3 className="text-base font-semibold text-gray-800">
                                        Ask Llama 3.2 about Live Traffic
                                    </h3>
                                )}
                                {(isLive ? liveMessages : messages).map((message, index) => (
                                    <div key={index} className={`flex ${
                                        message.role === "user" ? "justify-end" : "justify-start"
                                    }`}>
                                        <div className={`max-w-[85%] whitespace-pre-wrap break-words rounded-xl px-4 py-3 text-sm leading-6 ${
                                            message.role === "user"
                                                ? "bg-blue-600 text-white"
                                                : "bg-gray-100 text-gray-700"
                                        }`}>
                                            {message.content}
                                        </div>
                                    </div>
                                ))}
                                {loading && (
                                    <p className="text-sm text-gray-500">
                                        {isLive ? "Llama 3.2 is analysing live network data..." : "Llama 3.2 is analysing the saved capture..."}
                                    </p>
                                )}
                            </div>
                        </div>

                        <div className="border-t border-gray-200 p-5">
                            {chatError && (
                                <p className="mb-3 text-sm text-red-600">{chatError}</p>
                            )}
                            {isLive && selectedAlert && (
                                <div >

                                </div>
                            )}
                            <div className="flex gap-3">
                                <textarea
                                    value={question}
                                    onChange={(event) => setQuestion(event.target.value)}
                                    onKeyDown={onQuestionKeyDown}
                                    placeholder={isLive
                                        ? "Ask Llama 3.2 about live Mininet traffic or a detected alert..."
                                        : "Ask Llama 3.2 about this PCAP..."}
                                    rows={2}
                                    disabled={loading}
                                    className="flex-1 resize-none rounded-lg border border-gray-200 px-4 py-3 text-sm outline-none focus:border-blue-500 disabled:bg-gray-100"
                                />
                                <button
                                    type="button"
                                    onClick={askAssistant}
                                    disabled={loading || !question.trim()}
                                    className="rounded-lg bg-blue-600 px-6 py-3 font-medium text-white hover:bg-blue-700 disabled:bg-gray-300"
                                >
                                    {loading ? "Analysing..." : "Send"}
                                </button>
                            </div>
                            <p className="mt-2 text-xs text-gray-400">
                                {isLive
                                    ? "Llama 3.2 runs only when you send a question. Live detections still refresh."
                                    : `Questions use ${selectedCapture}.`} Enter to send · Shift + Enter for a new line
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default NetworkMonitoringAssistant;
