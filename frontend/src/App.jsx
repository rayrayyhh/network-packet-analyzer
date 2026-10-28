import { lazy, Suspense, useEffect, useState } from "react";
import Sidebar from "./Sidebar";
import Icon from "./components/Icon";
const MininetDashboard = lazy(() => import("./MininetDashboard"));
const ServerTraffic = lazy(() => import("./ServerTraffic"));
const PortScanAnalysis = lazy(() => import("./PortScanAnalysis"));
const NetworkMonitoringAssistant = lazy(() => import("./NetworkMonitoringAssistant"));
const LABELS = { Dashboard: "Overview", Packets: "Server traffic", Threats: "Threat analysis", Analytics: "AI assistant" };

function ApiStatus() {
    const [state, setState] = useState("checking");
    useEffect(() => {
        const controller = new AbortController();
        let inFlight = false;
        async function refresh() {
            if (inFlight) return;
            inFlight = true;
            try {
                const response = await fetch("/api/status", { signal: controller.signal, cache: "no-store" });
                const data = await response.json();
                if (!controller.signal.aborted) setState(response.ok && data.status === "online" ? "online" : "offline");
            } catch {
                if (!controller.signal.aborted) setState("offline");
            } finally { inFlight = false; }
        }
        refresh();
        const timer = setInterval(refresh, 10000);
        return () => { controller.abort(); clearInterval(timer); };
    }, []);
    return <span className={`connection-status connection-status--${state}`} role="status"><i/>API {state}</span>;
}

export default function App() {
    const [page, setPage] = useState(() => {
        const saved = sessionStorage.getItem("currentPage");
        return Object.hasOwn(LABELS, saved) ? saved : "Dashboard";
    });
    function changePage(nextPage) {
        setPage(nextPage);
        sessionStorage.setItem("currentPage", nextPage);
        document.querySelector(".workspace-main")?.scrollTo(0, 0);
    }
    return (
        <div className="app-shell">
            <a className="skip-link" href="#main-content">Skip to content</a>
            <Sidebar page={page} setPage={changePage}/>
            <div className="workspace">
                <header className="workspace-header">
                    <div className="breadcrumb"><span>Workspace</span><Icon name="chevron" size={12}/><strong>{LABELS[page]}</strong></div>
                    <div className="header-right"><ApiStatus/><span className="header-divider"/><span className="environment-label"><Icon name="network" size={15}/>Mininet environment</span></div>
                </header>
                <main id="main-content" className="workspace-main" tabIndex={-1}>
                    <Suspense fallback={<div className="page-loading"><Icon name="pulse"/>Loading workspace…</div>}>
                        {page === "Dashboard" && <MininetDashboard onNavigate={changePage}/>}
                        {page === "Packets" && <ServerTraffic/>}
                        {page === "Threats" && <PortScanAnalysis onNavigate={changePage}/>}
                        {page === "Analytics" && <NetworkMonitoringAssistant/>}
                    </Suspense>
                    <footer className="workspace-footer"><span>PacketSense <span className="footer-dot">·</span> Network intelligence for your lab</span><span>Human-reviewed security insights</span></footer>
                </main>
            </div>
        </div>
    );
}
