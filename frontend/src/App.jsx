import { lazy, Suspense, useState } from "react";

import Sidebar from "./Sidebar";
const MininetDashboard = lazy(() => import("./MininetDashboard"));
const ServerTraffic = lazy(() => import("./ServerTraffic"));
const PortScanAnalysis = lazy(() => import("./PortScanAnalysis"));
const NetworkMonitoringAssistant = lazy(() => import("./NetworkMonitoringAssistant"));

function App() {

    const [page, setPage] = useState(() => {
        const saved = sessionStorage.getItem("currentPage");
        return ["Dashboard", "Packets", "Threats", "Analytics"].includes(saved) ? saved : "Dashboard";
    });


    function changePage(newPage) {

        setPage(newPage);

        sessionStorage.setItem(
            "currentPage",
            newPage
        );
    }


    return (
        <div className="flex min-h-screen bg-gray-100">

            <Sidebar
                setPage={changePage}
            />

            <main className="flex-1 p-8">
                <Suspense fallback={<p>Loading page...</p>}>

                {page === "Dashboard" && (
                    <MininetDashboard onNavigate={changePage} />
                )}

                {page === "Packets" && (
                    <ServerTraffic />
                )}

                {page === "Threats" && (
                    <PortScanAnalysis onNavigate={changePage} />
                )}

                {page === "Analytics" && (
                    <NetworkMonitoringAssistant />
                )}

                </Suspense>
            </main>

        </div>
    );
}

export default App;