import { useState } from "react";

import Sidebar from "./Sidebar";
import MininetDashboard from "./MininetDashboard";
import ServerTraffic from "./ServerTraffic";
import PortScanAnalysis from "./PortScanAnalysis";
import NetworkMonitoringAssistant from "./NetworkMonitoringAssistant";

function App() {

    const [page, setPage] = useState(() => {
        return sessionStorage.getItem("currentPage") || "Dashboard";
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

            </main>

        </div>
    );
}

export default App;