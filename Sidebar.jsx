import { useState } from "react";

function Sidebar({ setPage }) {
    const [open, setOpen] = useState(true);

    return (
        <div
            className={
                open
                    ? "w-64 min-h-screen bg-white border-r border-gray-200 transition-all duration-300"
                    : "w-20 min-h-screen bg-white border-r border-gray-200 transition-all duration-300"
            }
        >
            <div className="flex items-center justify-between p-5 border-b border-gray-200">
                
                                  <span className="text-xl">🛡️</span>

                {open && (
                    <h2 className="text-xl font-bold text-gray-800">
                        PacketSense
                    </h2>
                )}

                <button
                    onClick={() => setOpen(!open)}
                    className="text-xl text-gray-600 hover:text-gray-900"
                >
                    ☰
                </button>

            </div>

    
            <div className="p-4">

        
                <div
                    onClick={() => setPage("Dashboard")}
                    className="flex items-center gap-4 p-3 mb-2 rounded-lg cursor-pointer hover:bg-gray-100"
                >
                    <span className="text-xl">🏠</span>

                    {open && (
                        <p className="text-gray-700">
                            Mininet Dashboard
                        </p>
                    )}
                </div>

          
                <div
                    onClick={() => setPage("Packets")}
                    className="flex items-center gap-4 p-3 mb-2 rounded-lg cursor-pointer hover:bg-gray-100"
                >
                    <span className="text-xl">📦</span>

                    {open && (
                        <p className="text-gray-700">
                            Server Traffic
                        </p>
                    )}
                </div>

                <div
                    onClick={() => setPage("Threats")}
                    className="flex items-center gap-4 p-3 mb-2 rounded-lg cursor-pointer hover:bg-gray-100"
                >
                    <span className="text-xl">⚠️</span>

                    {open && (
                        <p className="text-gray-700">
                            Port Scan Analysis
                        </p>
                    )}
                </div>

               
                <div
                    onClick={() => setPage("Analytics")}
                    className="flex items-center gap-4 p-3 mb-2 rounded-lg cursor-pointer hover:bg-gray-100"
                >
                    <span className="text-xl">📊</span>

                    {open && (
                        <p className="text-gray-700">
                            Network Monitoring Assistant
                        </p>
                    )}
                </div>

            </div>
        </div>
    );
}

export default Sidebar;