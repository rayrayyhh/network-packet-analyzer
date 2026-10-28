import { useState } from "react";
import Icon from "./components/Icon";

const ITEMS = [
    { page: "Dashboard", label: "Overview", icon: "overview" },
    { page: "Packets", label: "Server traffic", icon: "traffic" },
    { page: "Threats", label: "Threat analysis", icon: "shield" },
    { page: "Analytics", label: "AI assistant", icon: "assistant" },
];

export default function Sidebar({ page, setPage }) {
    const [collapsed, setCollapsed] = useState(false);
    return (
        <aside className={`sidebar ${collapsed ? "sidebar--collapsed" : ""}`} aria-label="Main navigation">
            <button className="brand" onClick={() => setPage("Dashboard")} aria-label="PacketSense home">
                <span className="brand-mark"><Icon name="pulse" size={23} /></span>
                <span className="sidebar-label brand-name">PacketSense<span>NETWORK MONITOR</span></span>
            </button>
            <div className="sidebar-section-label sidebar-label">WORKSPACE</div>
            <nav className="sidebar-nav">
                {ITEMS.map(item => (
                    <button key={item.page} className={`nav-item ${page === item.page ? "nav-item--active" : ""}`} onClick={() => setPage(item.page)} aria-current={page === item.page ? "page" : undefined} title={item.label}>
                        <Icon name={item.icon} /><span className="sidebar-label">{item.label}</span>
                        {page === item.page && <span className="nav-active-dot sidebar-label" />}
                    </button>
                ))}
            </nav>
            <div className="sidebar-bottom">
                <div className="lab-card sidebar-label">
                    <div className="lab-card-heading"><Icon name="network" size={17}/><span>Mininet lab</span><span className="tiny-tag">LOCAL</span></div>
                    <p>3 hosts · 1 switch</p>
                    <div className="lab-topology"><span>h1</span><i/><span>s1</span><i/><span>h3</span></div>
                    <small>Observing the server link</small>
                </div>
                <button className="collapse-button" onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} aria-expanded={!collapsed} title={collapsed ? "Expand navigation" : "Collapse navigation"}>
                    <Icon name="collapse"/><span className="sidebar-label">Collapse sidebar</span>
                </button>
            </div>
        </aside>
    );
}
