const PAGES = [
    ["Dashboard", "Overview"],
    ["Packets", "Packet explorer"],
    ["Threats", "Detections"],
    ["Analytics", "Assistant"],
];

export default function TopNavigation({ page, setPage }) {
    return <nav className="top-navigation" aria-label="Main navigation">
        {PAGES.map(([id, label]) => <button key={id} onClick={() => setPage(id)} aria-current={page === id ? "page" : undefined}>{label}</button>)}
    </nav>;
}
