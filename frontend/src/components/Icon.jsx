const paths = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    traffic: <><path d="M4 7h16M16 3l4 4-4 4M20 17H4M8 13l-4 4 4 4"/></>,
    shield: <><path d="M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="M12 8v5m0 3h.01"/></>,
    assistant: <><path d="M12 3l2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z"/><path d="m19 2 .8 2.2L22 5l-2.2.8L19 8l-.8-2.2L16 5l2.2-.8L19 2Z"/></>,
    network: <><rect x="8" y="3" width="8" height="5" rx="1"/><rect x="2" y="16" width="7" height="5" rx="1"/><rect x="15" y="16" width="7" height="5" rx="1"/><path d="M12 8v4M5.5 16v-4h13v4"/></>,
    pulse: <><path d="M2 12h5l3-8 4 16 3-8h5"/></>,
    packets: <><path d="m12 3 9 5-9 5-9-5 9-5ZM3 8v9l9 5 9-5V8M12 13v9"/></>,
    arrow: <><path d="M5 12h14m-5-5 5 5-5 5"/></>,
    chevron: <><path d="m9 5 7 7-7 7"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    file: <><path d="M14 2H5v20h14V7l-5-5ZM14 2v5h5M8 12h8M8 16h6"/></>,
    menu: <><path d="M4 6h16M4 12h16M4 18h16"/></>,
    collapse: <><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16m7-11-3 3 3 3"/></>,
    check: <><path d="m5 12 4 4L19 6"/></>,
    more: <><circle cx="5" cy="12" r=".7"/><circle cx="12" cy="12" r=".7"/><circle cx="19" cy="12" r=".7"/></>,
};

export default function Icon({ name, size = 18, className = "", ...props }) {
    return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className} {...props}>{paths[name] || paths.pulse}</svg>;
}
