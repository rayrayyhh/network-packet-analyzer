export function aggregateConversations(packets) {
    const groups = new Map();
    for (const packet of packets) {
        if (!packet.source || packet.source === "-" || !packet.destination || packet.destination === "-") continue;
        const fields = [packet.source, packet.destination, packet.protocol || "Other", packet.destinationPort ?? "-"];
        const key = JSON.stringify(fields);
        const group = groups.get(key) || { key, source: fields[0], destination: fields[1], protocol: fields[2], port: fields[3], packets: 0, bytes: 0 };
        group.packets += 1;
        group.bytes += Math.max(0, Number(packet.size) || 0);
        groups.set(key, group);
    }
    return [...groups.values()].sort((a, b) => b.bytes - a.bytes || b.packets - a.packets);
}

export function formatBytes(bytes) {
    const value = Math.max(0, Number(bytes) || 0);
    if (value >= 1e9) return `${(value / 1e9).toFixed(2)} GB`;
    if (value >= 1e6) return `${(value / 1e6).toFixed(2)} MB`;
    if (value >= 1e3) return `${(value / 1e3).toFixed(1)} KB`;
    return `${value} B`;
}
