function readIPv4(view, offset) {
    return [0, 1, 2, 3].map((i) => view.getUint8(offset + i)).join(".");
}

export function parsePcap(arrayBuffer, fileName) {
    const view = new DataView(arrayBuffer);

    if (view.byteLength < 24) {
        throw new Error(`${fileName} is empty or is not a valid PCAP file.`);
    }

    const magic = Array.from(new Uint8Array(arrayBuffer, 0, 4))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");

    const formats = {
        d4c3b2a1: { little: true, nano: false },
        a1b2c3d4: { little: false, nano: false },
        "4d3cb2a1": { little: true, nano: true },
        a1b23c4d: { little: false, nano: true },
    };
    const format = formats[magic];

    if (!format) {
        const beginning = new TextDecoder().decode(arrayBuffer.slice(0, 120)).trimStart();
        if (/^(<!doctype html|<html)/i.test(beginning)) {
            throw new Error(
                `Received an HTML page instead of ${fileName}. Check the samples folder and API connection.`
            );
        }
        throw new Error(
            `${fileName} is not a supported classic PCAP file (header: ${magic}).`
        );
    }

    const linkType = view.getUint32(20, format.little) & 0xffff;
    if (linkType !== 1) {
        throw new Error(`Unsupported PCAP link type ${linkType}; Ethernet (1) is required.`);
    }

    const packets = [];
    let offset = 24;
    let packetNumber = 1;

    while (offset + 16 <= view.byteLength) {
        const seconds = view.getUint32(offset, format.little);
        const fraction = view.getUint32(offset + 4, format.little);
        const capturedLength = view.getUint32(offset + 8, format.little);
        const originalLength = view.getUint32(offset + 12, format.little);
        offset += 16;

        if (capturedLength > view.byteLength - offset) {
            throw new Error(`Truncated packet ${packetNumber} in ${fileName}.`);
        }

        const start = offset;
        const end = start + capturedLength;
        const milliseconds = seconds * 1000 + fraction / (format.nano ? 1e6 : 1e3);
        const packet = {
            id: packetNumber,
            time: new Date(milliseconds).toLocaleTimeString(),
            source: "-",
            destination: "-",
            protocol: "Other",
            sourcePort: "-",
            destinationPort: "-",
            size: originalLength,
            syn: false,
            ack: false,
            ipVersion: null,
        };

        if (end - start >= 14) {
            let etherType = view.getUint16(start + 12, false);
            let payloadStart = start + 14;

            while (
                [0x8100, 0x88a8, 0x9100].includes(etherType) &&
                payloadStart + 4 <= end
            ) {
                etherType = view.getUint16(payloadStart + 2, false);
                payloadStart += 4;
            }

            if (etherType === 0x0800) {
                parseIPv4(view, payloadStart, end, packet);
            } else if (etherType === 0x0806) {
                parseARP(view, payloadStart, end, packet);
            }
        }

        packets.push(packet);
        offset = end;
        packetNumber++;
    }

    if (offset !== view.byteLength) {
        throw new Error(`Truncated packet header in ${fileName}.`);
    }
    return packets;
}

function parseIPv4(view, start, end, packet) {
    if (start + 20 > end) return;

    const versionAndLength = view.getUint8(start);
    const version = versionAndLength >> 4;
    const headerLength = (versionAndLength & 15) * 4;
    if (version !== 4 || headerLength < 20 || start + headerLength > end) return;

    packet.ipVersion = 4;
    packet.source = readIPv4(view, start + 12);
    packet.destination = readIPv4(view, start + 16);
    const protocol = view.getUint8(start + 9);
    const transport = start + headerLength;
    const fragmentOffset = view.getUint16(start + 6, false) & 0x1fff;

    if (protocol === 6 || protocol === 17) {
        packet.protocol = protocol === 6 ? "TCP" : "UDP";
        if (fragmentOffset === 0 && transport + 4 <= end) {
            packet.sourcePort = view.getUint16(transport, false);
            packet.destinationPort = view.getUint16(transport + 2, false);
        }
        if (protocol === 6 && fragmentOffset === 0 && transport + 14 <= end) {
            const flags = view.getUint8(transport + 13);
            packet.syn = (flags & 0x02) !== 0;
            packet.ack = (flags & 0x10) !== 0;
        }
    } else if (protocol === 1) {
        packet.protocol = "ICMP";
    }
}

function parseARP(view, start, end, packet) {
    packet.protocol = "ARP";
    if (start + 8 > end) return;

    const protocolType = view.getUint16(start + 2, false);
    const hardwareLength = view.getUint8(start + 4);
    const protocolLength = view.getUint8(start + 5);
    const sourceIP = start + 8 + hardwareLength;
    const targetIP = sourceIP + protocolLength + hardwareLength;

    if (protocolType === 0x0800 && protocolLength === 4 && targetIP + 4 <= end) {
        packet.source = readIPv4(view, sourceIP);
        packet.destination = readIPv4(view, targetIP);
    }
}

