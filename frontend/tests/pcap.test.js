import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { parsePcap } from '../src/pcap.js';

function arrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

for (const filename of readdirSync(new URL('../../samples/', import.meta.url))) {
    test(`parse bundled ${filename}`, () => {
        const bytes = readFileSync(new URL(`../../samples/${filename}`, import.meta.url));
        const packets = parsePcap(arrayBuffer(bytes), filename);
        assert.ok(packets.length > 0);
        assert.ok(packets.some(p => p.source.startsWith('10.')));
        assert.ok(packets.every(p => Number.isInteger(p.size)));
    });
}

test('reject HTML fallback and truncated captures', () => {
    assert.throws(() => parsePcap(arrayBuffer(Buffer.from('<!doctype html>' + ' '.repeat(20))), 'test'), /HTML/);
    assert.throws(() => parsePcap(new ArrayBuffer(0), 'test'), /valid PCAP/);
    const bytes = readFileSync(new URL('../../samples/port-scan.pcap', import.meta.url));
    assert.throws(() => parsePcap(arrayBuffer(bytes.subarray(0, bytes.length - 1)), 'test'), /Truncated/);
    assert.throws(() => parsePcap(arrayBuffer(Buffer.concat([bytes, Buffer.from([0])])), 'test'), /Truncated/);
});

for (const little of [true, false]) {
    for (const nano of [true, false]) {
        test(`timestamps little=${little}, nano=${nano}`, () => {
            const buffer = new ArrayBuffer(54);
            const view = new DataView(buffer);
            view.setUint32(0, nano ? 0xa1b23c4d : 0xa1b2c3d4, little);
            view.setUint32(20, 1, little);
            view.setUint32(24, 1700000000, little);
            view.setUint32(28, nano ? 500000000 : 500000, little);
            view.setUint32(32, 14, little);
            view.setUint32(36, 60, little);
            const packets = parsePcap(buffer, 'generated');
            assert.equal(packets[0].size, 60);
            assert.equal(packets[0].time, new Date(1700000000500).toLocaleTimeString());
        });
    }
}
