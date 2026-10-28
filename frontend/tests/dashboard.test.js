import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateConversations, formatBytes } from '../src/dashboardData.js';

test('conversation totals preserve direction and separate ports and protocols', () => {
    const base = { source: '10.0.0.1', destination: '10.0.0.3', protocol: 'TCP', destinationPort: 8000, size: 60 };
    const rows = aggregateConversations([base, base, { ...base, destinationPort: 443 }, { ...base, protocol: 'UDP' }, { ...base, source: '10.0.0.3', destination: '10.0.0.1' }]);
    assert.equal(rows.length, 4);
    assert.equal(rows[0].packets, 2);
    assert.equal(rows[0].bytes, 120);
    assert.equal(rows.reduce((sum, row) => sum + row.packets, 0), 5);
    assert.equal(rows.reduce((sum, row) => sum + row.bytes, 0), 300);
});

test('unknown endpoints are omitted and non-IP records can retain their endpoints', () => {
    const rows = aggregateConversations([{ source: '-', destination: '10.0.0.3', size: 20 }, { source: '10.0.0.1', destination: '10.0.0.3', protocol: 'ARP', size: 42 }]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].port, '-');
    assert.equal(rows[0].bytes, 42);
    assert.deepEqual(aggregateConversations([]), []);
});

test('traffic units use consistent decimal sizes', () => {
    assert.equal(formatBytes(0), '0 B');
    assert.equal(formatBytes(1500), '1.5 KB');
    assert.equal(formatBytes(2500000), '2.50 MB');
    assert.equal(formatBytes(3000000000), '3.00 GB');
});
