// Tests that need no database or network: input validation on the API routes
// and decoding of ERC-20 name/symbol return data.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const { ethers } = require('ethers');

const app = require('../server');
const { decodeTokenString } = app;

const ADDRESS = '0x000000000000000000000000000000000000dEaD';
let server;
let base;

test.before(async () => {
    server = app.listen(0);
    await new Promise((resolve) => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    // mongoose keeps no connection open in tests, but make sure nothing lingers
    await require('mongoose').disconnect();
});

const get = (path) => fetch(base + path);
const post = (path, body) => fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
});

test('health check lists the supported chains', async () => {
    const res = await get('/api/health');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.deepEqual(body.chains, ['ethereum', 'bsc', 'base', 'pulsechain']);
});

test('rejects an invalid wallet address', async () => {
    for (const path of ['/api/users/nope', '/api/tokens/nope/ethereum', '/api/liquidity/nope', '/api/analytics/nope']) {
        const res = await get(path);
        assert.equal(res.status, 400, path);
    }
});

test('rejects an unsupported chain, including inherited object keys', async () => {
    assert.equal((await get(`/api/tokens/${ADDRESS}/solana`)).status, 400);
    assert.equal((await get(`/api/tokens/${ADDRESS}/constructor`)).status, 400);
});

test('rejects a malformed token or position id instead of failing with a 500', async () => {
    assert.equal((await get(`/api/tokens/${ADDRESS}/ethereum/not-an-id`)).status, 400);
    assert.equal((await get(`/api/liquidity/${ADDRESS}/not-an-id`)).status, 400);
});

test('sync validates its body before doing any work', async () => {
    assert.equal((await post('/api/sync', {})).status, 400);
    assert.equal((await post('/api/sync', { address: 'nope' })).status, 400);
    assert.equal((await post('/api/sync', { address: ADDRESS, chains: 'ethereum' })).status, 400);
    assert.equal((await post('/api/sync', { address: ADDRESS, chains: ['solana'] })).status, 400);
    assert.equal((await post('/api/sync', { address: ADDRESS, chain: 'constructor' })).status, 400);
});

test('decodes an ABI-encoded token string', () => {
    const data = ethers.AbiCoder.defaultAbiCoder().encode(['string'], ['PulseX']);
    assert.equal(decodeTokenString(data, 'UNKNOWN'), 'PulseX');
});

test('decodes a bytes32 token string such as MKR', () => {
    assert.equal(decodeTokenString(ethers.encodeBytes32String('MKR'), 'UNKNOWN'), 'MKR');
});

test('falls back when a token returns nothing usable', () => {
    assert.equal(decodeTokenString('0x', 'UNKNOWN'), 'UNKNOWN');
    assert.equal(decodeTokenString(undefined, 'UNKNOWN'), 'UNKNOWN');
    assert.equal(decodeTokenString('0x' + '00'.repeat(32), 'UNKNOWN'), 'UNKNOWN');
});
