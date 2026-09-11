#!/usr/bin/env node
'use strict';
/*
 * v380-mjpeg.js — native V380 camera stream client (no vendor app, no .NET).
 *
 * Talks the proprietary V380 protocol on TCP :8800, authenticates, derives the
 * per-session AES key, and decrypts the MJPEG video stream. Serves it as:
 *    http://<host>:<httpPort>/          live view (HTML page)
 *    http://<host>:<httpPort>/stream    multipart/x-mixed-replace MJPEG
 *    http://<host>:<httpPort>/snapshot  latest single JPEG
 *
 * This camera (model AC54, deviceVersion 31) streams ENCRYPTED MJPEG on frame
 * type 0x09 — not H.264. Logic ported from PyanSofyan/V380Decoder (C#).
 *
 * Usage:
 *    node v380-mjpeg.js --id 12345678 --password '<your-password>' --mac aa:bb:cc:dd:ee:ff
 * Notes:
 *    --user defaults to the device id (this camera rejects "admin").
 */

const net = require('net');
const dgram = require('dgram');
const http = require('http');
const crypto = require('crypto');
const os = require('os');
const cp = require('child_process');

// ---- args ----------------------------------------------------------------
function arg(name, def) {
	const i = process.argv.indexOf('--' + name);
	return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const IP_HINT   = arg('ip', '');                    // optional; camera is auto-discovered by id
const DEVICE_ID = parseInt(arg('id'), 10);
const CAM_PORT  = parseInt(arg('port', '8800'), 10);
const USER      = arg('user', String(DEVICE_ID));   // this cam wants the id, not "admin"
const PASSWORD  = arg('password', '');
const HTTP_PORT = parseInt(arg('http', '8080'), 10);
const BCAST_ARG = arg('bcast', '');                 // extra broadcast addrs (comma-separated)
const MAC       = (arg('mac', '')).toLowerCase();   // optional: find camera by MAC (survives IP changes)
const DEBUG     = process.argv.includes('--debug');
let currentIp   = IP_HINT;                           // resolved IP (survives DHCP changes)

if (!DEVICE_ID || !PASSWORD) {
	console.error('usage: node v380-mjpeg.js --id <deviceId> --password <pw> [--ip <ip>] [--user <u>] [--port 8800] [--http 8080]');
	console.error('  (--ip is optional; the camera is auto-discovered by its device id and re-resolved on every reconnect)');
	process.exit(2);
}

// ---- V380 LAN discovery: broadcast NVDEVSEARCH^100 -> camera replies NVDEVRESULT^..^ip^..^devid
function discoverIp(deviceId, timeoutMs = 2500) {
	return new Promise((resolve) => {
		const s = dgram.createSocket({ type: 'udp4', reuseAddr: true });
		let found = null;
		s.on('error', () => { try { s.close(); } catch {} resolve(null); });
		s.on('message', (msg) => {
			const p = msg.toString('ascii').split('^');   // NVDEVRESULT^200^mac^ip^mask^gw^..^devid^..
			if (p[0] === 'NVDEVRESULT' && p.length >= 13 && (!deviceId || p[12] === String(deviceId))) found = p[3];
		});
		s.bind(() => {
			try { s.setBroadcast(true); } catch {}
			const cmd = Buffer.from('NVDEVSEARCH^100', 'ascii');
			const targets = [...new Set(['255.255.255.255', localBroadcast(), ...BCAST_ARG.split(',')].filter(Boolean))];
			const send = () => { for (const b of targets) { try { s.send(cmd, 10008, b); } catch {} } };
			send(); const iv = setInterval(send, 400);
			setTimeout(() => { clearInterval(iv); try { s.close(); } catch {} resolve(found); }, timeoutMs);
		});
	});
}
// Fallback discovery: find the camera's current IP by its MAC (hardware-stable).
function localIPv4() {
	for (const ifs of Object.values(os.networkInterfaces()))
		for (const i of ifs)
			if (i.family === 'IPv4' && !i.internal) return i.address;
	return null;
}
function localSubnet()    { const a = localIPv4(); if (!a) return null; const p = a.split('.'); return `${p[0]}.${p[1]}.${p[2]}.0/24`; }
function localBroadcast() { const a = localIPv4(); if (!a) return null; const p = a.split('.'); return `${p[0]}.${p[1]}.${p[2]}.255`; }
function macLookup(mac) {
	try {
		const out = cp.execSync('ip neigh', { timeout: 3000 }).toString();
		const line = out.split('\n').find((l) => l.toLowerCase().includes(mac));
		if (line) { const ip = line.split(/\s+/)[0]; if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip; }
	} catch {}
	return null;
}
function discoverByMac(mac) {
	if (!mac) return null;
	let ip = macLookup(mac);
	if (!ip) {
		const net = localSubnet();
		if (net) { try { cp.execSync(`nmap -sn -n ${net}`, { timeout: 20000, stdio: 'ignore' }); } catch {} ip = macLookup(mac); }
	}
	return ip;
}

const log = (...a) => console.error(...a);
const dbg = (...a) => { if (DEBUG) console.error(...a); };

// ---- AES helpers (AES-128-ECB, no padding) -------------------------------
function aesEcbEncrypt(key, data) {
	const c = crypto.createCipheriv('aes-128-ecb', key, null);
	c.setAutoPadding(false);
	return Buffer.concat([c.update(data), c.final()]);
}
function aesEcbDecrypt(key, data) {
	const d = crypto.createDecipheriv('aes-128-ecb', key, null);
	d.setAutoPadding(false);
	return Buffer.concat([d.update(data), d.final()]);
}

// Login password: pad(48) -> ECB(sk) -> ECB(rk); output = rk(16) || pad(48).
function generatePassword(pw) {
	const sk = Buffer.from('macrovideo+*#!^@', 'ascii'); // fixed 16-byte key
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const rk = Buffer.alloc(16);
	for (let i = 0; i < 16; i++) rk[i] = chars.charCodeAt((Math.random() * chars.length) | 0);
	let pad = Buffer.alloc(48);
	Buffer.from(pw, 'ascii').copy(pad, 0, 0, Math.min(pw.length, 48));
	pad = aesEcbEncrypt(sk, pad);
	pad = aesEcbEncrypt(rk, pad);
	const out = Buffer.alloc(64);
	rk.copy(out, 0);
	pad.copy(out, 16);
	return out;
}

// Session media key derived from the auth ticket.
let aesKey = Buffer.alloc(16);
function generateMediaKey(ticket) {
	aesKey = Buffer.alloc(16);
	aesKey.writeUInt32LE(ticket >>> 0, 0);
	aesKey.writeBigUInt64LE(0x618123462c14795cn, 4);
	aesKey.writeUInt32LE(0x82800df0 >>> 0, 12);
	dbg('[KEY]', aesKey.toString('hex'));
}

// Partial in-place decrypt: 4 AES blocks (64 bytes) out of every 80-byte window.
function decryptVideoFrame(data) {
	for (let off = 0; off + 64 <= data.length; off += 80) {
		const dec = aesEcbDecrypt(aesKey, data.subarray(off, off + 64));
		dec.copy(data, off);
	}
}

// ---- tiny socket read helper ---------------------------------------------
function readAtLeast(sock, n, timeoutMs) {
	return new Promise((resolve, reject) => {
		let buf = Buffer.alloc(0);
		const to = setTimeout(() => { cleanup(); reject(new Error('read timeout')); }, timeoutMs);
		function onData(d) {
			buf = Buffer.concat([buf, d]);
			if (buf.length >= n) { cleanup(); resolve(buf); }
		}
		function onErr(e) { cleanup(); reject(e); }
		function cleanup() { clearTimeout(to); sock.removeListener('data', onData); sock.removeListener('error', onErr); }
		sock.on('data', onData);
		sock.on('error', onErr);
	});
}
function connect(ip, port, timeoutMs) {
	return new Promise((resolve, reject) => {
		const s = net.connect({ host: ip, port });
		s.setNoDelay(true);
		const to = setTimeout(() => { s.destroy(); reject(new Error('connect timeout')); }, timeoutMs);
		s.once('connect', () => { clearTimeout(to); resolve(s); });
		s.once('error', (e) => { clearTimeout(to); reject(e); });
	});
}

// ---- protocol ------------------------------------------------------------
const state = { ticket: 0, session: 0, deviceVersion: 0, commVersion: 20, width: 0, height: 0 };

async function authenticate() {
	const s = await connect(currentIp, CAM_PORT, 5000);
	try {
		const encPw = generatePassword(PASSWORD);
		const cmd = Buffer.alloc(520);
		cmd.writeUInt32LE(1167, 0);
		cmd.writeUInt32LE(120, 4);
		cmd[8] = 31;
		cmd.writeUInt32LE(1, 9);
		cmd.writeUInt32LE(DEVICE_ID >>> 0, 13);
		Buffer.from(USER, 'ascii').copy(cmd, 49, 0, Math.min(USER.length, 32));
		encPw.copy(cmd, 81, 0, 64);
		s.write(cmd);

		const resp = await readAtLeast(s, 60, 5000);
		const respCmd = resp.readUInt32LE(0);
		if (respCmd !== 1168) throw new Error(`auth: unexpected cmd ${respCmd} (want 1168)`);
		const result = resp.readUInt32LE(4);
		if (result !== 1001) {
			const m = { 1011: 'invalid username', 1012: 'invalid password', 1018: 'invalid device id' }[result] || `result ${result}`;
			throw new Error(`auth failed: ${m}`);
		}
		state.deviceVersion = resp[12];
		state.ticket        = resp.readUInt32LE(13);
		state.session       = resp.readUInt32LE(17);
		log(`[AUTH] ok  ticket=${state.ticket} deviceVersion=${state.deviceVersion}`);
	} finally {
		s.destroy();
	}
}

async function streamLogin() {
	const s = await connect(currentIp, CAM_PORT, 5000);
	const cmd = Buffer.alloc(256);
	cmd.writeUInt32LE(301, 0);
	cmd.writeUInt32LE(DEVICE_ID >>> 0, 4);
	cmd.writeUInt32LE(0, 8);
	cmd.writeUInt16LE(20, 12);              // communication version
	cmd.writeUInt32LE(state.ticket >>> 0, 14);
	cmd.writeUInt32LE(4097, 22);            // audio on (4096=off)
	cmd.writeUInt32LE(1, 26);               // quality 1=HD
	s.write(cmd);

	const resp = await readAtLeast(s, 26, 5000);
	const respCmd = resp.readUInt32LE(0);
	if (respCmd !== 401) throw new Error(`streamLogin: unexpected cmd ${respCmd} (want 401)`);
	const result = resp.readInt32LE(4);
	if (result === -11 || result === -12) throw new Error(`streamLogin failed result=${result}`);
	state.commVersion = resp.readUInt16LE(8);
	state.width       = resp.readUInt32LE(10);
	state.height      = resp.readUInt32LE(14);
	log(`[STREAM] login ok  ${state.width}x${state.height} commVersion=${state.commVersion}`);
	if (state.deviceVersion > 30) generateMediaKey(state.ticket);

	// start stream
	const start = Buffer.alloc(256);
	start.writeUInt32LE(303, 0);
	start.writeUInt16LE(0x3001, 4);
	s.write(start);
	return s;
}

// ---- frame reassembly + decrypt -----------------------------------------
const VIDEO_TYPES = new Set([0x09, 0x00, 0x01, 0x28, 0x29]);
let latestJpeg = null;
let frameCount = 0;
let lastFrame = Date.now();
const clients = new Set(); // MJPEG http responses

function pushJpeg(jpeg) {
	latestJpeg = jpeg;
	frameCount++;
	lastFrame = Date.now();
	for (const res of clients) {
		try {
			res.write(`--v380frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${jpeg.length}\r\n\r\n`);
			res.write(jpeg);
			res.write('\r\n');
		} catch { /* client gone */ }
	}
}

function makeParser() {
	let acc = Buffer.alloc(0);
	let frags = [];
	let expectTotal = 0;
	return function onData(chunk) {
		acc = acc.length ? Buffer.concat([acc, chunk]) : chunk;
		while (acc.length >= 12) {
			if (acc[0] !== 0x7f) { acc = acc.subarray(1); continue; } // resync
			const type   = acc[1];
			const total  = acc.readUInt16LE(3);
			const cur    = acc.readUInt16LE(5);
			const payLen = acc.readUInt16LE(7);
			if (payLen === 0 || payLen > 20000 || total === 0 || cur >= total) { acc = acc.subarray(1); continue; }
			if (acc.length < 12 + payLen) break; // need more bytes
			const payload = acc.subarray(12, 12 + payLen);
			acc = acc.subarray(12 + payLen);

			if (!VIDEO_TYPES.has(type)) continue; // control/audio — ignore for video

			if (cur === 0 || total !== expectTotal) { frags = []; expectTotal = total; }
			frags.push(Buffer.from(payload));
			if (cur !== total - 1) continue;

			let full = Buffer.concat(frags);
			frags = [];
			if (full.length < 16) continue;
			const body = Buffer.from(full.subarray(16)); // strip inner 16-byte frame header
			if (state.deviceVersion > 30) decryptVideoFrame(body);
			if (body[0] === 0xff && body[1] === 0xd8) {   // JPEG SOI
				pushJpeg(body);
				if (frameCount === 1 || frameCount % 100 === 0) dbg(`[VIDEO] frame ${frameCount} (${body.length} bytes)`);
			} else {
				dbg(`[VIDEO] non-JPEG frame head=${body.subarray(0, 4).toString('hex')}`);
			}
		}
	};
}

// ---- run + reconnect loop ------------------------------------------------
let streamSock = null;
async function runOnce() {
	// (re)discover the camera's current IP — survives DHCP changes.
	// 1) V380 native discovery (by device id); 2) by MAC (if --mac given); 3) --ip hint.
	const ip = (await discoverIp(DEVICE_ID)) || discoverByMac(MAC) || IP_HINT;
	if (ip) {
		if (ip !== currentIp) log(`[DISCOVERY] camera ${DEVICE_ID} at ${ip}`);
		currentIp = ip;
	} else if (currentIp) log(`[DISCOVERY] no reply; using last-known ${currentIp}`);
	if (!currentIp) throw new Error(`camera ${DEVICE_ID} not found (native discovery + MAC + --ip all failed)`);
	await authenticate();
	streamSock = await streamLogin();
	const parser = makeParser();
	lastFrame = Date.now();
	await new Promise((resolve) => {
		let done = false;
		const finish = () => { if (done) return; done = true; clearInterval(wd); resolve(); };
		streamSock.on('data', parser);
		streamSock.on('error', (e) => { log('[STREAM] socket error:', e.message); finish(); });
		streamSock.on('close', () => { log('[STREAM] closed'); finish(); });
		// watchdog: the V380 can go silent on a live socket (idle/single-session takeover) — force reconnect
		const wd = setInterval(() => {
			if (Date.now() - lastFrame > 8000) { log('[STREAM] no frames for 8s — reconnecting'); try { streamSock.destroy(); } catch {} finish(); }
		}, 2000);
	});
}
async function runForever() {
	for (;;) {
		try { await runOnce(); }
		catch (e) { log('[ERR]', e.message); }
		try { streamSock && streamSock.destroy(); } catch {}
		log('[STREAM] reconnecting in 3s...');
		await new Promise((r) => setTimeout(r, 3000));
	}
}

// ---- HTTP server ---------------------------------------------------------
const PAGE = `<!doctype html><meta charset=utf-8><title>V380 ${DEVICE_ID}</title>
<style>body{margin:0;background:#111;color:#ccc;font:14px system-ui;text-align:center}
img{max-width:100%;height:auto}h1{font-size:14px;font-weight:400;padding:8px;margin:0}</style>
<h1>V380 camera ${DEVICE_ID} (auto-discovered) — live MJPEG</h1>
<img src="/stream" alt="stream">`;

http.createServer((req, res) => {
	if (req.url === '/' || req.url === '/index.html') {
		res.writeHead(200, { 'Content-Type': 'text/html' });
		res.end(PAGE);
	} else if (req.url === '/snapshot' || req.url === '/frame.jpg') {
		if (!latestJpeg) { res.writeHead(503); res.end('no frame yet'); return; }
		res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': latestJpeg.length, 'Cache-Control': 'no-store' });
		res.end(latestJpeg);
	} else if (req.url === '/stream') {
		res.writeHead(200, {
			'Content-Type': 'multipart/x-mixed-replace; boundary=v380frame',
			'Cache-Control': 'no-store', 'Connection': 'close', 'Pragma': 'no-cache',
		});
		clients.add(res);
		if (latestJpeg) pushJpeg.call(null, latestJpeg); // prime with current frame
		req.on('close', () => clients.delete(res));
	} else {
		res.writeHead(404); res.end('not found');
	}
}).listen(HTTP_PORT, () => {
	log(`[HTTP] serving on http://0.0.0.0:${HTTP_PORT}/  (snapshot: /snapshot, mjpeg: /stream)`);
});

runForever();
