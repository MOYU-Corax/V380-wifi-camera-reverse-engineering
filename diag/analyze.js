// Offline analyzer for a v380-mjpeg.js --dump capture.
// Usage: node diag/analyze.js diag/stream.bin
'use strict';
const fs = require('fs');

const buf = fs.readFileSync(process.argv[2] || 'diag/stream.bin');
const VIDEO_TYPES = new Set([0x09, 0x00, 0x01, 0x28, 0x29]);

const typeStats = {};
const frames = []; // complete reassembled video frames
let acc = Buffer.alloc(0);
let off = 0;
let frags = [], expectTotal = 0, curType = 0;
let syncErrs = 0, badHdrs = 0, incomplete = 0;

while (off < buf.length) {
	if (buf[off] !== 0x7f) { syncErrs++; off++; continue; }
	if (buf.length - off < 12) break;
	const type = buf[off + 1];
	const total = buf.readUInt16LE(off + 3);
	const cur = buf.readUInt16LE(off + 5);
	const payLen = buf.readUInt16LE(off + 7);
	if (payLen === 0 || payLen > 20000 || total === 0 || cur >= total) { badHdrs++; off++; continue; }
	if (buf.length - off < 12 + payLen) { incomplete++; break; }
	const payload = buf.subarray(off + 12, off + 12 + payLen);
	off += 12 + payLen;

	const t = `0x${type.toString(16)}`;
	typeStats[t] = typeStats[t] || { count: 0, bytes: 0, sizes: [] };
	typeStats[t].count++; typeStats[t].bytes += payLen; typeStats[t].sizes.push(payLen);

	if (!VIDEO_TYPES.has(type)) continue;
	if (cur === 0 || total !== expectTotal) { frags = []; expectTotal = total; curType = type; }
	frags.push(Buffer.from(payload));
	if (cur !== total - 1) continue;
	const full = Buffer.concat(frags); frags = [];
	if (full.length < 16) continue;
	frames.push({ type: curType, full });
}

console.log(`capture ${buf.length}B  syncErrors=${syncErrs} badHdrs=${badHdrs} truncatedTail=${incomplete}`);
console.log(`\nfragment types:`);
for (const [t, s] of Object.entries(typeStats)) {
	s.sizes.sort((a, b) => a - b);
	console.log(`  ${t}: ${s.count} frags, ${s.bytes}B, size min/med/max = ${s.sizes[0]}/${s.sizes[s.sizes.length >> 1]}/${s.sizes[s.sizes.length - 1]}`);
}

console.log(`\nreassembled video frames: ${frames.length}`);
const nalCount = {};
for (let i = 0; i < Math.min(frames.length, 12); i++) {
	const f = frames[i];
	const fh = {
		frameId: f.full.readUInt32LE(0),
		frameType: f.full.readUInt16LE(4),
		frameRate: f.full.readUInt16LE(6),
		ts: f.full.readBigUInt64LE(8),
	};
	const body = f.full.subarray(16);
	// list Annex B NAL headers in the first 64 bytes
	const nals = [];
	for (let j = 0; j + 5 <= Math.min(body.length, 96); j++) {
		if (body[j] === 0 && body[j + 1] === 0 && body[j + 2] === 0 && body[j + 3] === 1) nals.push(`nal[${body[j + 4]}]`);
	}
	for (const n of nals) nalCount[n] = (nalCount[n] || 0) + 1;
	console.log(`  #${i} type=0x${f.type.toString(16)} ${body.length}B  inner{id=${fh.frameId} type=${fh.frameType} rate=${fh.frameRate} ts=${fh.ts}}  nals=${nals.join(' ')}`);
}
console.log(`\nNAL header bytes seen in first frames: ${JSON.stringify(nalCount)}`);

// samples for inspection
const firstVideo = frames.find((f) => f.type === 0x00);
if (firstVideo) fs.writeFileSync('diag/frame-iframe.h264', firstVideo.full.subarray(16));
const firstP = frames.find((f) => f.type === 0x01);
if (firstP) fs.writeFileSync('diag/frame-pframe.h264', firstP.full.subarray(16));

// 0x16 channel: dump a few payloads raw
const t16 = [];
acc = Buffer.alloc(0); off = 0;
while (off < buf.length) {
	if (buf[off] !== 0x7f) { off++; continue; }
	if (buf.length - off < 12) break;
	const type = buf[off + 1];
	const total = buf.readUInt16LE(off + 3);
	const cur = buf.readUInt16LE(off + 5);
	const payLen = buf.readUInt16LE(off + 7);
	if (payLen === 0 || payLen > 20000 || total === 0 || cur >= total) { off++; continue; }
	if (buf.length - off < 12 + payLen) break;
	if (type === 0x16 && cur === total - 1) t16.push(buf.subarray(off + 12, off + 12 + payLen));
	off += 12 + payLen;
	if (t16.length >= 3) break;
}
for (let i = 0; i < t16.length; i++) {
	console.log(`\n0x16 sample ${i}: ${t16[i].length}B head=${t16[i].subarray(0, 24).toString('hex')}`);
	fs.writeFileSync(`diag/t16-${i}.bin`, t16[i]);
}
