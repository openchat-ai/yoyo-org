'use strict';
// yoyo-blob-to-tir.js — PoC: convert yoyo.ty's data.blob blocks into raw.bytes lines.
// This proves that blob content can live in TIR form (raw.bytes emits bytes verbatim).
// It does NOT translate x86 -> TIR intrinsics, but it's a stepping stone.
//
// Strategy:
//   - Parse yoyo.ty
//   - For each data.blob op, replace with N lines of raw.bytes (chunks of ~256 hex chars)
//   - Compare compiled output byte-for-byte against baseline

const fs = require('fs');
const path = require('path');
const yoyo = require('../src/yoyo.js');

const SRC = path.join(__dirname, '..', 'projects', 'yoyo.ty');
const OUT = path.join(__dirname, '..', 'projects', 'yoyo-tir-blob.ty');
const CHUNK = 256;

function main() {
  const text = fs.readFileSync(SRC, 'utf8');
  const prog = yoyo.analyze(yoyo.parse(text));
  const blobs = prog.blobs || [];

  console.log('found ' + blobs.length + ' data blobs:');
  for (const b of blobs) {
    console.log('  off=0x' + b.off.toString(16).padStart(4, '0') +
                ' (' + b.off.toString(16) + ')  bytes=' + b.data.length);
  }

  // Build new .ty by replacing data.blob ops with raw.bytes chunks.
  const out = [];
  const tokens = yoyo.parse(text);
  let bIdx = 0;
  for (const t of tokens) {
    if (t.op === 0x13) {
      const b = blobs[bIdx++];
      const hex = b.data.toString('hex');
      // Emit in chunks of CHUNK hex chars
      const total = hex.length;
      console.log('replacing data.blob 0x' + b.off.toString(16) +
                  ' (' + total + ' hex chars = ' + (total/2) + ' bytes) with raw.bytes chunks');
      // Emit the offset as a comment header so handlers can find it
      out.push('; (replaced data.blob at offset 0x' + b.off.toString(16) +
               ', ' + (total/2) + ' bytes; emit at code offset ' + bIdx + ')');
      for (let i = 0; i < hex.length; i += CHUNK) {
        out.push('  raw.bytes ' + hex.slice(i, i + CHUNK));
      }
      out.push('');
    } else if (t.op === 0x12) {
      // string.def — already TIR-compatible, pass through
      const arg = t.args[1] || (t.args[0] && t.args[0].t === 's' ? t.args[0] : null);
      const hex = arg && arg.raw ? arg.raw.toString('hex') : '';
      out.push('  string.def s' + hex);
    } else {
      // Pass through unchanged
      const args = (t.args || []).map(a => a && (a.t === 's' || a.t === 'h' ? a.v : (a.v != null ? a.v.toString(16) : '')));
      out.push('  ' + t.op.toString(16).padStart(2, '0') + (args.length ? ' ' + args.join(' ') : ''));
    }
  }

  fs.writeFileSync(OUT, out.join('\n') + '\n', 'utf8');
  console.log('wrote ' + OUT + ' (' + out.length + ' lines)');
}

main();