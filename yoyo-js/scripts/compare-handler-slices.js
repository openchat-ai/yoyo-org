'use strict';

/**
 * Compare Node-emitted handler machine code vs scan-emitted gen2 .text slices.
 *
 * Usage:
 *   node scripts/compare-handler-slices.js
 *   node scripts/compare-handler-slices.js --gen2 build/gen2.elf
 *   node scripts/compare-handler-slices.js --gen2 /tmp/gen2.elf --limit 20
 */

const fs = require('fs');
const path = require('path');
const { parse, analyze } = require('../src/yoyo.js');
const { handlerFileOrder, readHandlerLayout } = require('../src/blob-handlers.js');
const { ELF_TEXT_FILE_OFF } = require('../src/platform-config.js');

function parseArgs(argv) {
  const opts = { gen2: '/tmp/gen2.elf', limit: 0, src: 'projects/yoyo.ty' };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--gen2' && argv[i + 1]) opts.gen2 = argv[++i];
    else if (argv[i] === '--limit' && argv[i + 1]) opts.limit = parseInt(argv[++i], 10);
    else if (argv[i] === '--src' && argv[i + 1]) opts.src = argv[++i];
  }
  return opts;
}

function nodeHandlerSlices(src) {
  const prog = analyze(parse(src));
  const E = require('../src/encode-x64.js');
  const { makeLinuxEmit } = require('../src/linux-runtime.js');
  const { ELF, BASE } = require('../src/elf-builder.js');

  const codeElf = new ELF();
  codeElf.setCode(Buffer.alloc(0x8000, 0x90));
  codeElf.setData(Buffer.alloc(1, 0));
  codeElf.build();
  const dr = codeElf.dataRVA;

  const code = new E.Buf();
  code.labels = {};
  code.fixups = [];
  code.dataFixups = [];
  code.label = n => { code.labels[n] = code.tell(); };
  code.jmp32 = n => { E.jmp_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n }); };
  code.jcc32 = (cc, n) => { E.jcc32(code, cc, 0); code.fixups.push({ p: code.tell() - 4, n }); };
  const linux = makeLinuxEmit(code, dr, [], []);
  while (code.tell() < 128) code.u8(0x90);

  function emitLinux(op) {
    const a = op.args, o = op.op;
    if (o === 0x30) linux.stSet(a[0].v, a[1] ? a[1].v : 0);
    else if (o === 0x40) code.label('H' + a[0].v);
    else if (o === 0x41) { E.call_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n: 'H' + a[0].v }); }
    else if (o === 0x50) linux.emitLoadFile(a[0].v, a[1].v);
    else if (o === 0x51) linux.emitWriteFile(a[0].v, a[1].v, a[2] ? a[2].v : 0);
    else if (o === 0x60) { linux.stGet(0, a[1].v); linux.stPut(a[0].v, 0); }
    else if (o === 0x61) { linux.stGet(0, a[0].v); E.add_ri(code, 0, a[1].v); linux.stPut(a[0].v, 0); }
    else if (o === 0x62) { linux.stGet(0, a[0].v); E.sub_ri(code, 0, a[1].v); linux.stPut(a[0].v, 0); }
    else if (o === 0x63) { linux.stGet(0, a[0].v); linux.stGet(2, a[1].v); E.imul_rr(code, 0, 2); linux.stPut(a[0].v, 0); }
    else if (o === 0x66) { linux.stGet(0, a[0].v); E.add_ri(code, 0, 1); linux.stPut(a[0].v, 0); }
    else if (o === 0x68) { linux.stGet(0, a[0].v); linux.stGet(2, a[1].v); E.add_rr(code, 0, 2); linux.stPut(a[0].v, 0); }
    else if (o === 0x69) { linux.stGet(0, a[0].v); linux.stGet(2, a[1].v); E.sub_rr(code, 0, 2); linux.stPut(a[0].v, 0); }
    else if (o === 0x65) { linux.stGet(0, a[0].v); linux.stGet(2, a[1].v); E.cmp_rr(code, 0, 2); }
    else if (o === 0x70) code.jmp32('H' + a[0].v);
    else if (o === 0x71) code.jcc32(0, 'H' + a[0].v);
    else if (o === 0x78) code.jcc32(7, 'H' + a[0].v);
    else if (o === 0x55) { linux.stGet(2, a[0].v); linux.stGet(0, a[1].v); code.u8(0x89); code.u8(0x02); }
    else if (o === 0x57) { linux.stGet(2, a[0].v); linux.stGet(8, a[1].v); E.add_rr(code, 2, 8); linux.stGet(0, a[2].v); code.u8(0x88); code.u8(0x02); }
    else if (o === 0xFF) E.ret(code);
    else if (o === 0x20) linux.emitAlloc(a[0].v, a[1].v);
    else if (o === 0xA0) {
      const hex = a[0] ? a[0].v : '';
      for (let i = 0; i < hex.length; i += 2) {
        const b = parseInt(hex.substr(i, 2), 16);
        if (!isNaN(b)) code.u8(b);
      }
    }
  }

  for (const op of prog.top) emitLinux(op);
  for (const h of Object.keys(prog.handlers).map(Number).sort((a, b) => a - b)) {
    code.label('H' + h);
    for (const op of prog.handlers[h]) emitLinux(op);
    E.ret(code);
  }
  for (const f of code.fixups) {
    const t = code.labels[f.n];
    if (t !== undefined) code.b.writeInt32LE(t - (f.p + 4), f.p);
  }

  return { labels: code.labels, code: code.b.slice(128, code.tell()) };
}

function sliceFor(labels, code, hh) {
  const key = 'H' + hh;
  const start = labels[key];
  if (start === undefined) return null;
  const sorted = Object.keys(labels).map(k => ({ k, o: labels[k] })).sort((a, b) => a.o - b.o);
  const idx = sorted.findIndex(x => x.k === key);
  const end = idx + 1 < sorted.length ? sorted[idx + 1].o : code.length;
  return { start, end, buf: code.slice(start, end) };
}

function findInText(text, needle) {
  if (!needle || needle.length < 4) return -1;
  const head = needle.slice(0, Math.min(8, needle.length));
  for (let i = 0; i <= text.length - head.length; i++) {
    if (text.slice(i, i + head.length).equals(head)) return i;
  }
  return -1;
}

function byteDiff(a, b) {
  const n = Math.min(a.length, b.length);
  let d = 0;
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) d++;
  d += Math.abs(a.length - b.length);
  return d;
}

function main() {
  const opts = parseArgs(process.argv);
  const root = path.join(__dirname, '..');
  const srcPath = path.isAbsolute(opts.src) ? opts.src : path.join(root, opts.src);
  const src = fs.readFileSync(srcPath, 'utf8');

  const { labels, code } = nodeHandlerSlices(src);
  const order = handlerFileOrder(src);

  if (!fs.existsSync(opts.gen2)) {
    console.log('gen2 not found:', opts.gen2);
    console.log('Node reference handlers:', order.length, '(file order)');
    console.log('Run bootstrap on Linux/WSL, then:');
    console.log('  node scripts/compare-handler-slices.js --gen2 /path/to/gen2.elf');
    process.exit(0);
  }

  const gen2Buf = fs.readFileSync(opts.gen2);
  const g2text = gen2Buf.slice(ELF_TEXT_FILE_OFF, ELF_TEXT_FILE_OFF + 0x8000);
  let layout;
  try {
    layout = readHandlerLayout(opts.gen2);
  } catch (e) {
    console.log('readHandlerLayout failed:', e.message);
    layout = null;
  }

  let mismatches = 0;
  let compared = 0;
  const ids = opts.limit > 0 ? order.slice(0, opts.limit) : order;

  console.log('compare-handler-slices');
  console.log('  src:', srcPath);
  console.log('  gen2:', opts.gen2);
  console.log('  handlers (file order):', order.length);
  if (layout) console.log('  gen2 codeEnd:', layout.codeEnd, '(0x' + layout.codeEnd.toString(16) + ')');
  console.log('');

  for (const id of ids) {
    const ref = sliceFor(labels, code, id);
    if (!ref) {
      console.log('H_' + id.toString(16), 'missing in Node reference');
      continue;
    }
    compared++;

    let g2slice = null;
    let g2off = -1;
    if (layout && layout.table[id] > 0) {
      const nextIdx = order.indexOf(id) + 1;
      const end = nextIdx < order.length && layout.table[order[nextIdx]] > 0
        ? layout.table[order[nextIdx]]
        : layout.codeEnd;
      if (end > layout.table[id]) {
        g2off = layout.table[id];
        g2slice = g2text.slice(g2off, end);
      }
    }
    if (!g2slice || g2slice.length === 0) {
      g2off = findInText(g2text, ref.buf);
      if (g2off >= 0) g2slice = g2text.slice(g2off, g2off + ref.buf.length);
    }

    if (!g2slice || g2slice.length === 0) {
      console.log('H_' + id.toString(16).padStart(2, '0'),
        'node@0x' + ref.start.toString(16), 'len', ref.buf.length, 'gen2: NOT FOUND');
      mismatches++;
      continue;
    }

    const diffs = byteDiff(ref.buf, g2slice);
    const tag = diffs === 0 ? 'MATCH' : 'DIFF ' + diffs;
    console.log('H_' + id.toString(16).padStart(2, '0'),
      'node@0x' + ref.start.toString(16), 'len', ref.buf.length,
      'gen2@0x' + g2off.toString(16), 'len', g2slice.length, tag);
    if (diffs !== 0 && diffs <= 32) {
      console.log('  node:', ref.buf.slice(0, 16).toString('hex'));
      console.log('  gen2:', g2slice.slice(0, 16).toString('hex'));
    }
    if (diffs !== 0) mismatches++;
  }

  console.log('');
  console.log('summary: compared', compared, 'mismatches', mismatches);
  process.exit(mismatches > 0 ? 1 : 0);
}

main();
