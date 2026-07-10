'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { ELF_TEXT_FILE_OFF, PE_TEXT_FILE_OFF } = require('./platform-config.js');

const HANDLER_MAP_OFF = 0xFE00;
const PE_IMPORT_PREFIX = 0x400;
const DATA_FILE_OFF = 0x8400 + PE_IMPORT_PREFIX; // PE .rdata file off + import metadata
/** Windows scan blobs must not replace yoyo-gen snapshot control-flow handlers. */
const WIN_SCAN_BLOB_SKIP = new Set([0xcb, 0xcc, 0x42, 0x8d, 0xe0]);

function handlerFileOrder(src) {
  const order = [];
  const seen = new Set();
  for (const line of src.split('\n')) {
    const trimmed = line.replace(/;.*$/, '').trim();
    let m = trimmed.match(/^40\s+([0-9a-fA-F]+)$/);
    if (!m) m = trimmed.match(/^label\s+H_([0-9a-fA-F]+)$/i);
    if (!m) continue;
    const hh = parseInt(m[1], 16);
    if (!seen.has(hh)) {
      seen.add(hh);
      order.push(hh);
    }
  }
  return order;
}

function parseSectionEnds(src) {
  const endsWithFF = new Set();
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].replace(/;.*$/, '').trim();
    const m = trimmed.match(/^40\s+([0-9a-fA-F]+)$/);
    if (!m) continue;
    const hh = parseInt(m[1], 16);
    for (let j = i + 1; j < lines.length; j++) {
      const body = lines[j].replace(/;.*$/, '').trim();
      if (/^ff$/i.test(body)) {
        endsWithFF.add(hh);
        break;
      }
      if (/^40\s+[0-9a-fA-F]+$/.test(body)) break;
    }
  }
  return endsWithFF;
}

function parseBlobRefOffsets(src) {
  const refs = new Map();
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const cm = lines[i].match(/; blob \d+ bytes from \w+ reference @0x([0-9a-fA-F]+)/i);
    if (!cm) continue;
    for (let j = i - 1; j >= 0; j--) {
      const hm = lines[j].replace(/;.*$/, '').trim().match(/^40\s+([0-9a-fA-F]+)$/);
      if (hm) {
        refs.set(parseInt(hm[1], 16), parseInt(cm[1], 16));
        break;
      }
    }
  }
  return refs;
}

function a1ByteLines(buf) {
  const lines = [];
  for (let i = 0; i < buf.length; i++) {
    lines.push('a1 ' + buf[i].toString(16).padStart(2, '0'));
  }
  return lines;
}

// ── Instruction-boundary-aware x64 decoder (yoyo emit subset) ──────────────
// A naive byte-scan for e8/e9 cannot tell a real call/jmp opcode from an
// e8/e9 byte living inside an immediate (movabs), a RIP displacement, or a
// ModRM byte (e.g. `48 83 e8 XX` = sub rax,imm8). Relocating such a data byte
// corrupts the instruction — the root cause of the Windows M2→M3 crash.
// This decoder computes each instruction's true length so relocation only
// ever touches the rel32/disp32 field of a genuine branch/RIP reference.
// Ported from the yoyo-decoder tool's src/linscan.rs.
function _modrmLen(b, p) {
  if (p >= b.length) return 1;
  const modrm = b[p];
  const md = modrm >> 6;
  const rm = modrm & 7;
  if (md === 3) return 1;
  let len = 1;
  let baseDisp32 = false;
  if (rm === 4) { // SIB byte
    len += 1;
    if (md === 0 && p + 1 < b.length && (b[p + 1] & 7) === 5) baseDisp32 = true;
  }
  if (md === 0) { if (rm === 5 || baseDisp32) len += 4; } // disp32 (RIP when rm==5)
  else if (md === 1) len += 1;                            // disp8
  else if (md === 2) len += 4;                            // disp32
  return len;
}

// Decode one instruction at offset i. Returns { len, relOff } where relOff is
// the byte offset of a rel32/disp32 field to relocate, or -1 if the
// instruction has no relocatable PC-relative field. On an unrecognized
// opcode, returns len>=1 with relOff -1 so the caller advances safely.
function decodeInstr(b, i) {
  const start = i;
  let p = i;
  while (p < b.length && (b[p] === 0xF3 || b[p] === 0xF2 || b[p] === 0x66)) p++; // legacy prefixes
  let rexW = false;
  if (p < b.length && (b[p] & 0xF0) === 0x40) { rexW = (b[p] & 0x08) !== 0; p++; } // REX
  if (p >= b.length) return { len: Math.max(1, p - start), relOff: -1 };
  const op = b[p]; p++;
  const none = len => ({ len: Math.max(1, len), relOff: -1 });

  if (op === 0x90 || op === 0xC3) return none(p - start);          // nop / ret
  if (op === 0xE8 || op === 0xE9) return { len: p - start + 4, relOff: p }; // call/jmp rel32
  if (op === 0xEB) return none(p - start + 1);                    // jmp rel8
  if (op >= 0x70 && op <= 0x7F) return none(p - start + 1);       // jcc rel8
  if (op >= 0xB8 && op <= 0xBF) return none(p - start + (rexW ? 8 : 4)); // mov r, imm
  if (op >= 0x50 && op <= 0x5F) return none(p - start);           // push/pop r
  if (op === 0x0F) {
    if (p >= b.length) return none(p - start);
    const op2 = b[p]; p++;
    if (op2 >= 0x80 && op2 <= 0x8F) return { len: p - start + 4, relOff: p }; // jcc rel32
    if (op2 === 0x05) return none(p - start);                     // syscall
    if (op2 === 0xAF || op2 === 0xB6 || op2 === 0xB7 || op2 === 0xBE || op2 === 0xBF)
      return none(p - start + _modrmLen(b, p));                   // imul / movzx / movsx
    return none(p - start);                                       // unknown 0F
  }
  if (op === 0x89 || op === 0x8B || op === 0x01 || op === 0x03 || op === 0x29 ||
      op === 0x2B || op === 0x39 || op === 0x3B || op === 0x31 || op === 0x09 ||
      op === 0x21 || op === 0x85 || op === 0x88 || op === 0x8A)
    return none(p - start + _modrmLen(b, p));                     // ALU/mov reg forms
  if (op === 0x8D) {                                              // lea (maybe RIP-relative)
    const ml = _modrmLen(b, p);
    const modrm = p < b.length ? b[p] : 0;
    const riprel = (modrm >> 6) === 0 && (modrm & 7) === 5;
    return riprel ? { len: p - start + ml, relOff: p + 1 } : none(p - start + ml);
  }
  if (op === 0x83 || op === 0xC6) return none(p - start + _modrmLen(b, p) + 1); // + imm8
  if (op === 0x81 || op === 0xC7) return none(p - start + _modrmLen(b, p) + 4); // + imm32
  if (op === 0xA4) return none(p - start);                        // movsb (rep prefix handled)
  if (op === 0xFF) {                                              // group: call/jmp [rip] etc.
    if (p >= b.length) return none(p - start);
    const modrm = b[p];
    const reg = (modrm >> 3) & 7;
    const riprel = (modrm >> 6) === 0 && (modrm & 7) === 5;
    const ml = _modrmLen(b, p);
    if ((reg === 2 || reg === 4) && riprel) return { len: p - start + ml, relOff: p + 1 };
    return none(p - start + ml);
  }
  return none(p - start);                                         // unknown opcode
}

/**
 * Relocate PC-relative rel32/disp32 fields when moving a code slice from
 * oldBase to newBase. Uses instruction-boundary decoding so only genuine
 * call/jmp/jcc/call[rip]/jmp[rip]/lea[rip] fields are patched — never a data
 * byte that merely happens to equal e8/e9.
 */
function relocateSlice(buf, oldBase, newBase) {
  const delta = newBase - oldBase;
  const out = Buffer.from(buf);
  let i = 0;
  while (i < out.length) {
    const { len, relOff } = decodeInstr(out, i);
    if (relOff >= 0 && relOff + 4 <= out.length) {
      let checkByte = out[i];
      if ((checkByte & 0xF0) === 0x40) checkByte = out[i + 1]; // skip REX
      const isInternal = (checkByte === 0xE8 || checkByte === 0xE9 || checkByte === 0x0F);
      if (isInternal) {
        // E8/E9/0F8x target other handlers within the same block;
        // caller + callee shift together, rel32 stays correct.
      } else {
        // FF15/FF25 (IAT) and LEA rip (data) target fixed external addresses.
        out.writeInt32LE(out.readInt32LE(relOff) - delta, relOff);
      }
    }
    i += len > 0 ? len : 1;
  }
  return out;
}

function buildNewHandlerLabels(order, metaRefOffset, metaSizes, blobSizes) {
  const first = order[0];
  const handlersStart = metaRefOffset.get(first) ?? 0;
  const newLabels = new Map();
  let pos = handlersStart;
  for (const h of order) {
    newLabels.set('H' + h, pos);
    const size = blobSizes.has(h) ? blobSizes.get(h) : (metaSizes.get(h) || 0);
    pos += size + 1;
  }
  return newLabels;
}

function mapAbsOffset(oldAbs, order, metaRefOffset, actualRefOffset, metaSizes) {
  const first = order[0];
  const firstMeta = metaRefOffset.get(first);
  if (firstMeta !== undefined && oldAbs < firstMeta) {
    const firstActual = actualRefOffset.get(first);
    if (firstActual !== undefined) return oldAbs + (firstActual - firstMeta);
    return oldAbs;
  }
  for (const h of order) {
    const mStart = metaRefOffset.get(h);
    const mSize = metaSizes.get(h) || 0;
    if (mStart === undefined) continue;
    if (oldAbs >= mStart && oldAbs < mStart + mSize) {
      const nStart = actualRefOffset.get(h);
      if (nStart === undefined) {
        throw new Error(`blob relocate: no actual offset for handler H_${h.toString(16)} (ref @0x${oldAbs.toString(16)})`);
      }
      return nStart + (oldAbs - mStart);
    }
  }
  return oldAbs;
}

function relocateSliceWithLayout(buf, metaBase, newBase, order, metaRefOffset, actualRefOffset, metaSizes) {
  const out = Buffer.from(buf);
  let i = 0;
  while (i < out.length) {
    let instrLen = 0;
    let relOff = -1;
    // Layout-relocated instructions (unprefixed in yoyo emit): call/jmp rel32,
    // jcc rel32, call/jmp [rip]. Detected at the true instruction start.
    if (i + 5 <= out.length && (out[i] === 0xe8 || out[i] === 0xe9)) {
      instrLen = 5; relOff = i + 1;
    } else if (i + 6 <= out.length && out[i] === 0x0f && out[i + 1] >= 0x80 && out[i + 1] <= 0x8f) {
      instrLen = 6; relOff = i + 2;
    } else if (i + 6 <= out.length && out[i] === 0xff && (out[i + 1] === 0x15 || out[i + 1] === 0x25)) {
      instrLen = 6; relOff = i + 2;
    }
    if (relOff >= 0) {
      const oldRel = out.readInt32LE(relOff);
      const oldAbs = metaBase + i + instrLen + oldRel;
      const newAbs = mapAbsOffset(oldAbs, order, metaRefOffset, actualRefOffset, metaSizes);
      out.writeInt32LE(newAbs - (newBase + i + instrLen), relOff);
      i += instrLen;
    } else {
      // Not a layout reloc — advance by the true instruction length so an
      // e8/e9 data byte inside an immediate/ModRM/disp is never mis-read.
      const d = decodeInstr(out, i);
      i += d.len > 0 ? d.len : 1;
    }
  }
  return out;
}

function isBlobHandlerOps(ops) {
  return ops.length > 0 && ops.every(op => op.op === 0xA1 || op.op === 0xFF);
}

function blobRawFromOps(ops) {
  return Buffer.from(ops.filter(op => op.op === 0xA1).map(op => op.args[0].v & 0xff));
}

function parseBlobHandlers(src) {
  const blobSizes = new Map();
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const cm = lines[i].match(/; blob (\d+) bytes from \w+ reference/i);
    if (!cm) continue;
    let hh = null;
    for (let j = i - 1; j >= 0; j--) {
      const hm = lines[j].replace(/;.*$/, '').trim().match(/^40\s+([0-9a-fA-F]+)$/);
      if (hm) { hh = parseInt(hm[1], 16); break; }
    }
    if (hh === null) continue;
    let bytes = 0;
    for (let j = i + 1; j < lines.length; j++) {
      const body = lines[j].replace(/;.*$/, '').trim();
      if (/^ff$/i.test(body)) break;
      if (/^40\s+[0-9a-fA-F]+$/.test(body)) break;
      if (/^a1\s+[0-9a-fA-F]+$/i.test(body)) bytes++;
    }
    blobSizes.set(hh, bytes);
  }
  return blobSizes;
}

function writeWinBlobLayout(rootDir, layout) {
  const outPath = path.join(rootDir, 'build', 'win-blob-layout.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const payload = {
    order: layout.order,
    metaRefOffset: Object.fromEntries([...layout.metaRefOffset.entries()].map(([k, v]) => ['0x' + k.toString(16), v])),
    metaSizes: Object.fromEntries([...layout.metaSizes.entries()].map(([k, v]) => ['0x' + k.toString(16), v])),
  };
  fs.writeFileSync(outPath, JSON.stringify(payload));
}

function readWinBlobLayout(rootDir) {
  const p = path.join(rootDir, 'build', 'win-blob-layout.json');
  if (!fs.existsSync(p)) return null;
  const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  const parseMap = obj => {
    const m = new Map();
    for (const [k, v] of Object.entries(obj || {})) m.set(parseInt(k, 16), v);
    return m;
  };
  return {
    order: raw.order || [],
    metaRefOffset: parseMap(raw.metaRefOffset),
    metaSizes: parseMap(raw.metaSizes),
  };
}

function readHandlerLayout(elfPath) {
  const b = fs.readFileSync(elfPath);
  const mapOff = DATA_FILE_OFF + HANDLER_MAP_OFF;
  const table = [];
  for (let i = 0; i < 256; i++) {
    table.push(b.readUInt32LE(mapOff + i * 4));
  }
  const codeEnd = b.readUInt32LE(mapOff + 0x400);
  return { table, codeEnd };
}

function captureScanReferenceElf(src, rootDir) {
  const yoyoTy = path.join(rootDir, 'projects', 'yoyo.ty');
  const yoyoJs = path.join(rootDir, 'src', 'yoyo.js');
  const gen1 = path.join(rootDir, 'build', 'yoyo');
  const inputKy = path.join(rootDir, 'input.ky');
  const outputElf = path.join(rootDir, 'output');

  fs.writeFileSync(yoyoTy, src);
  execSync(`node "${yoyoJs}" --target=linux "${yoyoTy}" "${gen1}"`, { cwd: rootDir, stdio: 'pipe' });
  fs.writeFileSync(inputKy, src);
  execSync(`"${gen1}"`, { cwd: rootDir, stdio: 'pipe' });
  if (!fs.existsSync(outputElf)) throw new Error('reference compile produced no output');
  return outputElf;
}

function captureScanReferenceExe(src, rootDir, target) {
  target = (target || process.env.YOYO_TARGET || 'linux').toLowerCase();
  if (target === 'win') return captureScanReferencePe(src, rootDir);
  return captureScanReferenceElf(src, rootDir);
}

function captureScanReferencePe(src, rootDir) {
  const yoyoTy = path.join(rootDir, 'projects', 'yoyo.ty');
  const yoyoJs = path.join(rootDir, 'src', 'yoyo.js');
  const gen1 = path.join(rootDir, 'build', 'yoyo.exe');
  const inputKy = path.join(rootDir, 'input.ky');
  const outputExe = path.join(rootDir, 'output.exe');

  fs.writeFileSync(yoyoTy, src);
  execSync(`node "${yoyoJs}" --target=win "${yoyoTy}" "${gen1}"`, { cwd: rootDir, stdio: 'pipe' });
  fs.writeFileSync(inputKy, src);
  execSync(`"${gen1}"`, { cwd: rootDir, stdio: 'pipe' });
  if (!fs.existsSync(outputExe)) throw new Error('reference compile produced no output.exe');
  return outputExe;
}

function handlerSliceEnd(table, codeEnd, hh) {
  const start = table[hh];
  if (!start) return 0;
  let end = codeEnd;
  for (let i = 0; i < 256; i++) {
    const off = table[i];
    if (off > start && off < end) end = off;
  }
  return end;
}

function sectionHandlersFromSource(src, table) {
  const { parse, analyze } = require('./yoyo.js');
  const inProg = new Set(Object.keys(analyze(parse(src)).handlers).map(k => +k));
  return handlerFileOrder(src).filter(hh => {
    const off = table[hh];
    return inProg.has(hh) && off > 0 && off < 0x8000;
  });
}

function sectionMetaLayout(table, codeEnd, text, sectionOrder) {
  const metaRefOffset = new Map();
  const metaSizes = new Map();
  for (let i = 0; i < sectionOrder.length; i++) {
    const hh = sectionOrder[i];
    const start = table[hh];
    let end = codeEnd;
    for (let j = i + 1; j < sectionOrder.length; j++) {
      const off = table[sectionOrder[j]];
      if (off > start && off < end) end = off;
    }
    let size = Math.max(0, end - start);
    if (size > 0 && text[start + size - 1] === 0xc3) size--;
    metaRefOffset.set(hh, start);
    metaSizes.set(hh, size);
  }
  return { order: sectionOrder, metaRefOffset, metaSizes };
}

function buildActualRefFromLabels(codeLabels, metaRef, sectionRefOffset) {
  const actualRef = new Map(sectionRefOffset);
  if (!metaRef) return actualRef;
  for (const hh of metaRef.keys()) {
    const lab = codeLabels['H' + hh];
    if (lab !== undefined) actualRef.set(hh, lab);
  }
  const sections = [...sectionRefOffset.keys()].sort((a, b) => (metaRef.get(a) || 0) - (metaRef.get(b) || 0));
  for (const hh of metaRef.keys()) {
    if (actualRef.has(hh)) continue;
    let container = sections[0];
    for (const s of sections) {
      if ((metaRef.get(s) || 0) <= (metaRef.get(hh) || 0)) container = s;
    }
    if (container === undefined || !actualRef.has(container)) continue;
    actualRef.set(hh, actualRef.get(container) + (metaRef.get(hh) - metaRef.get(container)));
  }
  return actualRef;
}

function readPeHandlerLayout(exePath) {
  const b = fs.readFileSync(exePath);
  const mapOff = DATA_FILE_OFF + HANDLER_MAP_OFF;
  const table = [];
  for (let i = 0; i < 256; i++) table.push(b.readUInt32LE(mapOff + i * 4));
  const codeEnd = b.readUInt32LE(mapOff + 0x400);
  return { table, codeEnd, textOff: PE_TEXT_FILE_OFF, mapOff };
}

function captureTirHandlerSlices(src, rootDir, opts = {}) {
  const target = (opts.target || process.env.YOYO_TARGET || 'linux').toLowerCase();
  const tir = require('./tir/index.js');
  const mod = tir.lowerProgramFromSource(src, { handlerOrder: 'file' });
  const v = tir.verifyModule(mod);
  if (!v.ok) throw new Error('TIR verify failed: ' + v.errors.join('; '));
  if (target === 'win') {
    const { extractTirHandlerSlices } = require('./backends/win-emit-core.js');
    return extractTirHandlerSlices(mod, { role: 'output', handlerOrder: 'file', target: 'win' });
  }
  const { extractTirHandlerSlices } = require('./backends/linux-emit-core.js');
  return extractTirHandlerSlices(mod, {
    role: 'output',
    handlerOrder: 'file',
    target: 'linux',
  });
}

function blobHandlers(src, rootDir, opts = {}) {
  rootDir = rootDir || path.join(__dirname, '..');
  const target = (opts.target || process.env.YOYO_TARGET || 'linux').toLowerCase();
  const mode = opts.mode || process.env.YOYO_BLOB_MODE || (process.env.YOYO_TIR_BLOB === '1' ? 'tir' : 'scan');
  const blobTargets = parseSectionEnds(src);
  if (target === 'win' && mode === 'scan') {
    const { parse, analyze } = require('./yoyo.js');
    const inProg = new Set(Object.keys(analyze(parse(src)).handlers).map(k => +k));
    for (const hh of [...blobTargets]) {
      if (!inProg.has(hh)) blobTargets.delete(hh);
    }
    for (const hh of WIN_SCAN_BLOB_SKIP) blobTargets.delete(hh);
    if (process.env.YOYO_BLOB_SKIP) {
      for (const part of process.env.YOYO_BLOB_SKIP.split(/[\s,]+/)) {
        if (!part) continue;
        blobTargets.delete(parseInt(part, 16));
      }
    }
  }

  let slices = new Map();
  let sliceRefOffset = null;
  let sliceSource = mode;
  let progForFilter = null;

  if (mode === 'tir') {
    if (target === 'win') {
      const { parse, analyze } = require('./yoyo.js');
      const { extractWinHandlerSlices } = require('./backends/win-emit-core.js');
      const order = handlerFileOrder(src);
      const prog = analyze(parse(src));
      progForFilter = prog;
      const emitOrder = Object.keys(prog.handlers).map(k => +k).sort((a, b) => a - b);
      const extracted = extractWinHandlerSlices(prog, {
        handlerOrder: 'file',
        handlerOrderList: emitOrder,
      });
      slices = extracted.slices;
      sliceRefOffset = extracted.refOffset;
      sliceSource = 'node';
      writeWinBlobLayout(rootDir, {
        order: emitOrder,
        metaRefOffset: sliceRefOffset,
        metaSizes: extracted.metaSizes,
      });
    } else {
      const { slices: tirSlices } = captureTirHandlerSlices(src, rootDir, { target });
      slices = tirSlices;
    }
  } else {
    const refExe = captureScanReferenceExe(src, rootDir, target);
    const order = handlerFileOrder(src);
    sliceRefOffset = new Map();
    let metaRefOffset = new Map();
    let metaSizes = new Map();
    if (target === 'win') {
      const { table, codeEnd, textOff } = readPeHandlerLayout(refExe);
      const text = fs.readFileSync(refExe).slice(textOff, textOff + 0x8000);
      for (const hh of order) {
        if (!blobTargets.has(hh)) continue;
        const start = table[hh];
        const end = handlerSliceEnd(table, codeEnd, hh);
        if (start > 0 && end > start) {
          let slice = text.slice(start, end);
          if (slice.length > 0 && slice[slice.length - 1] === 0xc3) slice = slice.slice(0, -1);
          slices.set(hh, slice);
          sliceRefOffset.set(hh, start);
        }
      }
      const emitOrder = [];
      for (let hh = 0; hh < 256; hh++) {
        const off = table[hh];
        if (off > 0 && off < 0x8000) emitOrder.push(hh);
      }
      for (const hh of emitOrder) {
        const start = table[hh];
        const end = handlerSliceEnd(table, codeEnd, hh);
        let size = Math.max(0, end - start);
        if (size > 0 && text[start + size - 1] === 0xc3) size--;
        metaRefOffset.set(hh, start);
        metaSizes.set(hh, size);
      }
      writeWinBlobLayout(rootDir, { order: emitOrder, metaRefOffset, metaSizes });
    } else {
      const { table, codeEnd } = readHandlerLayout(refExe);
      const text = fs.readFileSync(refExe).slice(ELF_TEXT_FILE_OFF, ELF_TEXT_FILE_OFF + 0x8000);
      for (const hh of order) {
        if (!blobTargets.has(hh)) continue;
        const start = table[hh];
        const end = handlerSliceEnd(table, codeEnd, hh);
        if (start > 0 && end > start) {
          slices.set(hh, text.slice(start, end));
          sliceRefOffset.set(hh, start);
        }
      }
    }
  }

  const out = [];
  const raw = src.split('\n');
  let blobbed = 0;
  let i = 0;
  while (i < raw.length) {
    const line = raw[i];
    const trimmed = line.replace(/;.*$/, '').trim();
    const m = trimmed.match(/^40\s+([0-9a-fA-F]+)$/);
    if (m) {
      const hh = parseInt(m[1], 16);
      const slice = slices.get(hh);
      const inProg = !progForFilter || progForFilter.handlers[hh] || progForFilter.handlers[String(hh)];
      out.push(line);
      if (slice && slice.length > 0 && blobTargets.has(hh) && inProg) {
        const refOff = sliceRefOffset != null ? sliceRefOffset.get(hh) : undefined;
        const relNote = refOff !== undefined ? ' @0x' + refOff.toString(16) : '';
        out.push('; blob ' + slice.length + ' bytes from ' + sliceSource + ' reference' + relNote);
        out.push(...a1ByteLines(slice));
        out.push('ff');
        blobbed++;
        i++;
        while (i < raw.length) {
          const body = raw[i].replace(/;.*$/, '').trim();
          if (/^ff$/i.test(body)) { i++; break; }
          if (/^40\s+[0-9a-fA-F]+$/.test(body)) break;
          i++;
        }
        continue;
      }
      i++;
      continue;
    }
    out.push(line);
    i++;
  }

  if (opts.verbose !== false) {
    console.error('[blob-handlers] mode=' + mode + ' blobbed=' + blobbed + ' targets=' + blobTargets.size);
  }
  return out.join('\n');
}

module.exports = {
  blobHandlers,
  handlerFileOrder,
  handlerSliceEnd,
  readHandlerLayout,
  parseSectionEnds,
  parseBlobRefOffsets,
  parseBlobHandlers,
  isBlobHandlerOps,
  blobRawFromOps,
  relocateSlice,
  relocateSliceWithLayout,
  buildActualRefFromLabels,
  sectionHandlersFromSource,
  sectionMetaLayout,
  writeWinBlobLayout,
  readWinBlobLayout,
  a1ByteLines,
  captureTirHandlerSlices,
  captureScanReferenceElf,
  captureScanReferencePe,
  captureScanReferenceExe,
  readPeHandlerLayout,
};
