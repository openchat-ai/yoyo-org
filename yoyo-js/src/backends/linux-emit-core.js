'use strict';

/**
 * Shared Linux x64 emission — used by yoyo.js compileLinux and tir-emit-linux.
 * Single source of truth for opcode → machine code mapping.
 */
const E = require('../encode-x64.js');
const { ELF, alignS, BASE } = require('../elf-builder.js');
const { TEXT_VS, STATE_BUF_OFF, OUTPUT_STATE_BUF_OFF } = require('../platform-config.js');
const { buildLinuxStartup, buildLinuxOutputStartup, makeLinuxEmit } = require('../linux-runtime.js');
const { CompileError, resolveFixupsStrict, assertTextLimit } = require('../compile-validator.js');
const { emitStoreByte87, OP_RAW_BYTES } = require('../opcode-emit-x64.js');

const CODE_RVA = BASE + 0x1000;
const RAX = 0, RCX = 1, RDX = 2, RDI = 7, RSI = 6, R8 = 8;

const JCC_MAP = {
  eq: 0, ne: 1, l: 2, g: 5, lt: 2, le: 3, be: 4, gt: 5, jb: 6, ae: 7, a: 9,
};

function createEmitContext(strs, strPos, opts = {}) {
  const isCompiler = opts.role !== 'output';
  const elf = new ELF();
  elf.setCode(Buffer.alloc(TEXT_VS, 0x90));
  elf.setData(Buffer.alloc(1, 0));
  elf.build();
  const dr = elf.dataRVA;

  const code = new E.Buf();
  code.labels = {};
  code.fixups = [];
  code.dataFixups = [];
  code.label = n => { code.labels[n] = code.tell(); };
  code.jmp32 = n => { E.jmp_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n }); };
  code.jcc32 = (cc, n) => { E.jcc32(code, cc, 0); code.fixups.push({ p: code.tell() - 4, n }); };

  const linux = makeLinuxEmit(code, dr, strs, strPos);
  const STARTUP_MAX = 128;
  while (code.tell() < STARTUP_MAX) code.u8(0x90);

  function emitExitAligned() {
    code.u8(0x48); code.u8(0x83); code.u8(0xe4); code.u8(0xf0);
    linux.emitExit();
  }

  function emitRawOp(op) {
    const a = op.args;
    const o = op.op;
    if (o === 0x30) { linux.stSet(a[0].v, a[1] ? a[1].v : 0); }
    else if (o === 0x31 || o === 0x33 || o === 0x32) { /* stdout — unused on Linux */ }
    else if (o === 0x40) { code.label('H' + a[0].v); }
    else if (o === 0x41) { E.call_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n: 'H' + a[0].v }); }
    else if (o === 0x50) { linux.emitLoadFile(a[0].v, a[1].v); }
    else if (o === 0x51) { linux.emitWriteFile(a[0].v, a[1].v, a[2] ? a[2].v : 0); }
    else if (o === 0x60) { linux.stGet(RAX, a[1].v); linux.stPut(a[0].v, RAX); }
    else if (o === 0x61) { linux.stGet(RAX, a[0].v); E.add_ri(code, RAX, a[1].v); linux.stPut(a[0].v, RAX); }
    else if (o === 0x62) { linux.stGet(RAX, a[0].v); E.sub_ri(code, RAX, a[1].v); linux.stPut(a[0].v, RAX); }
    else if (o === 0x63) { linux.stGet(RAX, a[0].v); linux.stGet(RDX, a[1].v); E.imul_rr(code, RAX, RDX); linux.stPut(a[0].v, RAX); }
    else if (o === 0x66) { linux.stGet(RAX, a[0].v); E.add_ri(code, RAX, 1); linux.stPut(a[0].v, RAX); }
    else if (o === 0x67) { linux.stGet(RAX, a[0].v); E.sub_ri(code, RAX, 1); linux.stPut(a[0].v, RAX); }
    else if (o === 0x68) { linux.stGet(RAX, a[0].v); linux.stGet(RDX, a[1].v); E.add_rr(code, RAX, RDX); linux.stPut(a[0].v, RAX); }
    else if (o === 0x69) { linux.stGet(RAX, a[0].v); linux.stGet(RDX, a[1].v); E.sub_rr(code, RAX, RDX); linux.stPut(a[0].v, RAX); }
    else if (o === 0x65) { linux.stGet(RAX, a[0].v); linux.stGet(RDX, a[1].v); E.cmp_rr(code, RAX, RDX); }
    else if (o === 0x70) { code.jmp32('H' + a[0].v); }
    else if (o === 0x71) { code.jcc32(0, 'H' + a[0].v); }
    else if (o === 0x72) { code.jcc32(1, 'H' + a[0].v); }
    else if (o === 0x82) { code.jcc32(2, 'H' + a[0].v); }
    else if (o === 0x83) { code.jcc32(5, 'H' + a[0].v); }
    else if (o === 0x73) { code.jcc32(2, 'H' + a[0].v); }
    else if (o === 0x74) { code.jcc32(3, 'H' + a[0].v); }
    else if (o === 0x75) { code.jcc32(4, 'H' + a[0].v); }
    else if (o === 0x76) { code.jcc32(5, 'H' + a[0].v); }
    else if (o === 0x77) { code.jcc32(6, 'H' + a[0].v); }
    else if (o === 0x78) { code.jcc32(7, 'H' + a[0].v); }
    else if (o === 0x79) { code.jcc32(8, 'H' + a[0].v); }
    else if (o === 0x7a) { code.jcc32(9, 'H' + a[0].v); }
    else if (o === 0x80) {
      linux.stGet(RDX, a[1].v);
      code.u8(0x0f); code.u8(0xb6);
      const _d = a[2] ? a[2].v : 0;
      if (_d === 0 && 2 !== 5) code.u8(0x02);
      else if (_d >= -128 && _d <= 127) { code.u8(0x42); code.u8(_d & 255); }
      else { code.u8(0x82); code.u32(_d); }
      linux.stPut(a[0].v, RAX);
    }
    else if (o === 0x81) { E.mov_ri(code, RAX, BigInt(a[1].v)); linux.stGet(RDX, a[0].v); E.mov_mr(code, RDX, a[2] ? a[2].v : 0, RAX, true); }
    else if (o === 0x84) {
      linux.stGet(RDI, a[0].v);
      linux.stGet(RSI, 8);
      E.add_ri(code, RSI, a[1].v);
      E.mov_ri(code, RCX, BigInt(a[2].v));
      code.u8(0xf3); code.u8(0xa4);
    }
    else if (o === 0x85) { linux.stGet(RDI, a[0].v); linux.stGet(RSI, a[1].v); linux.stGet(RCX, a[2].v); code.u8(0xf3); code.u8(0xa4); }
    else if (o === 0x55) { linux.stGet(RDX, a[0].v); linux.stGet(RAX, a[1].v); code.u8(0x89); code.u8(0x02); }
    else if (o === 0x57) { linux.stGet(RDX, a[0].v); linux.stGet(R8, a[1].v); E.add_rr(code, RDX, R8); linux.stGet(RAX, a[2].v); code.u8(0x88); code.u8(0x02); }
    else if (o === 0x87) {
      emitStoreByte87(code, (s) => linux.stGet(RDX, s), (s) => linux.stGet(RAX, s), a);
    }
    else if (o === 0xff) { E.ret(code); }
    else if (o === 0x20) { linux.emitAlloc(a[0].v, a[1].v); }
    else if (o === 0xa0) {
      const hex = a[0] ? a[0].v : '';
      for (let i = 0; i < hex.length; i += 2) {
        const b = parseInt(hex.substr(i, 2), 16);
        if (!isNaN(b)) code.u8(b);
      }
    }
    else if (o === 0xa1) { if (a[0]) code.u8(a[0].v & 255); }
    else if (o === OP_RAW_BYTES) { for (const b of op.rawBytes) code.u8(b); }
    else {
      throw new CompileError(`line ${op.line || '?'}: unimplemented opcode 0x${o.toString(16)} in emit`);
    }
  }

  function emitTirOp(tirOp) {
    const { Op } = require('../tir/ops.js');
    switch (tirOp.kind) {
      case Op.LABEL: code.label('H' + tirOp.hh); break;
      case Op.CALL: E.call_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n: 'H' + tirOp.hh }); break;
      case Op.TAIL_CALL: {
        E.jmp_rel(code, 0);
        code.fixups.push({ p: code.tell() - 4, n: 'H' + tirOp.hh });
        break;
      }
      case Op.JMP: code.jmp32('H' + tirOp.hh); break;
      case Op.JCC: code.jcc32(JCC_MAP[tirOp.cond] ?? 0, 'H' + tirOp.hh); break;
      case Op.RET: E.ret(code); break;
      case Op.STATE_SET: linux.stSet(tirOp.slot, tirOp.value); break;
      case Op.STATE_COPY: linux.stGet(RAX, tirOp.src); linux.stPut(tirOp.dst, RAX); break;
      case Op.STATE_GET: linux.stGet(RAX, tirOp.slot); break;
      case Op.STATE_ADD_IMM: linux.stGet(RAX, tirOp.slot); E.add_ri(code, RAX, tirOp.imm); linux.stPut(tirOp.slot, RAX); break;
      case Op.STATE_SUB_IMM: linux.stGet(RAX, tirOp.slot); E.sub_ri(code, RAX, tirOp.imm); linux.stPut(tirOp.slot, RAX); break;
      case Op.STATE_INC: linux.stGet(RAX, tirOp.slot); E.add_ri(code, RAX, 1); linux.stPut(tirOp.slot, RAX); break;
      case Op.STATE_ADD: linux.stGet(RAX, tirOp.dst); linux.stGet(RDX, tirOp.src); E.add_rr(code, RAX, RDX); linux.stPut(tirOp.dst, RAX); break;
      case Op.STATE_SUB: linux.stGet(RAX, tirOp.dst); linux.stGet(RDX, tirOp.src); E.sub_rr(code, RAX, RDX); linux.stPut(tirOp.dst, RAX); break;
      case Op.STATE_CMP: linux.stGet(RAX, tirOp.a); linux.stGet(RDX, tirOp.b); E.cmp_rr(code, RAX, RDX); break;
      case Op.STATE_LOAD_BYTE: {
        linux.stGet(RDX, tirOp.base);
        code.u8(0x0f); code.u8(0xb6);
        const _d = tirOp.offset || 0;
        if (_d === 0 && 2 !== 5) code.u8(0x02);
        else if (_d >= -128 && _d <= 127) { code.u8(0x42); code.u8(_d & 255); }
        else { code.u8(0x82); code.u32(_d); }
        linux.stPut(tirOp.dst, RAX);
        break;
      }
      case Op.EMIT_U8: code.u8(tirOp.value & 0xff); break;
      case Op.EMIT_U8_SLOT: linux.stGet(RAX, tirOp.slot); code.u8(RAX & 0xff); break;
      case Op.EMIT_STORE_U32: linux.stGet(RDX, tirOp.addrSlot); linux.stGet(RAX, tirOp.valSlot); code.u8(0x89); code.u8(0x02); break;
      case Op.EMIT_STORE_BYTE: {
        linux.stGet(RDX, tirOp.base);
        linux.stGet(R8, tirOp.index);
        E.add_rr(code, RDX, R8);
        linux.stGet(RAX, tirOp.val);
        code.u8(0x88); code.u8(0x02);
        break;
      }
      case Op.EMIT_STORE_BYTE_IMM: {
        emitStoreByte87(code, (s) => linux.stGet(RDX, s), (s) => linux.stGet(RAX, s), {
          0: { v: tirOp.addrSlot }, 1: { v: tirOp.valSlot }, 2: { v: tirOp.offset || 0 },
        });
        break;
      }
      case Op.LOAD_FILE: linux.emitLoadFile(tirOp.stateSlot, tirOp.stringId); break;
      case Op.WRITE_FILE: linux.emitWriteFile(tirOp.fdSlot, tirOp.bufSlot, tirOp.lenSlot); break;
      case Op.ALLOC: linux.emitAlloc(tirOp.slot, tirOp.size); break;
      case Op.MEMCPY_DATA: linux.stGet(RDI, tirOp.dst); linux.ld(RSI, tirOp.blobOff); E.mov_ri(code, RCX, BigInt(tirOp.len)); code.u8(0xf3); code.u8(0xa4); break;
      case Op.MEMCPY_STATE: linux.stGet(RDI, tirOp.dst); linux.stGet(RSI, tirOp.src); linux.stGet(RCX, tirOp.lenSlot); code.u8(0xf3); code.u8(0xa4); break;
      case Op.RAW_A0: {
        const hex = tirOp.hex || '';
        for (let i = 0; i < hex.length; i += 2) {
          const b = parseInt(hex.substr(i, 2), 16);
          if (!isNaN(b)) code.u8(b);
        }
        break;
      }
      case Op.RAW_BYTES: {
        for (const b of (tirOp.bytes || [])) code.u8(b & 0xff);
        break;
      }
      case Op.STRING_DEF:
      case Op.DATA_BLOB:
      case Op.NOP:
      case Op.BLOB_LINE:
        break;
      default:
        throw new CompileError(`unimplemented TIR op kind ${tirOp.kind}`);
    }
  }

  function finish(prog, sOff) {
    assertTextLimit(code.tell(), TEXT_VS, 'linux-emit-core .text');
    resolveFixupsStrict(code, { allowMissing: process.env.YOYO_STRICT_FIXUPS !== '1' });

    const fixDR = CODE_RVA + alignS(code.tell());
    for (const f of code.dataFixups) {
      code.b.writeInt32LE(fixDR + f.o - f.instrEnd, f.dispPos);
    }

    const total = Buffer.alloc(code.tell(), 0);
    code.b.slice(0, code.tell()).copy(total, 0);

    const dataOff = isCompiler ? STATE_BUF_OFF : OUTPUT_STATE_BUF_OFF;
    const data = Buffer.alloc(0x10000 + dataOff + 0x20000, 0);
    data.writeUInt32LE(strs.length, 0);
    for (let i = 0; i < strs.length; i++) {
      const off = strPos[i];
      const tb = Buffer.from(strs[i].text + '\0', 'ascii');
      data.writeUInt32LE(strs[i].text.length, off);
      tb.copy(data, off + 4);
    }
    if (sOff !== undefined) Buffer.from('\n\0', 'ascii').copy(data, sOff);
    for (const b of prog.blobs || []) b.data.copy(data, b.off);

    const dataRva = CODE_RVA + alignS(code.tell());
    const startup = isCompiler
      ? buildLinuxStartup(dataRva, STARTUP_MAX)
      : buildLinuxOutputStartup(dataRva);
    startup.copy(total, 0);
    elf.entry = CODE_RVA;
    elf.setCode(total);
    elf.setData(data);
    return elf.build();
  }

  return { code, linux, emitRawOp, emitTirOp, emitExitAligned, finish, STARTUP_MAX, dr, elf };
}

function buildStringLayout(strings) {
  const strs = Object.values(strings);
  let sOff = 16;
  const strPos = [];
  for (const s of strs) { strPos.push(sOff); sOff += 4 + s.text.length + 1; }
  return { strs, strPos, sOff };
}

function compileFromAnalyzed(prog, opts = {}) {
  const { strs, strPos, sOff } = buildStringLayout(prog.strings);
  const ctx = createEmitContext(strs, strPos, opts);

  for (const op of prog.top) ctx.emitRawOp(op);
  ctx.emitExitAligned();

  const handlerKeys = Object.keys(prog.handlers).map(k => +k).sort((a, b) => a - b);
  for (const h of handlerKeys) {
    ctx.code.label('H' + h);
    for (const op of prog.handlers[h]) ctx.emitRawOp(op);
    E.ret(ctx.code);
  }
  while (ctx.code.tell() < TEXT_VS) ctx.code.u8(0x90);

  return ctx.finish(prog, sOff);
}

function compileFromTirModule(mod, opts = {}) {
  const strings = mod.strings || {};
  const { strs, strPos, sOff } = buildStringLayout(strings);
  const ctx = createEmitContext(strs, strPos, opts);

  const order = opts.handlerOrder === 'file'
    ? (mod.handlerOrder || [])
    : [...(mod.handlerOrder || [])].sort((a, b) => a - b);

  const topFn = mod.functions.find(f => f.name === '__top');
  if (topFn) {
    for (const block of topFn.blocks) {
      for (const op of block.ops) {
        if (op.kind !== require('../tir/ops.js').Op.STRING_DEF &&
            op.kind !== require('../tir/ops.js').Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
  }
  ctx.emitExitAligned();

  for (const hh of order) {
    const fn = mod.functions.find(f => f.name === 'H' + hh.toString(16));
    if (!fn) continue;
    for (const block of fn.blocks) {
      for (const op of block.ops) {
        if (op.kind === require('../tir/ops.js').Op.LABEL) ctx.code.label('H' + op.hh);
        else if (op.kind !== require('../tir/ops.js').Op.STRING_DEF &&
                 op.kind !== require('../tir/ops.js').Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
    E.ret(ctx.code);
  }
  while (ctx.code.tell() < TEXT_VS) ctx.code.u8(0x90);

  const blobs = mod.blobs || [];
  return ctx.finish({ blobs, strings }, sOff);
}

/**
 * Emit TIR module and return per-handler machine-code slices (pre-startup layout).
 * Used by blob-handlers TIR path — single codegen reference for scan-emitted gen2.
 */
function extractTirHandlerSlices(mod, opts = {}) {
  const strings = mod.strings || {};
  const { strs, strPos, sOff } = buildStringLayout(strings);
  const ctx = createEmitContext(strs, strPos, opts);

  const order = opts.handlerOrder === 'file'
    ? (mod.handlerOrder || [])
    : [...(mod.handlerOrder || [])].sort((a, b) => a - b);

  const topFn = mod.functions.find(f => f.name === '__top');
  if (topFn) {
    for (const block of topFn.blocks) {
      for (const op of block.ops) {
        if (op.kind !== require('../tir/ops.js').Op.STRING_DEF &&
            op.kind !== require('../tir/ops.js').Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
  }
  ctx.emitExitAligned();

  for (const hh of order) {
    const fn = mod.functions.find(f => f.name === 'H' + hh.toString(16));
    if (!fn) continue;
    for (const block of fn.blocks) {
      for (const op of block.ops) {
        if (op.kind === require('../tir/ops.js').Op.LABEL) ctx.code.label('H' + op.hh);
        else if (op.kind !== require('../tir/ops.js').Op.STRING_DEF &&
                 op.kind !== require('../tir/ops.js').Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
    E.ret(ctx.code);
  }

  for (const f of ctx.code.fixups) {
    const t = ctx.code.labels[f.n];
    if (t !== undefined) ctx.code.b.writeInt32LE(t - (f.p + 4), f.p);
  }

  const slices = new Map();
  for (let i = 0; i < order.length; i++) {
    const hh = order[i];
    const key = 'H' + hh.toString(16);
    const start = ctx.code.labels[key];
    if (start === undefined) continue;
    let end = ctx.code.tell();
    for (let j = i + 1; j < order.length; j++) {
      const nextKey = 'H' + order[j].toString(16);
      const nextStart = ctx.code.labels[nextKey];
      if (nextStart !== undefined) { end = nextStart; break; }
    }
    let buf = ctx.code.b.slice(start, end);
    if (buf.length > 0 && buf[buf.length - 1] === 0xc3) buf = buf.slice(0, -1);
    slices.set(hh, Buffer.from(buf));
  }

  return { slices, order, codeEnd: ctx.code.tell(), startupLen: ctx.STARTUP_MAX };
}

module.exports = {
  createEmitContext,
  compileFromAnalyzed,
  compileFromTirModule,
  extractTirHandlerSlices,
  buildStringLayout,
  JCC_MAP,
};
