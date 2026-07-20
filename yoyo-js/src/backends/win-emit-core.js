'use strict';

/**
 * Windows PE x64 emission — shared by yoyo.js compileWin and TIR blob extraction.
 */
const E = require('../encode-x64.js');
const { PE } = require('../pe-builder.js');
const { TEXT_VS, CODE_RVA, WIN_FUNCS } = require('../platform-config.js');
const { CompileError, resolveFixupsStrict, resolveWinIatFixupsStrict, assertWinImport, assertTextLimit } = require('../compile-validator.js');
const { emitStoreByte87, OP_RAW_BYTES } = require('../opcode-emit-x64.js');

const RCX = 1, RDX = 2, RSP = 4, RSI = 6, RDI = 7, R8 = 8, R9 = 9;
const R12 = 12, R13 = 13, R14 = 14, R15 = 15, RAX = 0;

const JCC_MAP = {
  eq: 0, ne: 1, l: 2, g: 5, lt: 2, le: 3, be: 4, gt: 5, jb: 6, ae: 7, a: 9,
};

E.mov_mi64 = function (b, b2, d, v) { E.mov_ri(b, RAX, v); E.mov_mr64(b, b2, d, RAX); };
E.lea_rr = function (b, d, s, disp) {
  b.rex(1, d > 7, 0, s > 7); b.u8(0x8D);
  function w(m) {
    if ((s & 7) === 4) { b.modrm(m, d & 7, 4); b.sib(0, 4, s & 7); }
    else b.modrm(m, d & 7, s & 7);
  }
  if (disp === 0 && s !== 5) w(0);
  else if (disp >= -128 && disp <= 127) { w(1); b.u8(disp & 255); }
  else { w(2); b.u32(disp); }
};

function buildStringLayout(strings) {
  const strs = Object.values(strings);
  let sOff = 16;
  const strPos = [];
  for (const s of strs) { strPos.push(sOff); sOff += 4 + s.text.length + 1; }
  return { strs, strPos, sOff };
}

function createWinEmitContext(prog, opts = {}) {
  const { strs, strPos, sOff } = buildStringLayout(prog.strings || {});

  const pe = new PE(); pe.subsys = 3;
  pe.addImport('KERNEL32.dll', WIN_FUNCS);
  pe.setCode(Buffer.alloc(TEXT_VS, 0x00)); pe.setData(Buffer.alloc(1, 0)); pe.build();
  const P = pe.ptrMap;
  pe.setCode(Buffer.alloc(TEXT_VS, 0x00)); pe.setData(Buffer.alloc(1, 0)); pe.build();
  const dr = pe.dataRVA;

  const code = new E.Buf();
  code.labels = {};
  code.fixups = [];
  code.iatFixups = [];
  code.label = n => { code.labels[n] = code.tell(); };
  code.jmp32 = n => { E.jmp_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n }); };
  code.jcc32 = (cc, n) => { E.jcc32(code, cc, 0); code.fixups.push({ p: code.tell() - 4, n }); };

  function winCall(name, stack, setup) {
    const n = stack || 0x28;
    code.u8(0x48); code.u8(0x83); code.u8(0xec); code.u8(n);
    if (setup) setup();
    const r = P[name];
    if (r === undefined) {
      if (process.env.YOYO_STRICT_IMPORTS === '1') assertWinImport(P, name);
    } else {
      const c = CODE_RVA + code.tell();
      E.call_rip(code, r - (c + 6));
      code.iatFixups.push({ importName: name, dispPos: code.tell() - 4, instrEnd: c + 6 });
    }
    code.u8(0x48); code.u8(0x83); code.u8(0xc4); code.u8(n);
  }
  function ci(n) { winCall(n, 0x28); }
  function ld(r, o) {
    code.u8(0x48 + (r > 7 ? 4 : 0)); code.u8(0x8D); code.u8(0x05 | ((r & 7) << 3));
    const _p = code.tell(); code.u32(0); const _e = code.tell();
    code.b.writeInt32LE(dr + o - (CODE_RVA + _e), _p);
    code.iatFixups.push({ o, dispPos: _p, instrEnd: CODE_RVA + _e, isLd: 1 });
  }
  function lr(r, b, d) { E.lea_rr(code, r, b, d); }
  function stSet(id, v) {
    // V3-compatible: 49 C7 47 <disp8> <simm32> (8 bytes)
    code.u8(0x49); code.u8(0xC7); code.u8(0x47); code.u8(id * 8);
    code.u32(v >>> 0);
  }
  function stInc(id) {
    // 49 FF 47 <disp8> (4 bytes) — inc qword [r15+disp8]
    code.u8(0x49); code.u8(0xFF); code.u8(0x47); code.u8(id * 8);
  }
  function stDec(id) {
    // 49 FF 4F <disp8> (4 bytes) — dec qword [r15+disp8]
    code.u8(0x49); code.u8(0xFF); code.u8(0x4F); code.u8(id * 8);
  }
  function stGet(reg, id) { E.mov_rm64(code, reg, R15, id * 8); }
  function stPut(id, reg) { E.mov_mr64(code, R15, id * 8, reg); }
  function stAdd(id, v) { stGet(RAX, id); E.add_ri(code, RAX, v); stPut(id, RAX); }
  function stSub(id, v) { stGet(RAX, id); E.sub_ri(code, RAX, v); stPut(id, RAX); }
  function stCmp(a, b) { stGet(RAX, a); stGet(RDX, b); E.cmp_rr(code, RAX, RDX); }
  // V3-compatible memory operations
  function stAddV(a, b) {
    // 49 8B 47 <b*8> 49 01 47 <a*8> (8 bytes) — state[a] += state[b]
    code.u8(0x49); code.u8(0x8B); code.u8(0x47); code.u8(b * 8);
    code.u8(0x49); code.u8(0x01); code.u8(0x47); code.u8(a * 8);
  }
  function stSubV(a, b) {
    // 49 8B 47 <b*8> 49 29 47 <a*8> (8 bytes) — state[a] -= state[b]
    code.u8(0x49); code.u8(0x8B); code.u8(0x47); code.u8(b * 8);
    code.u8(0x49); code.u8(0x29); code.u8(0x47); code.u8(a * 8);
  }
  function stCmpMem(a, b) {
    // 49 8B 47 <a*8> 49 3B 47 <b*8> (8 bytes) — cmp rax, [r15+b*8]
    code.u8(0x49); code.u8(0x8B); code.u8(0x47); code.u8(a * 8);
    code.u8(0x49); code.u8(0x3B); code.u8(0x47); code.u8(b * 8);
  }

  function emitLoadFile(stateSlot, strId) {
    ld(RCX, strPos[strId] + 4);
    E.mov_ri(code, RDX, 0x80000000n); E.mov_ri(code, R8, 1n); E.xor_rr(code, R9, R9);
    winCall('KERNEL32.dll.CreateFileA', 0x38, () => {
      E.mov_mi64(code, RSP, 0x20, 3n); E.mov_mi64(code, RSP, 0x28, 0x80n); E.mov_mi64(code, RSP, 0x30, 0n);
    });
    E.mov_rr(code, R13, RAX);
    E.mov_rr(code, RCX, R13); E.xor_rr(code, RDX, RDX); ci('KERNEL32.dll.GetFileSize');
    E.mov_rr(code, R12, RAX);
    E.mov_ri(code, RCX, 0n); E.mov_rr(code, RDX, R12);
    E.mov_ri(code, R8, 0x3000n); E.mov_ri(code, R9, 0x40n); ci('KERNEL32.dll.VirtualAlloc');
    stPut(stateSlot, RAX); stPut(stateSlot + 1, R12);
    E.mov_rr(code, RCX, R13); stGet(RDX, stateSlot); E.mov_rr(code, R8, R12);
    winCall('KERNEL32.dll.ReadFile', 0x28, () => { E.mov_mi64(code, RSP, 0x20, 0n); lr(R9, RSP, 0x20); });
    E.mov_rr(code, RCX, R13); ci('KERNEL32.dll.CloseHandle');
  }

  function emitWriteFile(bufSlot, strId, lenSlot) {
    ld(RCX, strPos[strId] + 4);
    E.mov_ri(code, RDX, 0x40000000n); E.xor_rr(code, R8, R8); E.xor_rr(code, R9, R9);
    winCall('KERNEL32.dll.CreateFileA', 0x38, () => {
      E.mov_mi64(code, RSP, 0x20, 2n); E.mov_mi64(code, RSP, 0x28, 0x80n); E.mov_mi64(code, RSP, 0x30, 0n);
    });
    E.mov_rr(code, R13, RAX);
    E.mov_rr(code, RCX, R13); stGet(RDX, bufSlot); stGet(R8, lenSlot);
    winCall('KERNEL32.dll.WriteFile', 0x28, () => { E.mov_mi64(code, RSP, 0x20, 0n); lr(R9, RSP, 0x20); });
    E.mov_rr(code, RCX, R13); ci('KERNEL32.dll.CloseHandle');
  }

  function emitAlloc(slot, size) {
    E.mov_ri(code, RCX, 0n); E.mov_ri(code, RDX, BigInt(size));
    E.mov_ri(code, R8, 0x3000n); E.mov_ri(code, R9, 0x40n);
    ci('KERNEL32.dll.VirtualAlloc'); stPut(slot, RAX);
  }

  // libyoyo_* call emitters (Phase 4c).
  // Each emits: load arg(s) into rdi/rsi/rdx, then call [libyoyo_*]
  // (via Win32 IAT-style indirection). The linker places a placeholder
  // (FF 15 <index> 00 00 00) that gets patched with the IAT RVA.
  function emitLibyoyoAlloc(slot, size) {
    E.mov_ri(code, RDI, BigInt(size));
    ci('KERNEL32.dll.libyoyo_alloc');
    stPut(slot, RAX);
  }
  function emitLibyoyoFree(slot) {
    stGet(RDI, slot);
    ci('KERNEL32.dll.libyoyo_free');
  }
  function emitLibyoyoOpen(slot, strId) {
    // rdi = pointer to NUL-terminated path string
    ld(RDI, strPos[strId] + 4);
    ci('KERNEL32.dll.libyoyo_open');
    stPut(slot, RAX);
  }
  function emitLibyoyoRead(slot, fdSlot, size) {
    stGet(RDI, fdSlot);
    stGet(RSI, slot);
    E.mov_ri(code, RDX, BigInt(size));
    ci('KERNEL32.dll.libyoyo_read');
    stPut(slot + 1, RAX);  // bytes read
  }
  function emitLibyoyoWrite(fdSlot, slot, size) {
    stGet(RDI, fdSlot);
    stGet(RSI, slot);
    E.mov_ri(code, RDX, BigInt(size));
    ci('KERNEL32.dll.libyoyo_write');
  }
  function emitLibyoyoClose(fdSlot) {
    stGet(RDI, fdSlot);
    ci('KERNEL32.dll.libyoyo_close');
  }
  function emitLibyoyoExit(slot) {
    stGet(RDI, slot);
    ci('KERNEL32.dll.libyoyo_exit');
    E.mov_ri(code, RCX, 0n); ci('KERNEL32.dll.ExitProcess');  // unreachable but safe
  }
  function emitLibyoyoPrint(slot) {
    stGet(RDI, slot);
    ci('KERNEL32.dll.libyoyo_print');
  }
  function emitLibyoyoTime(slot) {
    ci('KERNEL32.dll.libyoyo_time');
    stPut(slot, RAX);
  }

  function emit(op) {
    const a = op.args, o = op.op;
    if (o === 0x30) stSet(a[0].v, a[1] ? a[1].v : 0);
    else if (o === 0x31 || o === 0x33) {
      const si = a[0].v;
      E.mov_rr(code, RCX, R14); ld(RDX, strPos[si] + 4);
      E.mov_ri(code, R8, BigInt(strs[si].text.length));
      winCall('KERNEL32.dll.WriteFile', 0x28, () => { E.mov_mi64(code, RSP, 0x20, 0n); lr(R9, RSP, 0x28); });
      if (o === 0x33) {
        E.mov_rr(code, RCX, R14); ld(RDX, sOff); E.mov_ri(code, R8, 2n);
        winCall('KERNEL32.dll.WriteFile', 0x28, () => { E.mov_mi64(code, RSP, 0x20, 0n); lr(R9, RSP, 0x28); });
      }
    } else if (o === 0x32) {
      E.mov_rr(code, RCX, R14); ld(RDX, sOff); E.mov_ri(code, R8, 2n);
      winCall('KERNEL32.dll.WriteFile', 0x28, () => { E.mov_mi64(code, RSP, 0x20, 0n); lr(R9, RSP, 0x28); });
    } else if (o === 0x40) code.label('H' + a[0].v);
    else if (o === 0x41) { E.call_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n: 'H' + a[0].v }); }
    else if (o === 0x50) emitLoadFile(a[0].v, a[1].v);
    else if (o === 0x51) emitWriteFile(a[0].v, a[1].v, a[2] ? a[2].v : 0);
    else if (o === 0x60) { stGet(RAX, a[1].v); stPut(a[0].v, RAX); }
    else if (o === 0x61) stAdd(a[0].v, a[1].v);
    else if (o === 0x62) stSub(a[0].v, a[1].v);
    else if (o === 0x63) { stGet(RAX, a[0].v); stGet(RDX, a[1].v); E.imul_rr(code, RAX, RDX); stPut(a[0].v, RAX); }
    else if (o === 0x65) stCmpMem(a[0].v, a[1].v);
    else if (o === 0x66) { stInc(a[0].v); }
    else if (o === 0x67) { stDec(a[0].v); }
    else if (o === 0x68) stAddV(a[0].v, a[1].v);
    else if (o === 0x69) stSubV(a[0].v, a[1].v);
    else if (o === 0x6A) stAddV(a[0].v, a[1].v); // ADDV (same as ADD)
    else if (o === 0x70) code.jmp32('H' + a[0].v);
    else if (o === 0x71) code.jcc32(0, 'H' + a[0].v);
    else if (o === 0x72) code.jcc32(1, 'H' + a[0].v);
    else if (o === 0x82) code.jcc32(2, 'H' + a[0].v);
    else if (o === 0x83) code.jcc32(5, 'H' + a[0].v);
    else if (o === 0x73) code.jcc32(2, 'H' + a[0].v);
    else if (o === 0x74) code.jcc32(3, 'H' + a[0].v);
    else if (o === 0x75) code.jcc32(4, 'H' + a[0].v);
    else if (o === 0x76) code.jcc32(5, 'H' + a[0].v);
    else if (o === 0x77) code.jcc32(6, 'H' + a[0].v);
    else if (o === 0x78) code.jcc32(7, 'H' + a[0].v);
    else if (o === 0x79) code.jcc32(8, 'H' + a[0].v);
    else if (o === 0x7A) code.jcc32(9, 'H' + a[0].v);
    else if (o === 0x80) {
      stGet(RDX, a[1].v); code.u8(0x0F); code.u8(0xB6);
      const _d = a[2] ? a[2].v : 0;
      if (_d === 0 && 2 !== 5) code.u8(0x02);
      else if (_d >= -128 && _d <= 127) { code.u8(0x42); code.u8(_d & 255); }
      else { code.u8(0x82); code.u32(_d); }
      stPut(a[0].v, RAX);
    } else if (o === 0x81) {
      E.mov_ri(code, RAX, BigInt(a[1].v)); stGet(RDX, a[0].v);
      E.mov_mr(code, RDX, a[2] ? a[2].v : 0, RAX, true);
    } else if (o === 0x84) {
      stGet(RDI, a[0].v);
      ld(RSI, a[1].v);
      E.mov_ri(code, RCX, BigInt(a[2].v));
      code.u8(0xF3); code.u8(0xA4);
    } else if (o === 0x85) {
      stGet(RDI, a[0].v); stGet(RSI, a[1].v); stGet(RCX, a[2].v);
      code.u8(0xF3); code.u8(0xA4);
    } else if (o === 0x55) { stGet(RDX, a[0].v); stGet(RAX, a[1].v); code.u8(0x89); code.u8(0x02); }
    else if (o === 0x57) {
      stGet(RDX, a[0].v); stGet(R8, a[1].v); E.add_rr(code, RDX, R8);
      stGet(RAX, a[2].v); code.u8(0x88); code.u8(0x02);
    } else if (o === 0x87) {
      emitStoreByte87(code, (s) => stGet(RDX, s), (s) => stGet(RAX, s), a);
    } else if (o === 0xFF) E.ret(code);
    else if (o === 0x20) emitAlloc(a[0].v, a[1].v);
    else if (o === 0xA1) { if (a[0]) code.u8(a[0].v & 0xff); }
    else if (o === OP_RAW_BYTES) { for (const b of op.rawBytes) code.u8(b); }
    else if (o === 0xA0) {
      const hex = a[0] ? a[0].v : '';
      for (let i = 0; i < hex.length; i += 2) {
        const b = parseInt(hex.substr(i, 2), 16);
        if (!isNaN(b)) code.u8(b);
      }
    }
    // libyoyo_* (Phase 4c) - self-emit path
    else if (o === 0x52) emitLibyoyoAlloc(a[0].v, a[1].v);
    else if (o === 0x53) emitLibyoyoFree(a[0].v);
    else if (o === 0x54) emitLibyoyoOpen(a[0].v, a[1].v);
    else if (o === 0x55) emitLibyoyoRead(a[0].v, a[1].v, a[2].v);
    else if (o === 0x56) emitLibyoyoWrite(a[0].v, a[1].v, a[2].v);
    else if (o === 0x57) emitLibyoyoClose(a[0].v);
    else if (o === 0x58) emitLibyoyoExit(a[0].v);
    else if (o === 0x59) emitLibyoyoPrint(a[0].v);
    else if (o === 0x5a) emitLibyoyoTime(a[0].v);
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
        // tail call: emit jmp instead of call to save one ret+jmp pair
        E.jmp_rel(code, 0);
        code.fixups.push({ p: code.tell() - 4, n: 'H' + tirOp.hh });
        break;
      }
      case Op.JMP: code.jmp32('H' + tirOp.hh); break;
      case Op.JCC: code.jcc32(JCC_MAP[tirOp.cond] ?? 0, 'H' + tirOp.hh); break;
      case Op.RET: E.ret(code); break;
      case Op.STATE_SET: stSet(tirOp.slot, tirOp.value); break;
      case Op.STATE_COPY: stGet(RAX, tirOp.src); stPut(tirOp.dst, RAX); break;
      case Op.STATE_GET: stGet(RAX, tirOp.slot); break;
      case Op.STATE_ADD_IMM: stGet(RAX, tirOp.slot); E.add_ri(code, RAX, tirOp.imm); stPut(tirOp.slot, RAX); break;
      case Op.STATE_SUB_IMM: stGet(RAX, tirOp.slot); E.sub_ri(code, RAX, tirOp.imm); stPut(tirOp.slot, RAX); break;
      case Op.STATE_INC: stGet(RAX, tirOp.slot); E.add_ri(code, RAX, 1); stPut(tirOp.slot, RAX); break;
      case Op.STATE_ADD: stGet(RAX, tirOp.dst); stGet(RDX, tirOp.src); E.add_rr(code, RAX, RDX); stPut(tirOp.dst, RAX); break;
      case Op.STATE_SUB: stGet(RAX, tirOp.dst); stGet(RDX, tirOp.src); E.sub_rr(code, RAX, RDX); stPut(tirOp.dst, RAX); break;
      case Op.STATE_CMP: stGet(RAX, tirOp.a); stGet(RDX, tirOp.b); E.cmp_rr(code, RAX, RDX); break;
      case Op.STATE_LOAD_BYTE: {
        stGet(RDX, tirOp.base);
        code.u8(0x0f); code.u8(0xb6);
        const _d = tirOp.offset || 0;
        if (_d === 0 && 2 !== 5) code.u8(0x02);
        else if (_d >= -128 && _d <= 127) { code.u8(0x42); code.u8(_d & 255); }
        else { code.u8(0x82); code.u32(_d); }
        stPut(tirOp.dst, RAX);
        break;
      }
      case Op.EMIT_U8: code.u8(tirOp.value & 0xff); break;
      case Op.EMIT_U8_SLOT: stGet(RAX, tirOp.slot); code.u8(RAX & 0xff); break;
      case Op.EMIT_STORE_U32: stGet(RDX, tirOp.addrSlot); stGet(RAX, tirOp.valSlot); code.u8(0x89); code.u8(0x02); break;
      case Op.EMIT_STORE_BYTE: {
        stGet(RDX, tirOp.base); stGet(R8, tirOp.index); E.add_rr(code, RDX, R8);
        stGet(RAX, tirOp.val); code.u8(0x88); code.u8(0x02); break;
      }
      case Op.EMIT_STORE_BYTE_IMM: {
        emitStoreByte87(code, (s) => stGet(RDX, s), (s) => stGet(RAX, s), {
          0: { v: tirOp.addrSlot }, 1: { v: tirOp.valSlot }, 2: { v: tirOp.offset || 0 },
        });
        break;
      }
      case Op.LOAD_FILE: emitLoadFile(tirOp.stateSlot, tirOp.stringId); break;
      case Op.WRITE_FILE: emitWriteFile(tirOp.fdSlot, tirOp.bufSlot, tirOp.lenSlot); break;
      case Op.ALLOC: emitAlloc(tirOp.slot, tirOp.size); break;
      // libyoyo_* (Phase 4c)
      case Op.LIBYOYO_ALLOC: emitLibyoyoAlloc(tirOp.slot, tirOp.size); break;
      case Op.LIBYOYO_FREE: emitLibyoyoFree(tirOp.slot); break;
      case Op.LIBYOYO_OPEN: emitLibyoyoOpen(tirOp.slot, tirOp.stringId); break;
      case Op.LIBYOYO_READ: emitLibyoyoRead(tirOp.slot, tirOp.fdSlot, tirOp.size); break;
      case Op.LIBYOYO_WRITE: emitLibyoyoWrite(tirOp.fdSlot, tirOp.slot, tirOp.size); break;
      case Op.LIBYOYO_CLOSE: emitLibyoyoClose(tirOp.fdSlot); break;
      case Op.LIBYOYO_EXIT: emitLibyoyoExit(tirOp.slot); break;
      case Op.LIBYOYO_PRINT: emitLibyoyoPrint(tirOp.slot); break;
      case Op.LIBYOYO_TIME: emitLibyoyoTime(tirOp.slot); break;
      case Op.MEMCPY_DATA: stGet(RDI, tirOp.dst); ld(RSI, tirOp.blobOff); E.mov_ri(code, RCX, BigInt(tirOp.len)); code.u8(0xf3); code.u8(0xa4); break;
      case Op.MEMCPY_STATE: stGet(RDI, tirOp.dst); stGet(RSI, tirOp.src); stGet(RCX, tirOp.lenSlot); code.u8(0xf3); code.u8(0xa4); break;
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

  function emitStartup() {
    // V3-compatible startup stub: stack-based state, call generated code, ExitProcess
    E.sub_ri(code, RSP, 0x1008);
    E.lea_rr(code, R15, RSP, 0x808);
    E.call_rel(code, 0); code.fixups.push({ p: code.tell() - 4, n: 'H00' });
    E.add_ri(code, RSP, 0x1008);
    code.u8(0x31); code.u8(0xC9); // xor ecx,ecx (32-bit, matches V3)
    // Direct IAT call to ExitProcess (no shadow space, matching V3)
    const r = P['KERNEL32.dll.ExitProcess'];
    const c = CODE_RVA + code.tell();
    E.call_rip(code, r - (c + 6));
    code.iatFixups.push({ importName: 'KERNEL32.dll.ExitProcess', dispPos: code.tell() - 4, instrEnd: c + 6 });
  }

  function emitExit() {
    // ExitProcess is already in startup stub — no-op
  }

  function resolveFixups() {
    resolveFixupsStrict(code, { allowMissing: process.env.YOYO_STRICT_FIXUPS !== '1' });
  }

  function collectSlices(order) {
    const slices = new Map();
    const refOffset = new Map();
    for (let i = 0; i < order.length; i++) {
      const hh = order[i];
      const key = 'H' + hh;
      const start = code.labels[key];
      if (start === undefined) continue;
      refOffset.set(hh, start);
      let end = code.tell();
      for (let j = i + 1; j < order.length; j++) {
        const nextKey = 'H' + order[j];
        const nextStart = code.labels[nextKey];
        if (nextStart !== undefined) { end = nextStart; break; }
      }
      let buf = code.b.slice(start, end);
      if (buf.length > 0 && buf[buf.length - 1] === 0xc3) buf = buf.slice(0, -1);
      slices.set(hh, Buffer.from(buf));
    }
    const metaSizes = new Map();
    for (let i = 0; i < order.length; i++) {
      const hh = order[i];
      const start = refOffset.get(hh);
      if (start === undefined) continue;
      let end = code.tell();
      for (let j = i + 1; j < order.length; j++) {
        const nextStart = refOffset.get(order[j]);
        if (nextStart !== undefined) { end = nextStart; break; }
      }
      metaSizes.set(hh, end - start - 1);
    }
    return { slices, refOffset, metaSizes };
  }

  function finishPe() {
    assertTextLimit(code.tell(), TEXT_VS, 'win-emit-core .text');
    resolveFixups();
    const peFix = new PE(); peFix.subsys = 3;
    peFix.addImport('KERNEL32.dll', WIN_FUNCS);
    peFix.setCode(Buffer.alloc(code.tell(), 0x90)); peFix.setData(Buffer.alloc(1, 0)); peFix.build();
    resolveWinIatFixupsStrict(code, peFix);
    const total = Buffer.alloc(code.tell(), 0);
    code.b.slice(0, code.tell()).copy(total, 0);
    let dataSize = 0x10000;
    for (const b of prog.blobs || []) dataSize = Math.max(dataSize, b.off + b.data.length);
    dataSize = Math.max(dataSize, sOff + 4);
    dataSize = (dataSize + 0xfff) & ~0xfff;
    const data = Buffer.alloc(dataSize, 0);
    data.writeUInt32LE(strs.length, 0);
    for (let i = 0; i < strs.length; i++) {
      const off = strPos[i];
      const tb = Buffer.from(strs[i].text + '\0', 'ascii');
      data.writeUInt32LE(strs[i].text.length, off);
      tb.copy(data, off + 4);
    }
    Buffer.from('\r\n\0', 'ascii').copy(data, sOff);
    for (const b of prog.blobs || []) b.data.copy(data, b.off);
    pe.setCode(total); pe.setData(data);
    return pe.build();
  }

  return {
    code, emit, emitTirOp, emitStartup, emitExit, resolveFixups, collectSlices, finishPe, strs, strPos, sOff,
  };
}

function handlerOrderFromProg(prog, opts = {}) {
  if (opts.handlerOrder === 'file' && opts.handlerOrderList) return opts.handlerOrderList;
  return Object.keys(prog.handlers).map(k => +k).sort((a, b) => a - b);
}

function extractWinHandlerSlices(prog, opts = {}) {
  const ctx = createWinEmitContext(prog, opts);
  const order = handlerOrderFromProg(prog, opts);
  ctx.emitStartup();
  for (const op of prog.top || []) ctx.emit(op);
  ctx.emitExit();
  for (const h of order) {
    const ops = prog.handlers[h] ?? prog.handlers[String(h)];
    if (!ops) continue;
    ctx.code.label('H' + h);
    const { isBlobHandlerOps } = require('../blob-handlers.js');
    if (isBlobHandlerOps(ops)) {
      for (const op of ops) {
        if (op.op === 0xA1) ctx.emit(op);
      }
    } else {
      for (const op of ops) ctx.emit(op);
    }
    E.ret(ctx.code);
  }
  ctx.resolveFixups();
  const peFix = new PE(); peFix.subsys = 3;
  peFix.addImport('KERNEL32.dll', WIN_FUNCS);
  peFix.setCode(Buffer.alloc(ctx.code.tell(), 0x90)); peFix.setData(Buffer.alloc(1, 0)); peFix.build();
  resolveWinIatFixupsStrict(ctx.code, peFix);
  const { slices, refOffset, metaSizes: extractedMetaSizes } = ctx.collectSlices(order);
  return { slices, order, codeEnd: ctx.code.tell(), refOffset, metaSizes: extractedMetaSizes, codeLabels: ctx.code.labels };
}

function extractTirHandlerSlices(mod, opts = {}) {
  const prog = { strings: mod.strings, blobs: mod.blobs, top: [], handlers: {} };
  const ctx = createWinEmitContext(prog, opts);
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
  ctx.emitExit();

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
  ctx.resolveFixups();
  return { slices: ctx.collectSlices(order), order, codeEnd: ctx.code.tell() };
}

function compileFromAnalyzed(prog, opts = {}) {
  const ctx = createWinEmitContext(prog, opts);
  ctx.emitStartup();
  for (const op of prog.top) ctx.emit(op);
  ctx.emitExit();
  const order = handlerOrderFromProg(prog, opts);
  for (const h of order) {
    const ops = prog.handlers[h] ?? prog.handlers[String(h)];
    if (!ops) continue;
    ctx.code.label('H' + h);
    for (const op of ops) ctx.emit(op);
  }
  return ctx.finishPe();
}

const Op = require('../tir/ops.js').Op;

function compileFromTirModule(mod, opts = {}) {
  const prog = { strings: mod.strings || {}, blobs: mod.blobs || [], top: [], handlers: {} };
  const ctx = createWinEmitContext(prog, opts);
  ctx.emitStartup();

  const topFn = mod.functions.find(f => f.name === '__top');
  if (topFn) {
    for (const block of topFn.blocks) {
      for (const op of block.ops) {
        if (op.kind !== Op.STRING_DEF && op.kind !== Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
  }
  ctx.emitExit();

  const order = opts.handlerOrder === 'file'
    ? (mod.handlerOrder || [])
    : [...(mod.handlerOrder || [])].sort((a, b) => a - b);

  for (const hh of order) {
    const fn = mod.functions.find(f => f.name === 'H' + hh.toString(16));
    if (!fn) continue;
    ctx.code.label('H' + hh);
    for (const block of fn.blocks) {
      for (const op of block.ops) {
        if (op.kind === Op.LABEL) ctx.code.label('H' + op.hh);
        else if (op.kind !== Op.STRING_DEF && op.kind !== Op.DATA_BLOB) {
          ctx.emitTirOp(op);
        }
      }
    }
    E.ret(ctx.code);
  }
  return ctx.finishPe();
}

module.exports = {
  createWinEmitContext,
  extractWinHandlerSlices,
  extractTirHandlerSlices,
  compileFromAnalyzed,
  compileFromTirModule,
  buildStringLayout,
};
