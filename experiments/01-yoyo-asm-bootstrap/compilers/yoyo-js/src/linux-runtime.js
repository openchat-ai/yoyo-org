'use strict';

const E = require('./encode-x64.js');
const { STATE_TARGET, STATE_BUF_OFF, OUTPUT_STATE_BUF_OFF, LINUX_SYSCALL, O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC } = require('./platform-config.js');
const { BASE } = require('./elf-builder.js');
const CODE_RVA = BASE + 0x1000;

const RCX = 1, RDX = 2, RSP = 4, RDI = 7, RSI = 6, R8 = 8, R9 = 9, R10 = 10;
const RAX = 0, R12 = 12, R13 = 13, R14 = 14, R15 = 15;

function syscall(b) { b.u8(0x0f); b.u8(0x05); }

function buildLinuxStartup(dataRva, continueOff) {
  const b = new E.Buf();
  const leaState = b.tell();
  E.lea_rip(b, R15, dataRva + STATE_BUF_OFF - (CODE_RVA + leaState + 7));
  const leaData = b.tell();
  E.lea_rip(b, RAX, dataRva - (CODE_RVA + leaData + 7));
  E.mov_mr64(b, R15, 8 * 8, RAX);
  E.mov_ri(b, R14, 1n);
  if (continueOff !== undefined) E.jmp_rel(b, continueOff - b.tell() - 5);
  return b.b.slice(0, b.tell());
}

function buildLinuxOutputStartup(dataRva) {
  const b = new E.Buf();
  const leaState = b.tell();
  E.lea_rip(b, R15, dataRva + OUTPUT_STATE_BUF_OFF - (CODE_RVA + leaState + 7));
  const leaData = b.tell();
  E.lea_rip(b, RAX, dataRva - (CODE_RVA + leaData + 7));
  E.mov_mr64(b, R15, 8 * 8, RAX);
  E.mov_ri(b, R14, 1n);
  E.jmp_rel(b, 0);
  return b.b.slice(0, b.tell());
}

// Native forward-fixup resolver for the output compiler (state in R15).
// state_03=write_base, state_04=handler_table, state_05=fixup_hh, state_06=fixup_pos, state_07=count
function buildLinuxFixupResolver(startupLen) {
  const b = new E.Buf();
  const RAX = 0, RCX = 1, RDX = 2, RDI = 7, R8 = 8, R9 = 9, R10 = 10, R11 = 11, R15 = 15;

  E.xor_rr(b, RCX, RCX);
  E.mov_rm64(b, R10, R15, 7 * 8);

  const loopStart = b.tell();
  E.cmp_rr(b, RCX, R10);
  const jaeExitPos = b.tell();
  E.jcc32(b, 7, 0);

  E.mov_rr(b, R8, RCX);
  E.mov_ri(b, RAX, 4n);
  E.imul_rr(b, R8, RAX);

  E.mov_rm64(b, R11, R15, 5 * 8);
  E.mov_rr(b, RDI, R11);
  E.add_rr(b, RDI, R8);
  E.mov_rm(b, RAX, RDI, 0);

  E.mov_rm64(b, R11, R15, 6 * 8);
  E.mov_rr(b, RDI, R11);
  E.add_rr(b, RDI, R8);
  E.mov_rm(b, RDX, RDI, 0);

  E.cmp_ri(b, RDX, startupLen);
  const jbSkipPos = b.tell();
  E.jcc32(b, 6, 0);

  E.mov_rr(b, RDI, RAX);
  E.mov_ri(b, RAX, 4n);
  E.imul_rr(b, RDI, RAX);
  E.mov_rm64(b, R11, R15, 4 * 8);
  E.add_rr(b, R11, RDI);
  E.mov_rm(b, R9, R11, 0);

  E.mov_rr(b, RAX, R9);
  E.sub_rr(b, RAX, RDX);
  E.sub_ri(b, RAX, 4);

  E.mov_rm64(b, R11, R15, 3 * 8);
  E.mov_rr(b, RDI, R11);
  E.add_rr(b, RDI, RDX);
  E.mov_mr(b, RDI, 0, RAX, false);

  const skipLabel = b.tell();
  b.b.writeInt32LE(skipLabel - (jbSkipPos + 6), jbSkipPos + 2);

  E.add_ri(b, RCX, 1);
  const jmpPos = b.tell();
  E.jmp_rel(b, loopStart - (jmpPos + 5));

  const exitLabel = b.tell();
  b.b.writeInt32LE(exitLabel - (jaeExitPos + 6), jaeExitPos + 2);
  E.ret(b);
  return b.b.slice(0, b.tell());
}

function makeLinuxEmit(code, dr, strs, strPos) {
  function stSet(id, v) { E.mov_ri(code, RAX, BigInt(v)); E.mov_mr64(code, R15, id * 8, RAX); }
  function stGet(reg, id) { E.mov_rm64(code, reg, R15, id * 8); }
  function stPut(id, reg) { E.mov_mr64(code, R15, id * 8, reg); }
  function ld(r, o) {
    code.u8(0x48 + (r > 7 ? 4 : 0)); code.u8(0x8d); code.u8(0x05 | ((r & 7) << 3));
    const p = code.tell(); code.u32(0); const e = code.tell();
    code.dataFixups.push({ o, dispPos: p, instrEnd: CODE_RVA + e });
  }

  function emitLoadFile(stateId, strIdx) {
    ld(RDI, strPos[strIdx] + 4);
    E.mov_ri(code, RSI, BigInt(O_RDONLY));
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.open));
    syscall(code);
    E.mov_rr(code, R13, RAX);

    E.mov_rr(code, RDI, R13);
    E.mov_ri(code, RSI, 0n);
    E.mov_ri(code, RDX, 2n);
    E.mov_ri(code, RAX, 8n);
    syscall(code);
    E.mov_rr(code, R12, RAX);

    E.mov_rr(code, RDI, R13);
    E.mov_ri(code, RSI, 0n);
    E.mov_ri(code, RDX, 0n);
    E.mov_ri(code, RAX, 8n);
    syscall(code);

    E.mov_ri(code, RDI, 0n);
    E.mov_rr(code, RSI, R12);
    E.mov_ri(code, RDX, 3n);
    E.mov_ri(code, R10, 0x22n);
    E.mov_ri(code, R8, -1n);
    E.xor_rr(code, R9, R9);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.mmap));
    syscall(code);
    stPut(stateId, RAX);

    E.mov_rr(code, RDI, R13);
    stGet(RSI, stateId);
    E.mov_rr(code, RDX, R12);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.read));
    syscall(code);
    stPut(stateId + 1, R12);

    E.mov_rr(code, RDI, R13);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.close));
    syscall(code);
  }

  function emitWriteFile(stateId, strIdx, sizeId) {
    ld(RDI, strPos[strIdx] + 4);
    E.mov_ri(code, RSI, BigInt(O_WRONLY | O_CREAT | O_TRUNC));
    E.mov_ri(code, RDX, 0x1b6n);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.open));
    syscall(code);
    E.mov_rr(code, R13, RAX);

    E.mov_rr(code, RDI, R13);
    stGet(RSI, stateId);
    stGet(RDX, sizeId || 0);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.write));
    syscall(code);

    E.mov_rr(code, RDI, R13);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.close));
    syscall(code);
  }

  function emitAlloc(stateId, size) {
    E.mov_ri(code, RDI, 0n);
    E.mov_ri(code, RSI, BigInt(size));
    E.mov_ri(code, RDX, 7n);
    E.mov_ri(code, R10, 0x22n);
    E.mov_ri(code, R8, -1n);
    E.xor_rr(code, R9, R9);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.mmap));
    syscall(code);
    stPut(stateId, RAX);
  }

  function emitExit() {
    E.xor_rr(code, RDI, RDI);
    E.mov_ri(code, RAX, BigInt(LINUX_SYSCALL.exit));
    syscall(code);
  }

  return { emitLoadFile, emitWriteFile, emitAlloc, emitExit, stSet, stGet, stPut, ld };
}

module.exports = { buildLinuxStartup, buildLinuxOutputStartup, buildLinuxFixupResolver, makeLinuxEmit, syscall };
