'use strict';

const E = require('./encode-x64.js');
const { LINUX_SYSCALL, O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC } = require('./platform-config.js');

const RAX = 0, RDI = 7, RSI = 6, RDX = 2, R10 = 10, R8 = 8, R9 = 9;
const R12 = 12, R13 = 13;

function syscall(b) { b.u8(0x0f); b.u8(0x05); }

function hx(n, w) { return n.toString(16).padStart(w || 2, '0'); }
const H = n => '40 ' + hx(n);
const CH = n => '41 ' + hx(n);
const SET = (s, v) => '30 ' + hx(s) + ' ' + hx(v);
const GET = (d, s) => '60 ' + hx(d) + ' ' + hx(s);
const RET = () => 'FF';
const ADD = (s, v) => '61 ' + hx(s) + ' ' + hx(v);
const SUB = (s, v) => '62 ' + hx(s) + ' ' + hx(v);
const INC = s => '66 ' + hx(s);
const JE = n => '71 ' + hx(n);
const JMP = n => '70 ' + hx(n);

function emitByte(b) {
  return [SET(0x45, b), CH(0xE0)];
}

function emitBuf(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) out.push(...emitByte(buf[i]));
  return out;
}

function emitSignedDisp32(magnitude) {
  // Encode negative displacement as u32-LE via SET(0) then SUB magnitude.
  return [SET(0x4D, 0), SUB(0x4D, magnitude), CH(0xE5)];
}

function emitJmpOverString(name) {
  const str = Buffer.from(name + '\0', 'ascii');
  const jmpLen = 2;
  const leaLen = 7;
  const lines = [];
  lines.push(...emitByte(0xEB));
  lines.push(...emitByte(str.length));
  for (const b of str) lines.push(...emitByte(b));
  lines.push(...emitBuf([0x48, 0x8d, 0x3d]));
  lines.push(...emitSignedDisp32(str.length + leaLen));
  return lines;
}

function genLinuxAllocHandler() {
  const tail = new E.Buf();
  E.mov_ri(tail, RDX, 7n);
  E.mov_ri(tail, R10, 0x22n);
  E.mov_ri(tail, R8, -1n);
  E.xor_rr(tail, R9, R9);
  E.mov_ri(tail, RAX, BigInt(LINUX_SYSCALL.mmap));
  syscall(tail);

  const lines = [];
  lines.push('; H_60: Linux mmap alloc emit');
  lines.push(H(0x60));
  lines.push(...emitBuf([0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0xbe]));
  lines.push(CH(0xED) + '  ; size from state_51');
  lines.push('57 03 0E 4F'); lines.push(INC(0x0E));
  lines.push('57 03 0E 47'); lines.push(INC(0x0E));
  lines.push('57 03 0E 49'); lines.push(INC(0x0E));
  lines.push('57 03 0E 4B'); lines.push(INC(0x0E));
  lines.push(SET(0x45, 0));
  lines.push('57 03 0E 45'); lines.push(INC(0x0E));
  lines.push('57 03 0E 45'); lines.push(INC(0x0E));
  lines.push('57 03 0E 45'); lines.push(INC(0x0E));
  lines.push('57 03 0E 45'); lines.push(INC(0x0E));
  lines.push(...emitBuf(tail.b.slice(0, tail.tell())));
  lines.push(GET(0x46, 0x50));
  lines.push(CH(0xE3));
  lines.push(RET());
  lines.push('');
  return lines;
}

function genLinuxLoadFileHandler() {
  const lines = [];
  lines.push('; H_61: Linux LoadFile emit (anonymous mmap + read; matches linux-runtime.emitLoadFile)');
  lines.push(H(0x61));
  lines.push(SET(0x41, 0));
  lines.push('65 51 41');
  lines.push(JE(0xD3) + '  ; str_idx==0 -> input.ky');
  lines.push(...emitJmpOverString('output'));
  lines.push(JMP(0xD6));
  lines.push(H(0xD3));
  lines.push(...emitJmpOverString('input.ky'));
  lines.push(H(0xD6));

  // open(filename, O_RDONLY) -> fd (R13)
  const open = new E.Buf();
  E.mov_ri(open, RSI, BigInt(O_RDONLY));
  E.mov_ri(open, RAX, BigInt(LINUX_SYSCALL.open));
  syscall(open);
  lines.push(...emitBuf(open.b.slice(0, open.tell())));
  lines.push(...emitBuf([0x49, 0x89, 0xc5]));  // mov r13, rax

  // lseek(fd, 0, SEEK_END) -> file_size (R12)
  const lseekEnd = new E.Buf();
  E.mov_rr(lseekEnd, RDI, R13);
  E.mov_ri(lseekEnd, RSI, 0n);
  E.mov_ri(lseekEnd, RDX, 2n);  // SEEK_END = 2
  E.mov_ri(lseekEnd, RAX, 8n);  // SYS_lseek = 8
  syscall(lseekEnd);
  lines.push(...emitBuf(lseekEnd.b.slice(0, lseekEnd.tell())));
  lines.push(...emitBuf([0x49, 0x89, 0xc4]));  // mov r12, rax

  // lseek(fd, 0, SEEK_SET) -> rewind to start (so read() reads from beginning)
  const lseekStart = new E.Buf();
  E.mov_rr(lseekStart, RDI, R13);
  E.mov_ri(lseekStart, RSI, 0n);
  E.mov_ri(lseekStart, RDX, 0n);
  E.mov_ri(lseekStart, RAX, 8n);
  syscall(lseekStart);
  lines.push(...emitBuf(lseekStart.b.slice(0, lseekStart.tell())));

  // mmap(NULL, file_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) -> buffer
  // PROT = 3 (no PROT_EXEC!), FLAGS = MAP_PRIVATE | MAP_ANONYMOUS = 0x22
  // This avoids the EACCES that PROT_READ|PROT_WRITE|PROT_EXEC+MAP_SHARED produces.
  const map = new E.Buf();
  E.mov_ri(map, RDI, 0n);
  E.mov_rr(map, RSI, R12);                 // length = file_size
  E.mov_ri(map, RDX, 3n);                  // prot = RW only
  E.mov_ri(map, R10, 0x22n);               // flags = PRIVATE | ANONYMOUS
  E.mov_ri(map, R8, -1n);                  // fd = -1 (anonymous)
  E.xor_rr(map, R9, R9);
  E.mov_ri(map, RAX, BigInt(LINUX_SYSCALL.mmap));
  syscall(map);
  lines.push(...emitBuf(map.b.slice(0, map.tell())));

  // state[stateId] = buffer (RAX)
  lines.push(GET(0x46, 0x50));
  lines.push(CH(0xE3));  // stPut(state_50, RAX)

  // read(fd, buffer, file_size)
  // Need: rdi=fd, rsi=buffer, rdx=file_size
  // RAX has buffer; rdi would be overwritten, so move:
  lines.push(...emitBuf([0x48, 0x89, 0xc6])); // mov rsi, rax
  const readCall = new E.Buf();
  E.mov_rr(readCall, RDI, R13);            // rdi = fd (R13)
  E.mov_rr(readCall, RDX, R12);            // rdx = file_size (R12)
  E.mov_ri(readCall, RAX, BigInt(LINUX_SYSCALL.read));
  syscall(readCall);
  lines.push(...emitBuf(readCall.b.slice(0, readCall.tell())));

  // state[stateId+1] = file_size (R12)
  // Need: store R12 at [R15 + (stateId+1)*8]
  // Encoding: REX=4D 89 A7 disp32 (mov [r15+disp32], r12)
  //   REX = 0x40 | W(1) | R(1 for r12) | B(1 for r15) = 0x4D
  //   89 = MOV r/m64, reg64
  //   A7 = ModRM: mod=2, reg=4(R12), rm=7(R15)
  lines.push(ADD(0x50, 1));                // stateId+1
  lines.push(...emitBuf([0x4d, 0x89, 0xa7]));   // REX + 89 + ModRM
  lines.push(GET(0x46, 0x50));             // state_46 = state_50 = (stateId+1)
  lines.push(CH(0xE1));                   // compute disp = state_46*8
  lines.push(CH(0xE4));                   // emit disp32
  lines.push(SUB(0x50, 1));                // restore stateId

  // close(fd)
  const close = new E.Buf();
  E.mov_rr(close, RDI, R13);
  E.mov_ri(close, RAX, BigInt(LINUX_SYSCALL.close));
  syscall(close);
  lines.push(...emitBuf(close.b.slice(0, close.tell())));
  lines.push(RET());
  lines.push('');
  return lines;
}

function genLinuxWriteFileHandler() {
  const lines = [];
  lines.push('; H_62: Linux WriteFile emit');
  lines.push(H(0x62));
  lines.push(SET(0x41, 0));
  lines.push('65 51 41');
  lines.push(JE(0xD7) + '  ; str_idx==0 -> input.ky');
  lines.push(...emitJmpOverString('output'));
  lines.push(JMP(0xDA));
  lines.push(H(0xD7));
  lines.push(...emitJmpOverString('input.ky'));
  lines.push(JMP(0xDA));
  lines.push(H(0xDA));

  const open = new E.Buf();
  E.mov_ri(open, RSI, BigInt(O_WRONLY | O_CREAT | O_TRUNC));
  E.mov_ri(open, RDX, 0x1b6n);
  E.mov_ri(open, RAX, BigInt(LINUX_SYSCALL.open));
  syscall(open);
  lines.push(...emitBuf(open.b.slice(0, open.tell())));
  lines.push(...emitBuf([0x49, 0x89, 0xc5]));

  const write = new E.Buf();
  E.mov_rr(write, RDI, R13);
  lines.push(GET(0x46, 0x50));
  lines.push(CH(0xE2));
  lines.push(...emitBuf([0x48, 0x89, 0xc6]));
  lines.push(GET(0x46, 0x52));
  lines.push(CH(0xE2));
  lines.push(...emitBuf([0x48, 0x89, 0xc2]));
  E.mov_ri(write, RAX, BigInt(LINUX_SYSCALL.write));
  syscall(write);
  lines.push(...emitBuf(write.b.slice(0, write.tell())));

  const close = new E.Buf();
  E.mov_rr(close, RDI, R13);
  E.mov_ri(close, RAX, BigInt(LINUX_SYSCALL.close));
  syscall(close);
  lines.push(...emitBuf(close.b.slice(0, close.tell())));
  lines.push(RET());
  lines.push('');
  return lines;
}

function appendLinuxEmitHandlers(push) {
  for (const line of [
    ...genLinuxAllocHandler(),
    ...genLinuxLoadFileHandler(),
    ...genLinuxWriteFileHandler(),
  ]) push(line);
}

module.exports = { appendLinuxEmitHandlers };
