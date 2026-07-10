// ═══════════════════════════════════════════════════════════════════════════
// debug.js — Mini-KYC self-hosting debugger
// Self-contained Windows Debug API debugger with PE parsing, disassembly,
// crash analysis, and state introspection.  Minimal dependencies (koffi only).
// ═══════════════════════════════════════════════════════════════════════════
// Usage:
//   node debug.js                  - crash analysis mode (run yoyo.exe, dump on crash)
//   node debug.js --checkpoints    - INT3 checkpoint mode (place checkpoints at safe RVAs)
//   node debug.js --step           - single-step mode (one instruction at a time)
//   node debug.js --help           - show full usage
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// ─── Verify koffi ────────────────────────────────────────────────────────
let koffi;
try { koffi = require('koffi'); } catch {
  console.error('[!] koffi not found. Run: npm install');
  process.exit(1);
}

const OUT_DIR = path.join(__dirname, '..', 'debug-out');
if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

// ═══════════════════════════════════════════════════════════════════════════
// 1. PE Parser
// ═══════════════════════════════════════════════════════════════════════════
class PEParser {
  constructor(exePath) {
    this.data = fs.readFileSync(exePath);
    this.peOff = this._read(0x3C, 4).readUInt32LE(0);
    this.sections = [];
    this.iatByName = {};     // name -> { rva, hint }
    this.iatByIndex = [];    // [{name, rva, hint}] in IAT order
    this.iatBaseRVA = 0;     // RVA of the IAT array in .rdata
    this._parseSections();
    this._parseImports();
  }

  _read(off, len) { return this.data.slice(off, off + len); }

  rvaToFile(rva) {
    for (const s of this.sections)
      if (s.contains(rva)) return s.rvaToFile(rva);
    return null;
  }

  getSectionForRVA(rva) {
    return this.sections.find(s => s.contains(rva)) || null;
  }

  resolveIAT(iatRVA) {
    // iatRVA is an RVA into the IAT array
    const idx = (iatRVA - this.iatBaseRVA) / 8;
    if (idx >= 0 && idx < this.iatByIndex.length && Number.isInteger(idx))
      return this.iatByIndex[idx];
    // Not in our IAT - try to search backward or forward
    const fo = this.rvaToFile(iatRVA);
    if (fo !== null && fo + 8 <= this.data.length) {
      const val = this.data.readBigUInt64LE(fo);
      // The file contains IAT entries pointing to IMPORT_BY_NAME RVAs.
      // At load time they become actual function addresses.
      // We can't know what function it resolves to at runtime,
      // but we can check if it's within the import table.
      const func = this.iatByIndex.find(e => e.rva === iatRVA);
      if (func) return func;
      // Try to find an import entry that this IAT slot belongs to
      return { name: `iat_slot_0x${iatRVA.toString(16)}`, rva: iatRVA, hint: -1 };
    }
    return null;
  }

  _parseSections() {
    const numSects = this._read(this.peOff + 6, 2).readUInt16LE(0);
    const optSz = this._read(this.peOff + 0x14, 2).readUInt16LE(0);
    const secStart = this.peOff + 24 + optSz;
    for (let i = 0; i < numSects; i++) {
      const sOff = secStart + i * 40;
      const s = {
        name: this.data.slice(sOff, sOff + 8).toString('ascii').replace(/\0/g, '').trim(),
        vRVA: this._read(sOff + 12, 4).readUInt32LE(0),
        vSize: this._read(sOff + 8, 4).readUInt32LE(0),
        rSize: this._read(sOff + 16, 4).readUInt32LE(0),
        rOff: this._read(sOff + 20, 4).readUInt32LE(0),
        ch: this._read(sOff + 36, 4).readUInt32LE(0),
        contains(rva) { return rva >= this.vRVA && rva < this.vRVA + this.vSize; },
        rvaToFile(rva) { return this.rOff + (rva - this.vRVA); },
        perms() {
          const p = [];
          if (this.ch & 0x20000000) p.push('X');
          if (this.ch & 0x40000000) p.push('R');
          if (this.ch & 0x80000000) p.push('W');
          return p.join('');
        },
      };
      this.sections.push(s);
    }
  }

  _parseImports() {
    // DataDirectory[1] (Import) at peOff + 24 + 112 + 8
    const importRVA = this._read(this.peOff + 24 + 120, 4).readUInt32LE(0);
    if (!importRVA) return;
    const iidOff = this.rvaToFile(importRVA);
    if (iidOff === null) return;

    // Find IAT base from IMAGE_IMPORT_DESCRIPTOR
    for (let i = 0; ; i++) {
      const off = iidOff + i * 20;
      if (off + 20 > this.data.length) break;
      const oft = this._read(off, 4).readUInt32LE(0);    // OriginalFirstThunk
      const ft  = this._read(off + 16, 4).readUInt32LE(0); // FirstThunk
      if (oft === 0 && ft === 0) break;
      if (ft && !this.iatBaseRVA) this.iatBaseRVA = ft;

      // DLL name
      const nrv = this._read(off + 12, 4).readUInt32LE(0);
      const noff = this.rvaToFile(nrv);
      const dllEnd = this.data.indexOf(0, noff);
      const dllName = this.data.slice(noff, dllEnd).toString('ascii') || '(unknown)';

      // Read import thunks
      const thunkRVA = oft || ft;
      const thunkOff = this.rvaToFile(thunkRVA);
      if (thunkOff === null) continue;

      for (let j = 0; ; j++) {
        const to = thunkOff + j * 8;
        if (to + 8 > this.data.length) break;
        const entry = this.data.readBigUInt64LE(to);
        if (entry === 0n) break;

        if (entry & 0x8000000000000000n) {
          // Ordinal import
          const ord = Number(entry & 0xFFFFn);
          this.iatByIndex.push({ name: `${dllName}!#${ord}`, rva: ft + j * 8, hint: -1 });
        } else {
          const entryRVA = Number(entry);
          const ea = this.rvaToFile(entryRVA);
          if (ea !== null) {
            const hint = this._read(ea, 2).readUInt16LE(0);
            const ne = this.data.indexOf(0, ea + 2);
            const funcName = this.data.slice(ea + 2, ne).toString('ascii');
            const iatRVA = ft + j * 8;
            const info = { name: funcName, rva: iatRVA, hint, dll: dllName };
            this.iatByIndex.push(info);
            this.iatByName[funcName] = info;
            // Also store in iatByIndex at correct position
          }
        }
      }
    }
    // Sort by RVA
    this.iatByIndex.sort((a, b) => a.rva - b.rva);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Mini x64 Disassembler (covers patterns used by mini-kyc emitter)
// ═══════════════════════════════════════════════════════════════════════════
class MiniDisassembler {
  constructor(peParser) { this.pe = peParser; }

  // Decode one instruction at `offset` in `data`, return { mnemonic, bytes, size, target }
  disasmAt(data, offset, imageBase) {
    if (offset >= data.length) return { mnemonic: '(end)', bytes: [], size: 0 };
    const b = data.slice(offset);
    const bytes = [];
    const emit = (n) => { bytes.push(b[n]); if (b[n] === undefined) throw Error('undef'); };
    const tryPeek = (n) => (offset + n < data.length) ? data[offset + n] : 0;

    // Helper: REX prefix analysis
    const rex = () => {
      let w = 0, r = 0, x = 0, bb = 0;
      if (bytes.length > 0 && (bytes[0] & 0xF0) === 0x40) {
        const p = bytes[0];
        w = (p >> 3) & 1; r = (p >> 2) & 1; x = (p >> 1) & 1; bb = p & 1;
      }
      return { w, r, x, bb };
    };

    // Read signed 32-bit displacement from instruction bytes
    const disp32 = (at) => {
      const d = data.slice(offset + at, offset + at + 4);
      return d.readInt32LE(0);
    };

    // State slot decode: extract disp32 from mov [r15+disp], reg or mov reg, [r15+disp]
    const slotRef = (at, modrmByte) => {
      const mod = (modrmByte >> 6) & 3;
      const rm = modrmByte & 7;
      const r = (modrmByte >> 3) & 7;
      const rName = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][r];
      const rFull = rex().r ? `r${8+r}` : rName;
      if (rm === 7 && mod !== 3) { // [r15] with REX.B
        const baseReg = `r${15 + rex().bb}`;
        if (mod === 0) return { base: baseReg, disp: 0, size: 0, at };
        if (mod === 1) { emit(at); return { base: baseReg, disp: bytes[at] << (rex().bb?0:0), size: 1, at: at + 1 }; }
        if (mod === 2) { const d = data.slice(offset + at, offset + at + 4); emit(at); emit(at+1); emit(at+2); emit(at+3); return { base: baseReg, disp: d.readInt32LE(0), size: 4, at: at + 4 }; }
      }
      return null;
    };

    // ── 1-byte instructions ──
    if (b[0] === 0xC3) { emit(0); return { mnemonic: 'ret', bytes, size: 1 }; }
    if (b[0] === 0xCC) { emit(0); return { mnemonic: 'int3', bytes, size: 1 }; }
    if (b[0] === 0x90) { emit(0); return { mnemonic: 'nop', bytes, size: 1 }; }

    // ── 2-byte: 0F-prefixed ──
    if (b[0] === 0x0F && offset + 2 <= data.length) {
      // jcc rel32: 0F 8x xx xx xx xx
      const jccOpcodes = { 0x84:'je', 0x85:'jne', 0x8C:'jl', 0x8D:'jge',
                           0x8E:'jle', 0x8F:'jg', 0x82:'jb', 0x83:'jae',
                           0x86:'jbe', 0x87:'ja', 0x80:'jo', 0x81:'jno',
                           0x88:'js', 0x89:'jns', 0x8A:'jp', 0x8B:'jnp' };
      const opHi = b[1];
      if ((opHi >= 0x80 && opHi <= 0x8F) && offset + 6 <= data.length) {
        emit(0); emit(1); emit(2); emit(3); emit(4); emit(5);
        const d = data.slice(offset + 2, offset + 6).readInt32LE(0);
        const target = offset + 6 + d;
        const mnem = jccOpcodes[opHi] || `j${opHi.toString(16)}`;
        return { mnemonic: mnem, bytes, size: 6, target, targetRVA: (target - 0x400) + 0x1000 };
      }
      // movzx r64, r/m8: 0F B6 /r
      if (b[1] === 0xB6 && offset + 4 <= data.length) {
        emit(0); emit(1); const modrm = b[2]; emit(2);
        const mod = (modrm>>6)&3, rm = modrm&7, reg = (modrm>>3)&7;
        const regName = `r${reg + (rex().r?8:0)}`||`r${reg}`;
        if (mod === 0 && rm === 7) { // [r15] — from stGet for ldb
          emit(3);
          return { mnemonic: `movzx ${regName}, byte [r15+0x${b[3].toString(16)}]`, bytes, size: 4 };
        }
        if (mod === 0 && rm === 2) { // [rdx] — simple ldb
          return { mnemonic: `movzx ${regName}, byte [rdx]`, bytes, size: 3 };
        }
        if (mod === 0) {
          const rmName = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][rm];
          return { mnemonic: `movzx ${regName}, byte [${rmName}]`, bytes, size: 3 };
        }
        return { mnemonic: `movzx ${regName}, ...`, bytes, size: 3 };
      }
      // rep movsb: F3 A4
      if (b[1] === 0xA4 && b[0] === 0xF3 && offset + 2 <= data.length) {
        // Actually 0F F3 A4 is wrong; F3 A4 is rep movsb without 0F prefix
        // This won't be reached because b[0]==0x0F, but just in case:
        emit(0); emit(1);
        return { mnemonic: 'rep movsb', bytes, size: 2 };
      }
      // 0F B7 = movzx r16/r64
      if (b[1] === 0xB7 && offset + 4 <= data.length) {
        emit(0); emit(1); emit(2); const modrm = b[2];
        if ((modrm & 0xC7) === 0x02) { emit(3); return { mnemonic: `movzx r, word [rdx]`, bytes, size: 3 }; }
        return { mnemonic: `movzx ...`, bytes, size: 3 };
      }
    }

    // ── F3 A4 : rep movsb (without 0F prefix) ──
    if (b[0] === 0xF3 && b[1] === 0xA4 && offset + 2 <= data.length) {
      emit(0); emit(1);
      return { mnemonic: 'rep movsb', bytes, size: 2 };
    }

    // ── FF group: FF /2 = call [r/m], FF /4 = jmp [r/m] ──
    if (b[0] === 0xFF && offset + 2 <= data.length) {
      const modrm = b[1]; emit(0); emit(1);
      const mod = (modrm >> 6) & 3;
      const reg = (modrm >> 3) & 3; // FF uses bits 5-3 as sub-opcode
      const rm = modrm & 7;
      const op = ['inc','inc','call','call','jmp','jmp','push','undefined'][(modrm >> 3) & 7];
      // Only handle call [rip+disp32] (FF 15)
      if (reg === 2 && mod === 0 && rm === 5) { // call near [rip+disp32]
        const d = data.slice(offset + 2, offset + 6).readInt32LE(0);
        emit(2); emit(3); emit(4); emit(5);
        const nextOff = offset + 6;
        const iatRVA = (nextOff - 0x400) + 0x1000 + d;
        let funcName = '';
        if (this.pe) {
          const iat = this.pe.resolveIAT(iatRVA);
          if (iat) funcName = iat.name;
        }
        const targetAddr = imageBase ? `[0x${(imageBase + BigInt(iatRVA)).toString(16)}]` : '';
        return {
          mnemonic: funcName ? `call ${funcName}` : `call [rip+0x${d.toString(16)}]`,
          bytes, size: 6, target: iatRVA, targetRVA: iatRVA, funcName,
        };
      }
      if (reg === 2 && mod === 3) { // call reg
        const rmName = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][rm];
        return { mnemonic: `call ${rmName}`, bytes, size: 2 };
      }
      if (reg === 2) { // call [mem]
        // Only decoding the simple call [r15+...] case
        if (rm === 7 && mod === 1 && offset + 3 <= data.length) {
          emit(2);
          const disp = b[2];
          return { mnemonic: `call [r15+0x${disp.toString(16)}]`, bytes, size: 3 };
        }
        if (rm === 7 && mod === 2 && offset + 6 <= data.length) {
          const d = data.slice(offset + 2, offset + 6).readUInt32LE(0);
          emit(2); emit(3); emit(4); emit(5);
          return { mnemonic: `call [r15+0x${d.toString(16)}]`, bytes, size: 6 };
        }
        return { mnemonic: `call [rm=0x${rm.toString(16)}]`, bytes, size: 2 + (mod===2?4:mod===1?1:0) };
      }
      return { mnemonic: `ff ${modrm.toString(16)}`, bytes, size: 2 };
    }

    // ── E8 : call rel32 ──
    if (b[0] === 0xE8 && offset + 5 <= data.length) {
      const d = data.slice(offset + 1, offset + 5).readInt32LE(0);
      emit(0); emit(1); emit(2); emit(3); emit(4);
      const target = offset + 5 + d;
      const targetRVA = (target - 0x400) + 0x1000;
      return { mnemonic: `call 0x${targetRVA.toString(16)}`, bytes, size: 5, target: targetRVA };
    }

    // ── E9 : jmp rel32 ──
    if (b[0] === 0xE9 && offset + 5 <= data.length) {
      const d = data.slice(offset + 1, offset + 5).readInt32LE(0);
      emit(0); emit(1); emit(2); emit(3); emit(4);
      const target = offset + 5 + d;
      const targetRVA = (target - 0x400) + 0x1000;
      return { mnemonic: `jmp 0x${targetRVA.toString(16)}`, bytes, size: 5, target: targetRVA };
    }

      // ── 3-byte: 88 02 (mov [rdx], al) ──
      if (b[0] === 0x88 && b[1] === 0x02 && offset + 2 <= data.length) {
        emit(0); emit(1);
        return { mnemonic: 'mov [rdx], al', bytes, size: 2 };
      }

      // ── REX-prefixed MOV: 48|49|4B|4C|4D 89|8B + ModRM ──
    const hasREX = (b[0] & 0xF0) === 0x40;
    if (hasREX && offset + 3 <= data.length) {
      const rexVal = b[0];
      const op2 = b[1];
      const modrm = b[2];
      const mod = (modrm >> 6) & 3;
      const rm = (modrm & 7) + (rexVal & 1 ? 8 : 0);
      const reg = ((modrm >> 3) & 7) + ((rexVal >> 2) & 1 ? 8 : 0);
      const wBit = (rexVal >> 3) & 1;
      const regNames = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
                        'r8','r9','r10','r11','r12','r13','r14','r15'];

      const regName = regNames[reg] || `r${reg}`;
      const rmName = (mod === 3) ? (regNames[rm] || `r${rm}`) : null;

      // MOV r/m64, r64: 89
      // MOV r64, r/m64: 8B
      if (op2 === 0x89 || op2 === 0x8B) {
        const isLoad = (op2 === 0x8B);
        const mnem = isLoad ? 'mov' : 'mov';
        emit(0); emit(1); emit(2);

        // register-to-register
        if (mod === 3) {
          const dst = isLoad ? regName : rmName;
          const src = isLoad ? rmName : regName;
          return { mnemonic: `${mnem} ${dst}, ${src}`, bytes, size: 3 };
        }

        // [r15+disp8] or [r15+disp32] with REX.B containing R15
        if (rm === 15 || rm === 7) { // R15 is rm=7 with REX.B=1 -> 15, or rm=15 with REX.B
          if (mod === 0) {
            const slot = 0;
            const slotName = STATE_NAMES[slot] || '';
            const s = isLoad ? regName : regName;
            const dir = isLoad ? '→' : '←';
            return { mnemonic: `${mnem} ${regName}, [r15+0x0] // st[0x00]${slotName ? '='+slotName : ''} ${dir}`, bytes, size: 3 };
          }
          if (mod === 1 && offset + 3 <= data.length) {
            emit(3);
            const disp = b[3];
            const slot = disp / 8;
            const slotName = STATE_NAMES[slot] || '';
            const dir = isLoad ? '→' : '←';
            const dst = isLoad ? regName : `[r15+0x${disp.toString(16)}]`;
            const src = isLoad ? `[r15+0x${disp.toString(16)}]` : regName;
            return {
              mnemonic: `${mnem} ${dst}, ${src} // st[0x${slot.toString(16)}]${slotName ? '='+slotName : ''} ${dir}`,
              bytes, size: 4 + (mod===2?4:0),
            };
          }
          if (mod === 2 && offset + 6 <= data.length) {
            const d = data.slice(offset + 3, offset + 7).readInt32LE(0);
            emit(3); emit(4); emit(5); emit(6);
            const slot = d / 8;
            const slotName = STATE_NAMES[slot] || '';
            const dir = isLoad ? '→' : '←';
            return {
              mnemonic: `${mnem} ${regName}, [r15+0x${d.toString(16)}] // st[0x${slot.toString(16)}]${slotName ? '='+slotName : ''} ${dir}`,
              bytes, size: 7,
            };
          }
        }

        // Simple [reg+disp8] or [reg+disp32]
        let rmRegName = regNames[rm] || `r${rm}`;
        if (mod === 0) {
          return { mnemonic: `${mnem} ${regName}, [${rmRegName}]`, bytes, size: 3 };
        }
        if (mod === 1) {
          emit(3);
          return { mnemonic: `${mnem} ${regName}, [${rmRegName}+0x${b[3].toString(16)}]`, bytes, size: 4 };
        }
        if (mod === 2 && offset + 6 <= data.length) {
          const d = data.slice(offset + 3, offset + 7).readInt32LE(0);
          emit(3); emit(4); emit(5); emit(6);
          return { mnemonic: `${mnem} ${regName}, [${rmRegName}+0x${d.toString(16)}]`, bytes, size: 7 };
        }
        return { mnemonic: `${mnem} ...`, bytes, size: 3 };
      }

      // MOV r64, imm64: 48 B8..BF
      if ((op2 & 0xF8) === 0xB8) {
        const r = (op2 & 7) + (rexVal & 1 ? 8 : 0);
        const rn = regNames[r] || `r${r}`;
        emit(0); emit(1);
        if (offset + 10 <= data.length) {
          const imm = data.slice(offset + 2, offset + 10).readBigUInt64LE(0);
          emit(2); emit(3); emit(4); emit(5); emit(6); emit(7); emit(8); emit(9);
          return { mnemonic: `mov ${rn}, 0x${imm.toString(16)}`, bytes, size: 10 };
        }
        return { mnemonic: `mov ${rn}, ?`, bytes, size: 2 };
      }

      // ADD/SUB r/m64, imm8: 48 83 /0 (ADD) /5 (SUB) /7 (CMP)
      if (op2 === 0x83 && offset + 4 <= data.length) {
        const subOps = { 0:'add', 1:'or', 2:'adc', 3:'sbb', 4:'and', 5:'sub', 6:'xor', 7:'cmp' };
        const subOp = subOps[(modrm >> 3) & 7] || '?';
        emit(0); emit(1); emit(2);
        if ((modrm & 0xC7) === 0xC0) { // reg, imm8
          emit(3);
          const r = ((modrm >> 3) & 7) + (rexVal & 1 ? 8 : 0);
          const rn = regNames[r] || `r${r}`;
          return { mnemonic: `${subOp} ${rn}, 0x${b[3].toString(16)}`, bytes, size: 4 };
        }
        // ADD/SUB [r15+disp], imm8 (disp8 case)
        if ((modrm & 0xC7) === 0x47 && offset + 4 <= data.length) {
          emit(3);
          const slot = b[3] / 8;
          const slotName = STATE_NAMES[slot] || '';
          return { mnemonic: `${subOp} [r15+0x${b[3].toString(16)}], 0x${(offset+4<data.length ? data[offset+4] : 0).toString(16)} // st[0x${slot.toString(16)}]${slotName?'='+slotName:''}`, bytes, size: 4 };
        }
        return { mnemonic: `? ${(modrm >> 3) & 7} ...`, bytes, size: 3 };
      }

      // ADD/SUB r/m64, r64: 48 01 / 48 29 / 48 39
      if ((op2 === 0x01 || op2 === 0x29 || op2 === 0x39) && offset + 3 <= data.length) {
        const ops = { 0x01:'add', 0x29:'sub', 0x39:'cmp' };
        const opName = ops[op2] || '?';
        emit(0); emit(1); emit(2);
        if (mod === 3) {
          const dst = regNames[rm] || `r${rm}`;
          const src = regNames[reg] || `r${reg}`;
          return { mnemonic: `${opName} ${dst}, ${src}`, bytes, size: 3 };
        }
        return { mnemonic: `${opName} ...`, bytes, size: 3 };
      }

      // XOR: 48 31 /r
      if (op2 === 0x31 && offset + 3 <= data.length) {
        emit(0); emit(1); emit(2);
        if (mod === 3) {
          const dst = regNames[rm] || `r${rm}`;
          const src = regNames[reg] || `r${reg}`;
          return { mnemonic: `xor ${dst}, ${src}`, bytes, size: 3 };
        }
        return { mnemonic: `xor ...`, bytes, size: 3 };
      }

      // LEA: 48 8D /r
      if (op2 === 0x8D && offset + 4 <= data.length) {
        emit(0); emit(1); emit(2);
        const addrReg = regNames[rm] || `r${rm}`;
        const dst = regNames[reg] || `r${reg}`;
        if (mod === 1) { emit(3); return { mnemonic: `lea ${dst}, [${addrReg}+0x${b[3].toString(16)}]`, bytes, size: 4 }; }
        if (mod === 0) { return { mnemonic: `lea ${dst}, [${addrReg}]`, bytes, size: 3 }; }
        if (mod === 2 && offset + 7 <= data.length) {
          const d = data.slice(offset + 3, offset + 7).readInt32LE(0);
          emit(3); emit(4); emit(5); emit(6);
          return { mnemonic: `lea ${dst}, [${addrReg}+0x${d.toString(16)}]`, bytes, size: 7 };
        }
        // RIP-relative LEA
        if (mod === 0 && rm === 5) {
          const d = data.slice(offset + 3, offset + 7).readInt32LE(0);
          emit(3); emit(4); emit(5); emit(6);
          return { mnemonic: `lea ${dst}, [rip+0x${d.toString(16)}]`, bytes, size: 7, target: (offset+7-0x400+0x1000)+d };
        }
        return { mnemonic: `lea ${dst}, [...]`, bytes, size: 3 + (mod===2?4:mod===1?1:0) };
      }

      // PUSH/POP: 50-5F with REX (e.g., 41 50 = push r8)
      if (op2 >= 0x50 && op2 <= 0x5F) {
        const isPop = (op2 >= 0x58);
        const r = (op2 & 7) + (rexVal & 1 ? 8 : 0);
        const rn = regNames[r] || `r${r}`;
        emit(0); emit(1);
        return { mnemonic: `${isPop ? 'pop' : 'push'} ${rn}`, bytes, size: 2 };
      }

      // CMP: 48 3B /r (cmp r64, r/m64)
      if (op2 === 0x3B && offset + 3 <= data.length) {
        emit(0); emit(1); emit(2);
        if (mod === 3) {
          const dst = regNames[reg] || `r${reg}`;
          const src = regNames[rm] || `r${rm}`;
          return { mnemonic: `cmp ${dst}, ${src}`, bytes, size: 3 };
        }
        return { mnemonic: `cmp ...`, bytes, size: 3 };
      }

      // 88 02 = mov [rdx], al (REX-less variant)
      if (b[0] === 0x88 && b[1] === 0x02 && offset + 2 <= data.length) {
        emit(0); emit(1);
        return { mnemonic: 'mov [rdx], al', bytes, size: 2 };
      }

      // REX-prefixed 88 and 89 for byte stores
      if ((op2 === 0x88 || op2 === 0x89) && offset + 3 <= data.length) {
        emit(0); emit(1); emit(2);
        const rmReg = regNames[rm] || `r${rm}`;
        if (mod === 0) return { mnemonic: `mov [${rmReg}], ${regName}`, bytes, size: 3 };
        if (mod === 1) { emit(3); return { mnemonic: `mov [${rmReg}+0x${b[3].toString(16)}], ${regName}`, bytes, size: 4 }; }
        return { mnemonic: `mov ..., ${regName}`, bytes, size: 3 };
      }

      return { mnemonic: `... (REX=0x${rexVal.toString(16)} op=0x${op2.toString(16)})`, bytes, size: 2 };
    }

    // Non-REX 88/89 mov [mem], reg
    if ((b[0] === 0x88 || b[0] === 0x89) && offset + 2 <= data.length) {
      emit(0); emit(1);
      const modrm = b[1];
      const mod = (modrm >> 6) & 3;
      const reg = (modrm >> 3) & 7;
      const rm = modrm & 7;
      const regNames = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];
      const regName = regNames[reg] || `r${reg}`;
      if (mod === 0 && rm === 2) {
        return { mnemonic: `mov [rdx], ${regName}`, bytes, size: 2 };
      }
      if (mod === 0) {
        return { mnemonic: `mov [${regNames[rm]}], ${regName}`, bytes, size: 2 };
      }
      if (mod === 1) { emit(2); return { mnemonic: `mov ..., ${regName}`, bytes, size: 3 }; }
      return { mnemonic: `mov ..., ${regName}`, bytes, size: 2 };
    }

    // Non-REX: INC/DEC/PUSH/POP reg (40-4F without REX meaning, but we already handled REX prefix)
    if (b[0] >= 0x50 && b[0] <= 0x5F && offset + 1 <= data.length) {
      emit(0);
      const r = b[0] & 7;
      const rn = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][r];
      const isPop = b[0] >= 0x58;
      return { mnemonic: `${isPop ? 'pop' : 'push'} ${rn}`, bytes, size: 1 };
    }

    // ── INT3 (already covered above for 0xCC) ──

    // Catch-all for unknown instruction
    emit(0);
    return { mnemonic: `db 0x${b[0].toString(16)}`, bytes, size: 1 };
  }

  // Disassemble N instructions starting from `offset` in `data`
  disasmRange(data, offset, count, imageBase) {
    const result = [];
    let off = offset;
    for (let i = 0; i < count && off < data.length; i++) {
      try {
        const insn = this.disasmAt(data, off, imageBase);
        if (insn.size === 0) break;
        insn.offset = off;
        result.push(insn);
        off += insn.size;
      } catch (e) {
        result.push({ mnemonic: `(err: ${e.message})`, bytes: [], size: 1, offset: off });
        off += 1;
      }
    }
    return result;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. State Slot Names
// ═══════════════════════════════════════════════════════════════════════════
const STATE_NAMES = {};
{
  const names = {
    0x00: 'scratch_00',
    0x01: 'scratch_01',
    0x02: 'output_buf',
    0x03: 'write_base',
    0x04: 'handler_offsets',
    0x05: 'fixup_hh',
    0x06: 'fixup_pos',
    0x07: 'fixup_cnt',
    0x08: 'data_base',
    0x09: 'first_handler',
    0x0A: 'file_buf',
    0x0B: 'file_size',
    0x0C: 'scanner_read_ptr',
    0x0D: 'scanner_end_ptr',
    0x0E: 'code_offset',
    0x0F: 'scanner_byte',
    0x10: 'scanner_state',
    0x11: 'scanner_acc',
    0x12: 'scanner_digit_cnt',
    0x13: 'scanner_opcode',
    0x14: 'scanner_arg_idx',
    0x15: 'defined_handlers',
    0x40: 'scratch_40',
    0x41: 'scratch_41',
    0x42: 'scratch_42',
    0x43: 'scratch_43',
    0x44: 'scratch_44',
    0x45: 'byte_to_emit',
    0x46: 'state_id',
    0x47: 'loop_var_i',
    0x48: 'addr_ptr',
    0x49: 'b1_disp',
    0x4A: 'arg_lo',
    0x4B: 'b3_disp',
    0x4C: 'addr_base',
    0x4D: 'u32_val',
    0x4E: 'rel32_end',
    0x4F: 'b0_disp',
    0x50: 'arg0',
    0x51: 'arg1',
    0x52: 'arg2',
    0x53: 'scratch_53',
    0xF0: 'jcc_cond',
    0xF7: 'defined[hh]',
    0xF8: 'scratch_F8',
    0xF9: 'load_u32',
  };
  for (const [k, v] of Object.entries(names)) STATE_NAMES[parseInt(k)] = v;
}

// Read handler offset table from PE .data+0xFE00 (handler_map)
// Returns Map<h_int, file_offset_in_text>
function readHandlerMap(pePath) {
  const buf = fs.readFileSync(pePath);
  // .data RVA + 0xFE00 = handler_map start
  // .data starts at PE_DATA_FILE_OFF (0x8400 + 0x400 = 0x8800 in file)
  // handler_map_off = DATA_FILE_OFF + HANDLER_MAP_OFF = 0x8800 + 0xFE00 = 0x18600
  const MAP_OFF = 0x18600;
  if (buf.length < MAP_OFF + 0x404) return null;
  const table = new Map();
  for (let i = 0; i < 256; i++) {
    const off = buf.readUInt32LE(MAP_OFF + i * 4);
    if (off > 0 && off < 0x8000) table.set(i, off);
  }
  const codeEnd = buf.readUInt32LE(MAP_OFF + 0x400);
  return { table, codeEnd };
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Debugger
// ═══════════════════════════════════════════════════════════════════════════
const kernel32 = koffi.load('kernel32.dll');

const BOOL = koffi.alias('BOOL', 'int');
const DWORD = koffi.alias('DWORD', 'uint32');
const WORD = koffi.alias('WORD', 'uint16');
const BYTE = koffi.alias('BYTE', 'uint8');
const HANDLE = koffi.alias('HANDLE', 'void*');
const LPCWSTR = koffi.alias('LPCWSTR', 'uint64');
const LPWSTR = koffi.alias('LPWSTR', 'uint64');
const LPBYTE = koffi.alias('LPBYTE', 'uint64');
const LPTHREAD_START_ROUTINE = koffi.alias('LPTHREAD_START_ROUTINE', 'void*');

const STARTUPINFOW = koffi.struct('STARTUPINFOW', {
  cb: DWORD, lpReserved: LPWSTR, lpDesktop: LPWSTR, lpTitle: LPWSTR,
  dwX: DWORD, dwY: DWORD, dwXSize: DWORD, dwYSize: DWORD,
  dwXCountChars: DWORD, dwYCountChars: DWORD, dwFillAttribute: DWORD,
  dwFlags: DWORD, wShowWindow: WORD, cbReserved2: WORD, lpReserved2: LPBYTE,
  hStdInput: HANDLE, hStdOutput: HANDLE, hStdError: HANDLE,
});

const PROCESS_INFORMATION = koffi.struct('PROCESS_INFORMATION', {
  hProcess: HANDLE, hThread: HANDLE, dwProcessId: DWORD, dwThreadId: DWORD,
});

const DEBUG_EVENT = koffi.struct('DEBUG_EVENT', {
  dwDebugEventCode: DWORD, dwProcessId: DWORD, dwThreadId: DWORD,
  u: koffi.array('uint8', 80),
});

const CONTEXT_SIZE = 1232;
const CTX = {
  ContextFlags: 0x30,
  Rax: 0x78, Rcx: 0x80, Rdx: 0x88, Rbx: 0x90,
  Rsp: 0x98, Rbp: 0xA0, Rsi: 0xA8, Rdi: 0xB0,
  R8: 0xB8, R9: 0xC0, R10: 0xC8, R11: 0xD0,
  R12: 0xD8, R13: 0xE0, R14: 0xE8, R15: 0xF0,
  Rip: 0xF8,
};

const CreateProcessW = kernel32.func('CreateProcessW', 'BOOL',
  [LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, BOOL, DWORD, 'void*', LPCWSTR,
   koffi.pointer(STARTUPINFOW), koffi.pointer(PROCESS_INFORMATION)]);

const WaitForDebugEvent = kernel32.func('WaitForDebugEvent', 'BOOL',
  [koffi.pointer(DEBUG_EVENT), DWORD]);

const ContinueDebugEvent = kernel32.func('ContinueDebugEvent', 'BOOL',
  [DWORD, DWORD, DWORD]);

const GetThreadContext = kernel32.func('GetThreadContext', 'BOOL',
  ['void*', 'void*']);

const SetThreadContext = kernel32.func('SetThreadContext', 'BOOL',
  ['void*', 'void*']);

const ReadProcessMemory = kernel32.func('ReadProcessMemory', 'BOOL',
  ['void*', 'void*', 'void*', 'size_t', koffi.out(koffi.pointer(DWORD))]);

const WriteProcessMemory = kernel32.func('WriteProcessMemory', 'BOOL',
  ['void*', 'void*', 'void*', 'size_t', koffi.out(koffi.pointer(DWORD))]);

const DebugActiveProcessStop = kernel32.func('DebugActiveProcessStop', 'BOOL', ['DWORD']);
const CloseHandle = kernel32.func('CloseHandle', 'BOOL', ['void*']);

const EXCEPTION_DEBUG_EVENT = 1;
const CREATE_PROCESS_DEBUG_EVENT = 3;
const EXIT_PROCESS_DEBUG_EVENT = 5;
const EXCEPTION_BREAKPOINT = 0x80000003;
const EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
const EXCEPTION_SINGLE_STEP = 0x80000004;
const DBG_CONTINUE = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// Union offset within DEBUG_EVENT (after 3 DWORDs + 4 bytes alignment padding = 16)
const U_OFFSET = 16;

function toWide(s) {
  const buf = Buffer.from(s + '\0', 'ucs2');
  return koffi.address(buf);
}

class Debugger {
  constructor(exePath) {
    this.exePath = exePath;
    this.imageBase = 0n;
    this.processHandle = null;
    this.mainThreadHandle = null;
    this.processId = 0;
    this.stdinReadHandle = null;
    this.tempExePath = null;
    this.cleanedUp = false;
    this.pe = null;
    this.disasm = null;
    this.codeData = null; // .text section data for disassembly
    this.mode = 'crash';  // 'crash' | 'checkpoints' | 'step'
    this.stepCount = 0;
    this.lastHitRVA = 0;
  }

  cleanup() {
    if (this.cleanedUp) return;
    this.cleanedUp = true;

    try {
      if (this.mainThreadHandle) {
        CloseHandle(this.mainThreadHandle);
        this.mainThreadHandle = null;
      }
    } catch {}

    try {
      if (this.processHandle) {
        DebugActiveProcessStop(this.processId);
        CloseHandle(this.processHandle);
        this.processHandle = null;
      }
    } catch {}

    try {
      if (this.stdinReadHandle) {
        CloseHandle(this.stdinReadHandle);
        this.stdinReadHandle = null;
      }
    } catch {}

    if (this.tempExePath && this.tempExePath !== this.exePath && fs.existsSync(this.tempExePath)) {
      try {
        fs.unlinkSync(this.tempExePath);
      } catch {}
    }
  }

  shutdown(code = 0, message) {
    if (message) console.log(message);
    this.cleanup();
    process.exit(code);
  }

  allocateContext() {
    const buf = Buffer.alloc(CONTEXT_SIZE);
    return { ptr: koffi.address(buf), buf };
  }

  readMem(addr, size) {
    const buf = Buffer.alloc(size);
    const br = [0];
    const ok = ReadProcessMemory(this.processHandle, addr, buf, size, br);
    return ok && br[0] === size ? buf : null;
  }

  readState(r15, slot) {
    if (!r15) return null;
    const buf = this.readMem(Number(r15) + slot * 8, 8);
    return buf ? buf.readBigUInt64LE(0) : null;
  }

  readStates(r15) {
    const result = [];
    for (let slot = 0; slot < 0x60; slot++) {
      const v = this.readState(r15, slot);
      if (v !== null) result.push({ slot, val: v });
    }
    return result;
  }

  getRegs(ctxBuf) {
    const b = ctxBuf.buf || ctxBuf;
    const g = off => b.readBigUInt64LE(off);
    return {
      Rip: g(CTX.Rip), Rsp: g(CTX.Rsp), Rbp: g(CTX.Rbp),
      Rax: g(CTX.Rax), Rcx: g(CTX.Rcx), Rdx: g(CTX.Rdx), Rbx: g(CTX.Rbx),
      Rsi: g(CTX.Rsi), Rdi: g(CTX.Rdi),
      R8: g(CTX.R8), R9: g(CTX.R9), R10: g(CTX.R10), R11: g(CTX.R11),
      R12: g(CTX.R12), R13: g(CTX.R13), R14: g(CTX.R14), R15: g(CTX.R15),
    };
  }

  rva(addr) { return Number(addr - this.imageBase); }

  rvaToFileOff(rva) {
    // Convert RVA to file offset based on .text section
    if (this.pe) {
      const fo = this.pe.rvaToFile(rva);
      if (fo !== null) return fo;
    }
    // Fallback: assume .text at RVA 0x1000, file offset 0x400
    return (rva - 0x1000) + 0x400;
  }

  // Find all ff 15 (call [rip+disp32]) sites in .text for API tracing
  findCallSites() {
    if (!this.codeData || !this.pe) return [];
    const sites = [];
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) return [];
    const textRVA = textSec.vRVA;
    const textFileOff = textSec.rOff;
    for (let off = 0; off < this.codeData.length - 6; off++) {
      if (this.codeData[off] === 0xFF && this.codeData[off+1] === 0x15) {
        const disp = this.codeData.readInt32LE(off + 2);
        const nextOff = off + 6;
        const iatRVA = textRVA + nextOff + disp;
        const iat = this.pe.resolveIAT(iatRVA);
        if (iat && !iat.name.startsWith('iat_slot_')) {
          const callRVA = textRVA + off;
          sites.push({ rva: callRVA, name: iat.name });
        }
      }
    }
    return sites;
  }

  // ── Dump Functions ──

  dumpRegs(regs) {
    console.log(`  RIP=0x${regs.Rip.toString(16)}  RSP=0x${regs.Rsp.toString(16)}  RBP=0x${regs.Rbp.toString(16)}`);
    console.log(`  RAX=0x${regs.Rax.toString(16)}  RCX=0x${regs.Rcx.toString(16)}  RDX=0x${regs.Rdx.toString(16)}  RBX=0x${regs.Rbx.toString(16)}`);
    console.log(`  RSI=0x${regs.Rsi.toString(16)}  RDI=0x${regs.Rdi.toString(16)}  R8=0x${regs.R8.toString(16)}  R9=0x${regs.R9.toString(16)}`);
    console.log(`  R10=0x${regs.R10.toString(16)} R11=0x${regs.R11.toString(16)} R12=0x${regs.R12.toString(16)} R13=0x${regs.R13.toString(16)}`);
    console.log(`  R14=0x${regs.R14.toString(16)} R15=0x${regs.R15.toString(16)}`);
  }

  dumpStates(r15) {
    if (!r15 || r15 === 0n) return;
    const states = this.readStates(r15);
    if (states.length === 0) return;
    const nonZero = states.filter(s => s.val !== 0n);
    if (nonZero.length === 0) return;
    console.log('');
    console.log('  ── State Slots (non-zero) ──');
    for (const { slot, val } of nonZero) {
      const name = STATE_NAMES[slot] || '';
      const comment = name ? `  // ${name}` : '';
      const hex = val.toString(16).padStart(16, '0');
      // Show ASCII if it looks like a pointer/string
      let extra = '';
      if (val > 0x1000 && val < 0x7FFFFFFF0000n) {
        const buf = this.readMem(Number(val), 16);
        if (buf) {
          const ascii = Array.from(buf.slice(0, 8)).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
          if (ascii.replace(/\\./g,'').length > 2) extra = ` → "${ascii}"`;
        }
      }
      console.log(`    st[0x${slot.toString(16).padStart(2, '0')}] = 0x${hex}${comment}${extra}`);
    }
  }

  dumpStack(rsp) {
    if (!rsp) return;
    console.log('');
    console.log('  ── Stack Trace (RSP-relative, up to 16 entries) ──');
    for (let i = 0; i < 16; i++) {
      const addr = Number(rsp) + i * 8;
      const buf = this.readMem(addr, 8);
      if (!buf) break;
      const val = buf.readBigUInt64LE(0);
      if (val === 0n) continue;
      const rva = this.rva(val);
      const section = this.pe ? this.pe.getSectionForRVA(rva & 0xFFFFF) : null;
      let info = '';
      if (section) {
        info = ` (→ ${section.name}+0x${(rva - section.vRVA).toString(16)})`;
        // Try to find function name if in IAT
        if (this.pe) {
          const iat = this.pe.resolveIAT(rva);
          if (iat) info = ` → ${iat.name}`;
        }
      }
      console.log(`    [rsp+0x${(i*8).toString(16)}] 0x${val.toString(16).padStart(16, '0')}${info}`);
    }
  }

  dumpDisasmAt(rip, count) {
    if (!this.codeData || !this.pe) return;
    console.log('');
    const ripRVA = this.rva(rip);
    console.log(`  ── Disassembly (${count} insns @ RVA 0x${ripRVA.toString(16)}) ──`);
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) { console.log('    (no .text section)'); return; }
    const textRVA = textSec.vRVA;
    const textFileOff = textSec.rOff;
    // fileOff is offset within codeData (which starts at textSec.rOff)
    const fileOff = this.rvaToFileOff(ripRVA) - textFileOff;
    if (fileOff < 0 || fileOff >= this.codeData.length) {
      console.log('    (outside .text section)');
      return;
    }
    const insns = this.disasm.disasmRange(this.codeData, fileOff, count, this.imageBase);
    for (const insn of insns) {
      const hexBytes = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
      // insn.offset is relative to codeData start (which = textFileOff in file, textRVA in RVA)
      const rva = (insn.offset + textFileOff - textFileOff) + textRVA;
      // Actually insn.offset is the offset within codeData, so RVA = textRVA + insn.offset
      const rvaStr = `RVA 0x${(insn.offset + textRVA).toString(16).padStart(4, '0')}`;
      const marker = (insn.offset + textRVA === ripRVA) ? '  <─── RIP' : '';
      console.log(`    ${rvaStr}  ${hexBytes.padEnd(20)}  ${insn.mnemonic}${marker}`);
    }
  }

  dumpFaultRegion(addr) {
    console.log('');
    console.log('  ── Fault Analysis ──');
    const faultRVA = this.rva(addr);
    if (faultRVA > 0 && faultRVA < 0x10000) {
      const section = this.pe ? this.pe.getSectionForRVA(faultRVA) : null;
      if (section) {
        console.log(`    Fault address 0x${addr.toString(16)} is in ${section.name}+0x${(faultRVA - section.vRVA).toString(16)}`);
      } else {
        console.log(`    Fault address 0x${addr.toString(16)} (RVA 0x${faultRVA.toString(16)}) is OUTSIDE mapped sections`);
      }
    } else if (Number(addr) < 0x10000) {
      console.log(`    Fault address 0x${addr.toString(16)} is near NULL → possible null pointer dereference`);
    } else {
      console.log(`    Fault address 0x${addr.toString(16)} is outside expected range`);
    }
  }

  // Diff helper: compare running gen2 .text vs Node compileFromAnalyzed
  // Loads handlers/slices via extractWinHandlerSlices; finds the handler containing
  // the given RVA and prints a side-by-side byte diff.
  diffAgainstNode(handlerHH, ripRva, windowBefore = 64, windowAfter = 192) {
    if (!fs.existsSync('projects/yoyo.ty')) {
      console.log('  [diff-node] no projects/yoyo.ty');
      return;
    }
    let parse, analyze, extractWinHandlerSlices;
    try {
      ({ parse, analyze } = require('../src/yoyo.js'));
      ({ extractWinHandlerSlices } = require('../src/backends/win-emit-core.js'));
    } catch (e) {
      console.log('  [diff-node] require failed:', e.message);
      return;
    }
    const src = fs.readFileSync('projects/yoyo.ty', 'utf8');
    const prog = analyze(parse(src));
    const handlers = Object.keys(prog.handlers).map(k => +k).sort((a,b) => a - b);
    let layout;
    try {
      layout = extractWinHandlerSlices(prog, { handlerOrder: 'file', handlerOrderList: handlers });
    } catch (e) {
      console.log('  [diff-node] extract failed:', e.message);
      return;
    }
    if (handlerHH === undefined) {
      let best = -1, bestHH = -1;
      if (this.handlerTable) {
        for (const [hh, off] of this.handlerTable.entries) {
          const entryRva = 0x1000 + off;
          if (entryRva <= ripRva && entryRva > best) { best = entryRva; bestHH = hh; }
        }
      }
      if (bestHH < 0) { console.log('  [diff-node] no handler map; pass handlerHH explicitly'); return; }
      handlerHH = bestHH;
    }
    const slice = layout.slices.get(handlerHH);
    if (!slice) { console.log('  [diff-node] H_' + handlerHH.toString(16) + ' not in Node slice output'); return; }
    if (!this.handlerTable) { console.log('  [diff-node] no handler_map'); return; }
    const expectedTextOff = this.handlerTable.entries.get(handlerHH);
    if (expectedTextOff === undefined) { console.log('  [diff-node] H_' + handlerHH.toString(16) + ' not in handler_map'); return; }
    const cd = this.codeData;
    const nodeBuf = slice;
    const gen2Off = expectedTextOff;
    const ripOff = ripRva - 0x1000;
    const start = Math.max(0, ripOff - windowBefore);
    const end = Math.min(nodeBuf.length, ripOff + windowAfter);
    console.log('');
    console.log('  -- diff(Node H_' + handlerHH.toString(16).padStart(2,'0') + ' vs gen2 @ .text+0x' + expectedTextOff.toString(16) + ') --');
    console.log('  RIP at .text-offset 0x' + ripOff.toString(16) + ', window .text+0x' + start.toString(16) + '..+0x' + end.toString(16));
    console.log('  offset  | Node | gen2');
    let diffs = 0;
    for (let i = start; i < end; i++) {
      const nb = nodeBuf[i];
      const gb = cd[gen2Off + i];
      const mark = nb !== gb ? '*' : ' ';
      if (nb !== gb) diffs++;
      const pointer = (gen2Off + i === ripOff) ? ' <-- RIP' : '';
      console.log('    +0x' + i.toString(16).padStart(4,'0') + ' : ' + nb.toString(16).padStart(2,'0') + '    ' + gb.toString(16).padStart(2,'0') + '    ' + mark + pointer);
    }
    console.log('  byte diffs in window: ' + diffs + ' / ' + (end - start));
    console.log('  Node slice size: ' + nodeBuf.length + 'B, gen2 handler size: ' + (cd.length - gen2Off) + 'B remaining');
  }

  // ── Save diagnostics to timestamped file ──

  saveDiag(totalWait, regs, ripRVA) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const diagPath = path.join(OUT_DIR, `diag-${timestamp}.txt`);
    const lines = [];
    const w = (s) => lines.push(s);
    w(`Debug Diagnostic — ${new Date().toISOString()}`);
    w(`EXE: ${this.exePath}`);
    w(`Mode: ${this.mode}  Wait: ${totalWait}s`);
    w(`ImageBase: 0x${this.imageBase.toString(16)}`);
    if (regs) {
      w(`RIP=0x${regs.Rip.toString(16)}  RSP=0x${regs.Rsp.toString(16)}`);
      w(`RAX=0x${regs.Rax.toString(16)}  RCX=0x${regs.Rcx.toString(16)}  RDX=0x${regs.Rdx.toString(16)}  RBX=0x${regs.Rbx.toString(16)}`);
      w(`RSI=0x${regs.Rsi.toString(16)}  RDI=0x${regs.Rdi.toString(16)}  R15=0x${regs.R15.toString(16)}`);
    }
    if (ripRVA !== undefined) {
      w(`\nDisassembly @ RVA 0x${ripRVA.toString(16)}:`);
      const fileOff = this.rvaToFileOff(ripRVA);
      if (this.codeData) {
        const textSec = this.pe.sections.find(s => s.name === '.text');
        if (textSec) {
          const codeOff = fileOff - textSec.rOff;
          if (codeOff >= 0 && codeOff < this.codeData.length) {
            const insns = this.disasm.disasmRange(this.codeData, codeOff, 16, this.imageBase);
            for (const insn of insns) {
              const hexB = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
              const rva = textSec.vRVA + insn.offset;
              w(`  RVA 0x${rva.toString(16)}  ${hexB.padEnd(20)}  ${insn.mnemonic}`);
            }
          }
        }
      }
    }
    if (regs && regs.R15) {
      w(`\nState slots (non-zero):`);
      for (let slot = 0; slot < 0x60; slot++) {
        const buf = this.readMem(Number(regs.R15) + slot * 8, 8);
        if (!buf) break;
        const val = buf.readBigUInt64LE(0);
        if (val === 0n) continue;
        const name = STATE_NAMES[slot] || '';
        w(`  st[0x${slot.toString(16).padStart(2, '0')}] = 0x${val.toString(16).padStart(16, '0')}${name ? '  // ' + name : ''}`);
      }
    }
    fs.writeFileSync(diagPath, lines.join('\n'));
    console.error(`[*] Diagnostics saved: ${diagPath}`);
  }

  // ── New instrumentation modes (added 2026-07-05) ──
  // Snapshot: which handlers have we entered, how many times?
  // Stores per-hit event log so we can print summaries at exit.
  initInstrumentation(opts) {
    // opts = { traceHandlers, watchSlots, filter, auditRel32, maxHits,
    //          crashHexRva, crashHexBefore, crashHexAfter, memcpyAnalysis,
    //          diffNodeAtCrash, diffNodeHH }
    this.instOpts = opts;
    this.eventLog = [];     // array of { type, hit, rva, extra }
    this.handlerCounts = new Map();  // int hh -> int count
    this.handlerFirstSeen = new Map(); // int hh -> hit number (first time)
    this.lastState = null;          // for diff display
    this.lastCodeOff = null;        // for delta tracking
    this._emitByteTotal = 0;        // running count of state_0e advances (observed)
    this._stopRequested = false;
    this._hitsSeen = 0;
  }

  // Compute rel32 from given RVA back to caller position from bytes at patchOff
  // patchOffRVA = absolute RVA where 4-byte rel32 starts (i.e. addr_of_e8 + 1)
  resolveRel32(patchRva) {
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) return null;
    const fileOff = this.pe.rvaToFile(patchRva);
    if (fileOff === null || fileOff + 4 > this.pe.data.length) return null;
    const rel = this.pe.data.readInt32LE(fileOff);
    // next_ip = patchRva + 4
    // target = next_ip + rel = patchRva + 4 + rel
    return { rel, target: patchRva + 4 + rel };
  }

  // Dump emit trace for a specific handler entry
  // Compares:
  //   - state_0e (expected .text byte position)
  //   - state_45 (last byte that was emit)
  //   - handler_map[hh] (recorded handler offset)
  //   - actual bytes at handler_map[hh] (from .text)
  dumpEmitTrace(hh, regs) {
    const r15 = regs.R15;
    if (!r15 || r15 === 0n) {
      console.log(`  [trace-emit] H_${hh.toString(16).padStart(2, '0')}: R15 is null`);
      return;
    }
    const state0e = this.readState(r15, 0x0e);
    const state45 = this.readState(r15, 0x45);
    const state4d = this.readState(r15, 0x4d);
    const state07 = this.readState(r15, 0x07);
    const line = `  [emit H_${hh.toString(16).padStart(2, '0')}] state_0e=0x${(state0e||0n).toString(16).padStart(4,'0')} state_45=0x${Number(state45||0n).toString(16).padStart(2,'0')} state_4d=0x${(state4d||0n).toString(16).slice(-12)} state_07=${state07||0n}`;
    console.log(line);
    if (this.eventLog.length < 200) this.eventLog.push({ type: 'emit', hh, line });
    // Read handler_table[hh] if .data section loaded
    if (this.handlerTable) {
      const tableRVA = this.handlerTable.rva;
      const fileOff = this.pe.rvaToFile(tableRVA + hh * 4);
      if (fileOff !== null && fileOff + 8 <= this.pe.data.length) {
        const expected_off = this.pe.data.readUInt32LE(fileOff);
        const actual_rip_in_text = this.rva(regs.Rip) - 0x1000;
        const delta = actual_rip_in_text - expected_off;
        console.log(`    handler_map[0x${hh.toString(16)}]=0x${expected_off.toString(16)} (got 0x${actual_rip_in_text.toString(16)}, Δ=${delta})`);
        if (delta !== 0 && this.eventLog.length < 200) {
          this.eventLog.push({ type: 'mismatch', hh, expected: expected_off, actual: actual_rip_in_text, delta });
        }
      }
    }
  }

  // Audit rel32 at the immediate next byte after RIP for E8/E9/0F 8x sites
  // If RIP is on the call/jmp instruction, the rel32 starts 1 byte later (E8/E9) or 2 later (0F 8x)
  auditRel32(regs) {
    if (!this.codeData) return;
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) return;
    const ripRva = this.rva(regs.Rip);
    const fo = this.pe.rvaToFile(ripRva);
    if (fo === null || fo + 6 >= this.pe.data.length) return;
    const b = this.codeData[fo - textSec.rOff];
    let relOff, insnLen;
    if (b === 0xe8 || b === 0xe9) { relOff = 1; insnLen = 5; }
    else if (b === 0x0f && (this.codeData[fo - textSec.rOff + 1] & 0xf0) === 0x80) {
      relOff = 2; insnLen = 6;
    } else return; // not a PC-relative branch
    const rel = this.codeData.readInt32LE(fo - textSec.rOff + relOff);
    const nextIp = ripRva + insnLen;
    const target = nextIp + rel;
    console.log(`  [rel32-audit] @ RVA 0x${ripRva.toString(16)}: ${b===0xe8?'call':b===0xe9?'jmp':'jcc'} target=0x${target.toString(16)} (rel=${rel})`);
    if (this.eventLog.length < 200) this.eventLog.push({ type: 'rel32', rva: ripRva, target });
  }

  // Watch specific state slots over time — show on hit
  watchStateDump(regs, label) {
    if (!this.instOpts || !this.instOpts.watchSlots) return;
    if (!regs.R15 || regs.R15 === 0n) return;
    const parts = [];
    for (const slot of this.instOpts.watchSlots) {
      const v = this.readState(regs.R15, slot);
      const name = STATE_NAMES[slot] || '';
      const hex = (v === null ? 'null' : '0x' + v.toString(16).padStart(16, '0'));
      const lastHex = this.lastState && this.lastState[slot] !== undefined ? this.lastState[slot] : null;
      const delta = (v !== null && lastHex !== null && hex !== lastHex) ? ' ←' : '';
      parts.push(`st[0x${slot.toString(16).padStart(2,'0')}]=${hex}${delta}`);
    }
    if (parts.length) {
      console.log(`  [watch ${label || ''}] ${parts.join('  ')}`);
    }
    if (regs.R15) {
      this.lastState = {};
      for (const slot of this.instOpts.watchSlots) {
        const v = this.readState(regs.R15, slot);
        this.lastState[slot] = v === null ? null : '0x' + v.toString(16).padStart(16, '0');
      }
    }
  }

  // ── Bulk rel32 audit (no checkpoint needed): scan entire .text ──
  // For every E8/E9/0F 8x site in .text, decode the rel32 and classify:
  //   - "OK   : inside .text; lands on a handler_map entry" (matches a known handler)
  //   - "OK-:  intra-handler forward branch (within one handler)"
  //   - "BACK : backward branch (intra-handler loop, usually fine)"
  //   - "BAD  : outside .text or hits NN (uninitialized)"
  // This catches off-by-N rel32 bugs deterministically without running.
  fullRel32Audit() {
    if (!this.codeData || !this.pe || !this.handlerTable) {
      console.log('  [full-rel32-audit] requires .text + PE + handler_map');
      return;
    }
    const cd = this.codeData;
    let totalE8=0, totalE9=0, totalCC=0, bad=0, ok=0;
    const handlerMap = new Map();
    for (const [hh, off] of this.handlerTable.entries) handlerMap.set(off, hh);
    for (let off = 0; off < cd.length - 5; off++) {
      const b = cd[off];
      if (b === 0xe8) {
        totalE8++;
        const rel = cd.readInt32LE(off + 1);
        const target = off + 5 + rel;  // .text-relative
        if (target < 0 || target >= cd.length) {
          console.log(`  [BAD  ] E8 at .text+0x${off.toString(16)}: target=.text+0x${target.toString(16)} OUT OF BOUNDS`);
          bad++; continue;
        }
        // Check whether target bytes look like a real handler or part of one
        const hh = handlerMap.get(target);
        const hhClose = hh !== undefined ? hh : handlerMap.get(this.findNearestHandler(target));
        ok++;
      } else if (b === 0xe9) {
        totalE9++;
        const rel = cd.readInt32LE(off + 1);
        const target = off + 5 + rel;
        if (target < 0 || target >= cd.length) { bad++; console.log(`  [BAD  ] E9 at .text+0x${off.toString(16)}: target OUT OF BOUNDS`); }
      } else if (b === 0x0f && cd[off + 1] >= 0x80 && cd[off + 1] <= 0x8f && off + 6 <= cd.length) {
        const rel = cd.readInt32LE(off + 2);
        const target = off + 6 + rel;
        if (target < 0 || target >= cd.length) { bad++; console.log(`  [BAD  ] 0F 8x at .text+0x${off.toString(16)}: target OUT OF BOUNDS`); }
        else ok++;
        totalCC++;
      }
    }
    console.log(`  [full-rel32-audit] E8=${totalE8}, E9=${totalE9}, 0F8x=${totalCC}; out-of-bounds=${bad}`);
  }

  // Boot-time scan: every LEA rax, [rip+disp32] in .text, classified.
  dumpLeaTargets() {
    if (!this.codeData || !this.pe) { console.log('  [dump-lea] no .text / PE'); return; }
    const cd = this.codeData;
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) return;
    const textRvaBase = textSec.vRVA;
    let l_total = 0, l_outside = 0, l_in_text = 0, l_in_iat = 0, l_in_data = 0;
    const out = [];
    for (let i = 0; i < cd.length - 7; i++) {
      const b0 = cd[i];
      if (b0 !== 0x48 || cd[i+1] !== 0x8d) continue;
      if (cd[i+2] !== 0x05) continue;
      l_total++;
      const disp = cd.readInt32LE(i+3);
      const ipRva = textRvaBase + i + 7;
      const targetRva = ipRva + disp;
      let cls = 'unknown';
      if (this.pe.iatBaseRVA && targetRva >= this.pe.iatBaseRVA && targetRva < this.pe.iatBaseRVA + 0x100) { cls = 'IAT'; l_in_iat++; }
      else {
        const dataSec = this.pe.sections.find(s => s.name === '.data' || s.name === '.rdata');
        if (dataSec && targetRva >= dataSec.vRVA && targetRva < dataSec.vRVA + dataSec.vSize) { cls = dataSec.name; l_in_data++; }
        else if (targetRva < textRvaBase || targetRva >= textRvaBase + textSec.vSize) { cls = 'OUTSIDE .text'; l_outside++; }
        else { cls = 'inside .text'; l_in_text++; }
      }
      const iat = this.pe.resolveIAT ? this.pe.resolveIAT(targetRva) : null;
      const symName = (iat && iat.name) ? ('sym=' + iat.name) : '';
      const fileOff = this.pe.rvaToFile(targetRva);
      let ascii = '';
      if (fileOff !== null && fileOff + 16 <= this.pe.data.length) {
        ascii = Array.from(this.pe.data.slice(fileOff, fileOff + 16)).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      }
      out.push({ rva: textRvaBase + i, disp, ipRva, targetRva, cls, symName, ascii });
    }
    console.log('');
    console.log('  -- dumpLeaTargets: ' + l_total + ' LEA rax, [rip+disp32] instructions --');
    for (const o of out) {
      console.log('  RVA 0x' + o.rva.toString(16).padStart(4,'0') + ': lea rax, [rip+0x' + o.disp.toString(16) + '] -> RVA 0x' + o.targetRva.toString(16).padStart(8,'0') + ' (' + o.cls + ')' + (o.symName ? ' ' + o.symName : '') + (o.ascii && o.ascii.replace(/\./g,'') ? ' "' + o.ascii + '"' : ''));
    }
    console.log('  summary: in IAT=' + l_in_iat + ' in .data/.rdata=' + l_in_data + ' inside .text=' + l_in_text + ' OUTSIDE .text=' + l_outside);
    if (l_outside > 0) console.log('  ** WARNING: ' + l_outside + ' LEAs target outside .text — likely wrong base **');
  }

  // Find nearest handler_map entry ≤ off
  findNearestHandler(off) {
    let best = -1;
    for (const [hh, hOff] of this.handlerTable.entries) {
      if (hOff <= off && hOff > best) best = hOff;
    }
    return best;
  }

  // After diff against Node, dump summary: which forward-fixup E8 rel32s in gen2
  // point to wrong address (delta != 0). Auto-detected after --diff-node.
  // Quick scan: walk current .text, decode every FF 15 (call [rip+disp32])
  // and verify the resolved IAT target is within the IAT region.
  scanRel32Mismatches(_ignoredRva) {
    if (!this.handlerTable || !this.codeData) return;
    const cd = this.codeData;
    const codeEnd = this.handlerTable.codeEnd;
    if (!this.pe) { console.log('  [scanRel32] no PE'); return; }
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (!textSec) return;
    const iatRvaBase = this.pe.iatBaseRVA || 0;
    let inspected = 0, e8Mismatched = 0, e8OutOfRange = 0, e8Forward = 0;
    let ff15Count = 0, ff15OutOfRange = 0, ff15Suspicious = 0;
    const offByRange = new Map();
    const sampleLines = [];
    if (this.pe && this.pe.iatByIndex) {
      for (const e of this.pe.iatByIndex) {}
    }
    for (let i = 0; i < cd.length - 6; i++) {
      const b = cd[i];
      if (b === 0xff && cd[i + 1] === 0x15) {
        const disp = cd.readInt32LE(i + 2);
        const ipRva = textSec.vRVA + i + 6;
        const targetRva = ipRva + disp;
        inspected++;
        ff15Count++;
        const targetFileOff = this.pe.rvaToFile(targetRva);
        if (targetFileOff === null || targetFileOff >= this.pe.data.length) {
          ff15OutOfRange++;
          if (sampleLines.length < 12) sampleLines.push(`  RVA 0x${(textSec.vRVA + i).toString(16)}: call[rip+${disp.toString(16)}] -> RVA 0x${targetRva.toString(16)} OUT OF RANGE`);
        } else {
          const iat = this.pe.resolveIAT(targetRva);
          if (iat && iat.name && iat.name.startsWith('iat_slot_')) {
            ff15Suspicious++;
            if (sampleLines.length < 12) sampleLines.push(`  RVA 0x${(textSec.vRVA + i).toString(16)}: call[rip+${disp.toString(16)}] -> RVA 0x${targetRva.toString(16)} (resolved: ${iat.name})`);
          }
        }
        continue;
      }
      if (b === 0xe8) {
        const rel = cd.readInt32LE(i + 1);
        const target = i + 5 + rel;
        inspected++;
        e8Forward++;
        if (target < 0 || target > codeEnd) {
          e8OutOfRange++;
          continue;
        }
        const hOff = this.handlerTable.entries.get(target);
        if (hOff === undefined) continue;
        const expectedRel = hOff - (i + 5);
        const delta = rel - expectedRel;
        if (delta !== 0) {
          e8Mismatched++;
          const cnt = offByRange.get(delta) || 0;
          offByRange.set(delta, cnt + 1);
          if (sampleLines.length < 12) {
            sampleLines.push(`  RVA 0x${(textSec.vRVA + i).toString(16)}: call → RVA 0x${(textSec.vRVA + target).toString(16)} (handler), rel=0x${rel.toString(16)} expected=0x${expectedRel.toString(16)} Δ=${delta}`);
          }
        }
      }
    }
    console.log('');
    console.log('  -- scanRel32Mismatches --');
    console.log('  E8 (handler-call) inspected: ' + e8Forward);
    console.log('  FF 15 (IAT-call) inspected: ' + ff15Count);
    console.log('  E8 with wrong rel32 (handler target): ' + e8Mismatched);
    console.log('  E8 out-of-range / external: ' + e8OutOfRange);
    console.log('  FF 15 out-of-range: ' + ff15OutOfRange);
    console.log('  FF 15 resolved to unknown iat_slot (gen2 IAT shifted): ' + ff15Suspicious);
    if (offByRange.size > 0) {
      console.log('  E8 delta distribution:');
      const sortedDelta = [...offByRange.entries()].sort((a,b) => a[0] - b[0]);
      for (const [d, c] of sortedDelta) {
        console.log('    Δ=' + (d >= 0 ? '+' : '') + d.toString(16) + ' (' + d + '): ' + c + ' occurrences');
      }
    }
    if (sampleLines.length > 0) {
      console.log('  first 12 sample sites (E8 + IAT mismatches):');
      for (const s of sampleLines) console.log(s);
    }
  }

  // Hex-dump bytes around a given RVA (default = RIP at hit time).
  // Argument rva is an RVA, e.g. 0x121c (which lives at .text offset 0x21c,
  // since CODE_RVA=0x1000). Pass isRva=true (default) for RVA-relative input.
  hexDumpRange(rva, bytesBefore, bytesAfter, isRva = true) {
    if (!this.codeData) { console.log('  [hex-dump] no .text'); return; }
    // If rva is in RVA space (>=0x1000), convert to .text offset
    const textOff = isRva ? (rva - 0x1000) : rva;
    const start = Math.max(0, textOff - bytesBefore);
    const end = Math.min(this.codeData.length, textOff + bytesAfter);
    const len = end - start;
    const lines = [];
    for (let i = start; i < end; i += 16) {
      const hex = Array.from(this.codeData.slice(i, Math.min(i + 16, end)))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(this.codeData.slice(i, Math.min(i + 16, end)))
        .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      const lineAddr = isRva ? (0x1000 + i) : i;
      lines.push(`  RVA 0x${lineAddr.toString(16).padStart(4, '0')}: ${hex.padEnd(48 * 2 - 1)}  ${ascii}`);
    }
    const startRva = isRva ? (0x1000 + start) : start;
    const endRva = isRva ? (0x1000 + end) : end;
    console.log(`  ── Hex dump RVA 0x${startRva.toString(16)}..0x${endRva.toString(16)} (${len}B) ──`);
    for (const l of lines) console.log(l);
    console.log('');
  }

  // Analyse rep movsb params: compare RSI/RDI/RCX with state_08, state_03+state_0e, state_4d-ish
  // Triggered when RIP is at F3 A4
  memcpyParamsAnalysis(regs) {
    if (!regs || !regs.R15 || regs.R15 === 0n) return;
    // Read state
    const state08 = this.readState(regs.R15, 0x08);  // data_base
    const state03 = this.readState(regs.R15, 0x03);  // write_base = output_buf + 0x400
    const state0e = this.readState(regs.R15, 0x0e);  // code_offset
    const state4d = this.readState(regs.R15, 0x4d);  // rel32 / u32_val
    const rdi = Number(regs.Rdi);
    const rsi = Number(regs.Rsi);
    const rcx = Number(regs.Rcx);
    let msg = '  ── memcpy analysis (F3 A4) ──';
    msg += `\n    RCX (count)        = 0x${rcx.toString(16)} = ${rcx} bytes`;
    msg += `\n    RSI (src)          = 0x${rsi.toString(16)}`;
    if (state08) msg += `\n    state_08 + 0x4000 = 0x${(Number(state08) + 0x4000).toString(16)}  (delta=${rsi - (Number(state08) + 0x4000)})`;
    msg += `\n    RDI (dst)          = 0x${rdi.toString(16)}`;
    if (state03) msg += `\n    state_03           = 0x${state03.toString(16)} (write_base)`;
    if (state0e) msg += `\n    state_0e           = 0x${state0e.toString(16)} (code_offset) → expected .text+0x${state0e.toString(16)}`;
    msg += `\n    state_4d           = 0x${state4d ? state4d.toString(16) : 'null'} (last u32)`;
    // Check if RSI / RDI look like page-aligned output_buf + offset
    if (rsi && (rsi & 0xfff) !== 0) msg += `\n    ⚠ RSI is NOT page-aligned (low-12-bit ${rsi & 0xfff} ≠ 0)`;
    console.log(msg);
  }

  // ── Analyze crash context ──

  analyzeCrash(regs, exAddr) {
    console.log('');
    console.log('  ═══════════════════════════════════════════════');
    console.log('  ⚡ CRASH ANALYSIS');
    console.log('  ═══════════════════════════════════════════════');

    // Check for null pointers
    if (regs.Rdx === 0n) console.log('  ⚠ RDX is NULL — possible null parameter to API call');
    if (regs.Rcx === 0n) console.log('  ⚠ RCX is NULL — possible null handle');
    if (regs.R8 === 0n) console.log('  ⚠ R8 is NULL');
    if (regs.R15 === 0n) console.log('  ⚠ R15 is NULL — state pointer destroyed!');

    // Check RIP
    const ripRVA = this.rva(regs.Rip);
    const section = this.pe ? this.pe.getSectionForRVA(ripRVA) : null;

    // Disassemble at RIP
    if (this.codeData) {
      const fileOff = (ripRVA - 0x1000) + 0x400;
      if (fileOff >= 0 && fileOff + 12 <= this.codeData.length) {
        // Try to decode the crashing instruction
        try {
          const insn = this.disasm.disasmAt(this.codeData, fileOff, this.imageBase);
          console.log(`  Crashing instruction: ${insn.mnemonic}`);
          if (insn.funcName) {
            console.log(`  → Calling: ${insn.funcName}`);
            // Check parameters for common API issues
            if (insn.funcName === 'CloseHandle') {
              const h = regs.Rcx;
              if (h === 0n) console.log('  ⚠ CloseHandle called with NULL handle');
              else console.log(`  ✓ CloseHandle(0x${h.toString(16)}) — handle looks valid`);
            }
            if (insn.funcName === 'ReadFile') {
              const buf = regs.Rdx;
              if (buf === 0n) console.log('  ⚠ ReadFile called with NULL buffer (RDX=0)');
              else console.log(`  ✓ ReadFile: buffer=0x${buf.toString(16)} size=0x${regs.R8.toString(16)}`);
            }
            if (insn.funcName === 'WriteFile') {
              const buf = regs.Rdx;
              if (buf === 0n) console.log('  ⚠ WriteFile called with NULL buffer (RDX=0)');
            }
            if (insn.funcName === 'VirtualAlloc') {
              console.log(`  VirtualAlloc(addr=0x${regs.Rcx.toString(16)}, size=0x${regs.Rdx.toString(16)}, type=0x${regs.R8.toString(16)}, prot=0x${regs.R9.toString(16)})`);
            }
            if (insn.funcName === 'CreateFileA') {
              console.log(`  CreateFileA(name=0x${regs.Rcx.toString(16)}, ...)`);
            }
          }
          if (insn.targetRVA) {
            const targetSection = this.pe ? this.pe.getSectionForRVA(insn.targetRVA) : null;
            if (targetSection) {
              console.log(`  Target: ${targetSection.name}+0x${(insn.targetRVA - targetSection.vRVA).toString(16)}`);
            }
          }
        } catch (e) {
          console.log(`  (disassembly error: ${e.message})`);
        }
      }
    }

    // Stack analysis
    this.dumpStack(regs.Rsp);

    // Fault region
    if (exAddr) {
      const faultRVA = this.rva(exAddr);
      console.log('');
      console.log(`  Exception at: 0x${exAddr.toString(16)} (RVA 0x${faultRVA.toString(16)})`);
      const faultSection = this.pe ? this.pe.getSectionForRVA(faultRVA) : null;
      if (faultSection) {
        console.log(`  In section: ${faultSection.name} (${faultSection.perms()}) at offset 0x${(faultRVA - faultSection.vRVA).toString(16)}`);
      }
    }

    console.log('');
  }

  // ── Run the debug loop ──

  run(mode = 'crash', checkpoints = [], inputFile = null, maxWaitSec = 10) {
    this.mode = mode;

    // Parse PE
    this.pe = new PEParser(this.exePath);
    this.disasm = new MiniDisassembler(this.pe);

    // Read .text section for disassembly
    const textSec = this.pe.sections.find(s => s.name === '.text');
    if (textSec) {
      this.codeData = this.pe.data.slice(textSec.rOff, textSec.rOff + textSec.rSize);
    }

    // Create patched exe with INT3 checkpoints (if any)
    let tmpPath = this.exePath;
    let origBytes = {};
    if (checkpoints.length > 0) {
      const result = this.patchInt3(this.exePath, checkpoints);
      tmpPath = result.tmpPath;
      origBytes = result.origBytes;
    }

    this.stdinReadHandle = this.openInput(inputFile);
    this.tempExePath = (checkpoints.length > 0) ? tmpPath : null;

    // Setup STARTUPINFOW
    const siBuf = Buffer.alloc(Number(STARTUPINFOW.size));
    siBuf.writeUInt32LE(Number(STARTUPINFOW.size), 0);
    siBuf.writeUInt32LE(0x00000100, 0x48); // dwFlags STARTF_USESTDHANDLES
    if (this.stdinReadHandle) {
      siBuf.writeBigUInt64LE(BigInt(koffi.address(this.stdinReadHandle).toString()), 0x48);
    }
    const piBuf = Buffer.alloc(Number(PROCESS_INFORMATION.size));

    const ok = CreateProcessW(
      toWide(tmpPath),
      koffi.address(Buffer.alloc(0)),
      koffi.address(Buffer.alloc(0)),
      koffi.address(Buffer.alloc(0)),
      1,
      0x00000003, // DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS
      koffi.address(Buffer.alloc(0)),
      koffi.address(Buffer.alloc(0)),
      koffi.address(siBuf),
      koffi.address(piBuf),
    );
    if (!ok) { this.shutdown(1, '[!] CreateProcessW failed'); }

    this.processHandle = piBuf.readBigUInt64LE(0);
    this.mainThreadHandle = piBuf.readBigUInt64LE(8);
    this.processId = piBuf.readUInt32LE(16);
    console.log(`[*] Process started: PID ${this.processId}`);
    console.log(`[*] Mode: ${mode}`);
    if (checkpoints.length > 0)
      console.log(`[*] Checkpoints: ${checkpoints.map(r => '0x' + r.toString(16)).join(', ')}`);

    this.debugLoop(piBuf, origBytes, maxWaitSec);
  }

  patchInt3(exePath, rvas) {
    const buf = fs.readFileSync(exePath);
    const origBytes = {};
    for (const rva of rvas) {
      const fileOff = 0x400 + (rva - 0x1000);
      if (fileOff >= buf.length) continue;
      origBytes[rva] = buf[fileOff];
      buf[fileOff] = 0xCC;
      console.log(`[*] INT3 at RVA 0x${rva.toString(16)} (file 0x${fileOff.toString(16)}, orig=0x${origBytes[rva].toString(16)})`);
    }
    const tmpPath = exePath.replace('.exe', '-patched-' + Date.now() + '.exe');
    fs.writeFileSync(tmpPath, buf);
    return { tmpPath, origBytes };
  }

  openInput(inputFile) {
    if (!inputFile) return null;
    const GENERIC_READ = 0x80000000;
    const FILE_SHARE_READ = 1;
    const OPEN_EXISTING = 3;
    const CreateFileW = kernel32.func('CreateFileW', 'void*',
      [LPCWSTR, DWORD, DWORD, 'void*', DWORD, DWORD, 'void*']);
    const h = CreateFileW(toWide(inputFile), GENERIC_READ, FILE_SHARE_READ,
      null, OPEN_EXISTING, 0x80, null);
    if (!h || koffi.address(h) === 0xFFFFFFFFFFFFFFFFn) {
      console.error('[!] Failed to open input file:', inputFile);
      return null;
    }
    console.log(`[*] Input file: ${inputFile}`);
    return h;
  }

  _getSnapshot() {
    const result = { regs: null, ripRVA: -1, codeOff: -1, ctx: null };
    const ctx = this.allocateContext();
    ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
    const ok = GetThreadContext(this.mainThreadHandle, ctx.ptr);
    if (!ok) return result;
    result.ctx = ctx;
    result.regs = this.getRegs(ctx);
    result.ripRVA = this.rva(result.regs.Rip);
    const coBuf = this.readMem(Number(result.regs.R15) + 0x0e * 8, 8);
    if (coBuf) result.codeOff = Number(coBuf.readBigUInt64LE(0));
    return result;
  }

  _snapshotToStderr(snap, label) {
    if (!snap.regs) return;
    const { regs, ripRVA, codeOff } = snap;
    const log = (s) => console.error(s);
    console.error('');
    log(`${'='.repeat(8)} ${label} @ RVA 0x${ripRVA.toString(16)} ${'='.repeat(8)}`);
    log(`  RIP=0x${regs.Rip.toString(16)}  RSP=0x${regs.Rsp.toString(16)}`);
    log(`  RAX=0x${regs.Rax.toString(16)} RCX=0x${regs.Rcx.toString(16)} RDX=0x${regs.Rdx.toString(16)} R15=0x${regs.R15.toString(16)}`);
    if (codeOff >= 0) {
      const desc = codeOff > 0x8800 ? `(emitted ${codeOff - 0x8800} bytes)` : `(in PE copy mode)`;
      log(`  code_offset=0x${codeOff.toString(16)} ${desc}`);
    }
    if (this.codeData && ripRVA >= 0) {
      const textSec = this.pe.sections.find(s => s.name === '.text');
      if (textSec) {
        const fileOff = this.rvaToFileOff(ripRVA) - textSec.rOff;
        if (fileOff >= 0 && fileOff < this.codeData.length) {
          log('  --- Disassembly ---');
          const insns = this.disasm.disasmRange(this.codeData, fileOff, 5, this.imageBase);
          for (const insn of insns) {
            const hexBytes = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
            const rva = textSec.vRVA + insn.offset;
            const marker = (rva === ripRVA) ? '  <== RIP' : '';
            log(`    RVA 0x${rva.toString(16).padStart(4, '0')}  ${hexBytes.padEnd(20)}  ${insn.mnemonic}${marker}`);
          }
        }
      }
    }
    if (regs.R15) {
      const nonZero = [];
      for (let slot = 0; slot < 0x60; slot++) {
        const buf = this.readMem(Number(regs.R15) + slot * 8, 8);
        if (!buf) break;
        const val = buf.readBigUInt64LE(0);
        if (val !== 0n) {
          const name = STATE_NAMES[slot] || '';
          nonZero.push({ slot, val, name });
        }
      }
      if (nonZero.length > 0) {
        log('  --- State Slots (non-zero) ---');
        for (const { slot, val, name } of nonZero) {
          const comment = name ? `  // ${name}` : '';
          log(`    st[0x${slot.toString(16).padStart(2, '0')}] = 0x${val.toString(16).padStart(16, '0')}${comment}`);
        }
      }
    }
  }

  _terminate(reason, snap, wait) {
    if (snap && snap.regs) {
      this.saveDiag(wait, snap.regs, snap.ripRVA);
      this._snapshotToStderr(snap, reason);
    } else {
      console.error(`\n[!] ${reason}, terminating...`);
    }
    console.log(`\n[*] Done. Hits=${this.hitCount || 0}, Crashed=false, Steps=${this.stepCount || 0}`);
    this.shutdown(0);
  }

  debugLoop(piBuf, origBytes, maxWaitSec = 10) {
    this.hitCount = 0;
    this.stepCount = 0;
    let crashed = false;
    let eventBuf = Buffer.alloc(Number(DEBUG_EVENT.size));
    let silentSec = 0;
    const PROGRESS_INTERVAL = 2;     // show progress every 2s
    const STALL_THRESHOLD_RIP = 6;   // kill if RIP unchanged for 6s
    const STALL_THRESHOLD_CO = 8;    // kill if code_offset unchanged for 8s
    let stalledRipSec = 0;
    let stalledCoSec = 0;
    let totalWait = 0;
    let lastRip = -1;
    let lastCo = -1;

    while (true) {
      if (this._stopRequested) {
        console.log(`\n  [*] Stop requested after ${this.hitCount} hits.`);
        const finalSnap = this._getSnapshot();
        if (finalSnap.regs) {
          console.log('  ── Final state ──');
          this.dumpRegs(finalSnap.regs);
          this.dumpStates(finalSnap.regs.R15);
        }
        if (this.handlerCounts && this.handlerCounts.size > 0) {
          console.log('  ── Handler-entry counts ──');
          for (const [hh, n] of this.handlerCounts.entries()) {
            console.log(`    H_${hh.toString(16).padStart(2,'0')}: ${n} entries`);
          }
        }
        if (this.eventLog && this.eventLog.length > 0) {
          console.log('  ── First 50 instrumentation events ──');
          for (const ev of this.eventLog.slice(0, 50)) {
            if (ev.type === 'emit') console.log(ev.line);
            else if (ev.type === 'mismatch') {
              console.log(`    [MISMATCH] H_${ev.hh.toString(16)}: handler_map=0x${ev.expected.toString(16)} got 0x${ev.actual.toString(16)} Δ=${ev.delta}`);
            } else if (ev.type === 'rel32') {
              console.log(`    [rel32] @ RVA 0x${ev.rva.toString(16)} -> 0x${ev.target.toString(16)}`);
            }
          }
        }
        this.shutdown(0);
        break;
      }
      const got = WaitForDebugEvent(koffi.address(eventBuf), 1000);
      if (!got) {
        silentSec++;
        totalWait++;
        // Update progress every PROGRESS_INTERVAL seconds
        if (silentSec >= PROGRESS_INTERVAL && silentSec % PROGRESS_INTERVAL === 0) {
          const snap = this._getSnapshot();
          if (!snap.regs) continue;
          // Stall detection: check BEFORE showing progress
          if (snap.ripRVA === lastRip) stalledRipSec += PROGRESS_INTERVAL;
          else { stalledRipSec = 0; lastRip = snap.ripRVA; }
          if (snap.codeOff >= 0 && snap.codeOff === lastCo) stalledCoSec += PROGRESS_INTERVAL;
          else { stalledCoSec = 0; lastCo = snap.codeOff; }
          if (stalledRipSec >= STALL_THRESHOLD_RIP) {
            this._terminate(`RIP unchanged for ${stalledRipSec}s`, snap, totalWait);
            break;
          }
          if (stalledCoSec >= STALL_THRESHOLD_CO) {
            this._terminate(`code_offset unchanged for ${stalledCoSec}s`, snap, totalWait);
            break;
          }
          // Not stalled — show normal progress
          this._snapshotToStderr(snap, `Progress #${Math.floor(totalWait / PROGRESS_INTERVAL)} (t=${totalWait}s)`);
        }
        // Hard timeout
        if (totalWait >= maxWaitSec) {
          const snap = this._getSnapshot();
          this._terminate(`Max wait time (${maxWaitSec}s) exceeded`, snap, totalWait);
          break;
        }
        continue;
      }
      silentSec = 0;
      stalledRipSec = 0;
      stalledCoSec = 0;

      const code = eventBuf.readUInt32LE(0);
      const pid = eventBuf.readUInt32LE(4);
      const tid = eventBuf.readUInt32LE(8);

      if (code === EXCEPTION_DEBUG_EVENT) {
        const exCode = eventBuf.readUInt32LE(U_OFFSET);
        const exAddr = eventBuf.readBigUInt64LE(U_OFFSET + 16);

        if (exCode === EXCEPTION_BREAKPOINT) {
          const hitRva = Number(exAddr - this.imageBase);

          // System initial BP — in ntdll, skip
          if (hitRva < 0x1000) {
            console.log(`[*] System BP at 0x${exAddr.toString(16)}`);
            ContinueDebugEvent(pid, tid, DBG_CONTINUE);
            continue;
          }

          // Only handle INT3s we placed via checkpoints
          if (origBytes[hitRva] === undefined) {
            // Not our checkpoint — let system handle it
            ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
            continue;
          }

          this.hitCount++;
          const ctx = this.allocateContext();
          ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
          GetThreadContext(this.mainThreadHandle, ctx.ptr);
          const regs = this.getRegs(ctx);

          console.log(`\n═══ INT3 #${this.hitCount} at RVA 0x${hitRva.toString(16)} ═══`);
          this.dumpRegs(regs);

          // Show the call target if RIP is at a call instruction
          if (this.codeData) {
            const fileOff = this.rvaToFileOff(this.rva(regs.Rip));
            if (fileOff >= 0 && fileOff + 6 <= this.codeData.length) {
              try {
                const insn = this.disasm.disasmAt(this.codeData, fileOff, this.imageBase);
                if (insn && insn.funcName) {
                  console.log(`  → Calling: ${insn.funcName}`);
                }
              } catch (e) { /* ignore disasm errors */ }
            }
          }

          this.dumpDisasmAt(regs.Rip, 3);
          this.dumpStates(regs.R15);

          // ── Instrumentation hooks ──
          if (this.instOpts) {
            this._hitsSeen++;
            // --trace-emit: if hitRva corresponds to a handler in traceHandlers
            if (this.instOpts.traceHandlers && this.handlerTable) {
              const tableRVA = this.handlerTable.rva;
              const tableFileOff = this.pe.rvaToFile(tableRVA);
              if (tableFileOff !== null) {
                for (const hh of this.instOpts.traceHandlers) {
                  const expected = this.pe.data.readUInt32LE(tableFileOff + hh * 4);
                  // handler entry RVA = 0x1000 + handler_offset
                  if (expected > 0 && hitRva === expected + 0x1000) {
                    this.handlerCounts.set(hh, (this.handlerCounts.get(hh) || 0) + 1);
                    if (!this.handlerFirstSeen.has(hh)) this.handlerFirstSeen.set(hh, this.hitCount);
                    this.dumpEmitTrace(hh, regs);
                    break;
                  }
                }
              }
            }
            // --audit-rel32: if RIP is at a call/jmp/jcc, decode and log target
            if (this.instOpts.auditRel32) {
              this.auditRel32(regs);
            }
            // --watch-state: highlight specific state slots
            if (this.instOpts.watchSlots) {
              this.watchStateDump(regs, `hit#${this.hitCount}@rva0x${hitRva.toString(16)}`);
            }
            // --filter: log only if matches
            if (this.instOpts.filter) {
              const pass = this.instOpts.filter(regs, hitRva);
              if (!pass) console.log('  [filter] predicate not met — silenced');
            }
            // --count=N: stop after N hits
            if (this.instOpts.maxHits && this._hitsSeen >= this.instOpts.maxHits) {
              console.log(`\n  [*] Reached max-hits=${this.instOpts.maxHits}, terminating.`);
              this._stopRequested = true;
              const addr2 = Number(this.imageBase + BigInt(hitRva));
              const rbuf2 = Buffer.from([origBytes[hitRva]]);
              const bw2 = [0];
              WriteProcessMemory(this.processHandle, addr2, koffi.address(rbuf2), 1, bw2);
              ctx.buf.writeBigUInt64LE(BigInt(hitRva) + this.imageBase, CTX.Rip);
              SetThreadContext(this.mainThreadHandle, ctx.ptr);
              ContinueDebugEvent(pid, tid, DBG_CONTINUE);
              break;
            }
          }

          // Restore INT3
          const addr = Number(this.imageBase + BigInt(hitRva));
          const rbuf = Buffer.from([origBytes[hitRva]]);
          const bw = [0];
          WriteProcessMemory(this.processHandle, addr, koffi.address(rbuf), 1, bw);
          // RIP = exception address (resume at original instruction)
          ctx.buf.writeBigUInt64LE(BigInt(hitRva) + this.imageBase, CTX.Rip);
          SetThreadContext(this.mainThreadHandle, ctx.ptr);

          ContinueDebugEvent(pid, tid, DBG_CONTINUE);
          continue;
        }

        if (exCode === EXCEPTION_ACCESS_VIOLATION) {
          crashed = true;
          const ctx = this.allocateContext();
          ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
          GetThreadContext(this.mainThreadHandle, ctx.ptr);
          const regs = this.getRegs(ctx);

          console.log(`\n═══ 💥 ACCESS VIOLATION at 0x${exAddr.toString(16)} ═══`);
          this.dumpRegs(regs);
          this.dumpDisasmAt(regs.Rip, 8);
          this.dumpStates(regs.R15);
          this.analyzeCrash(regs, exAddr);

          // Optional crash-hex-dump and memcpy-analysis
          const ripRva = Number(this.rva(regs.Rip));
          if (this.instOpts) {
            if (this.instOpts.crashHexRva !== undefined) {
              const offRva = this.instOpts.crashHexRva;
              this.hexDumpRange(offRva, this.instOpts.crashHexBefore, this.instOpts.crashHexAfter);
            } else {
              // Default: show .text around RIP with bigger window than dumpDisasmAt (8 insns)
              this.hexDumpRange(ripRva, 64, 192);
            }
            if (this.instOpts.memcpyAnalysis) this.memcpyParamsAnalysis(regs);
            if (this.instOpts.diffNodeAtCrash) {
              console.log('  [diff-node] starting');
              try {
                this.diffAgainstNode(this.instOpts.diffNodeHH, ripRva);
                console.log('  [diff-node] diff dumped');
                if (this.instOpts.diffNodeHH === undefined && this.handlerTable) {
                  this.scanRel32Mismatches(ripRva);
                  console.log('  [diff-node] scanRel32 done');
                }
              } catch (e) { console.log('  [diff-node] THREW: ' + e.message + '\\n' + e.stack); }
            }
          }

          // EXCEPTION_RECORD layout:
          //   +0x00: ExceptionCode (4)
          //   +0x04: ExceptionFlags (4)
          //   +0x08: ExceptionRecord (8)
          //   +0x10: ExceptionAddress (8)
          //   +0x18: NumberParameters (4)
          //   +0x1C: __unusedAlignment (4)
          //   +0x20: ExceptionInformation[0] (8) = read(0)/write(1)
          //   +0x28: ExceptionInformation[1] (8) = fault address
          const readOp = eventBuf.readUInt32LE(U_OFFSET + 0x20);
          const faultAddr = eventBuf.readBigUInt64LE(U_OFFSET + 0x28);
          console.log(`  Access type: ${readOp === 0 ? 'READ' : 'WRITE'}`);
          console.log(`  Fault address: 0x${faultAddr.toString(16)}`);
          if (faultAddr !== 0n && Number(faultAddr) < 0x10000)
            console.log('  ⚠ Fault address is near NULL — null pointer likely!');
          else if (faultAddr)
            this.dumpFaultRegion(faultAddr);

          ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
          break;
        }

        if (exCode === EXCEPTION_SINGLE_STEP) {
          this.stepCount = (this.stepCount || 0) + 1;
          const ctx = this.allocateContext();
          ctx.buf.writeUInt32LE(0x0010000F, CTX.ContextFlags);
          GetThreadContext(this.mainThreadHandle, ctx.ptr);
          const regs = this.getRegs(ctx);
          const ripRVA = this.rva(regs.Rip);

          if (ripRVA >= 0x1000) {
            console.log(`\n═══ STEP #${this.stepCount} @ RVA 0x${ripRVA.toString(16)} ═══`);
            this.dumpDisasmAt(regs.Rip, 3);
          }

          // Re-set TF for next step
          ctx.buf.writeUInt32LE(0x00000100, CTX.ContextFlags); // just ContextFlags + others
          // Actually need to set EFlags.TF — easier to just set single step via DR/flag
          // For now, just continue without stepping
          SetThreadContext(this.mainThreadHandle, ctx.ptr);
          ContinueDebugEvent(pid, tid, DBG_CONTINUE);
          continue;
        }

        ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
        continue;

      } else if (code === CREATE_PROCESS_DEBUG_EVENT) {
        this.imageBase = eventBuf.readBigUInt64LE(U_OFFSET + 24);
        console.log(`[*] Image base: 0x${this.imageBase.toString(16)}`);
        ContinueDebugEvent(pid, tid, DBG_CONTINUE);
        continue;

      } else if (code === EXIT_PROCESS_DEBUG_EVENT) {
        const exitCode = eventBuf.readUInt32LE(U_OFFSET);
        console.log(`[*] Process exited with code ${exitCode}`);
        break;

      } else {
        ContinueDebugEvent(pid, tid, DBG_CONTINUE);
        continue;
      }
    }

    console.log(`\n[*] Done. Hits=${this.hitCount}, Crashed=${crashed}, Steps=${this.stepCount}`);
    this.shutdown(0);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Main
// ═══════════════════════════════════════════════════════════════════════════
function main() {
  const args = process.argv.slice(2);
  let mode = 'crash';
  if (args.includes('--trace-api')) mode = 'trace-api';
  else if (args.includes('--checkpoints')) mode = 'checkpoints';
  else if (args.includes('--step')) mode = 'step';
  else if (args.includes('--trace-emit')) mode = 'checkpoints';

  let maxWaitSec = 10;
  const waitArg = args.find(a => a.startsWith('--wait='));
  if (waitArg) {
    const n = parseInt(waitArg.split('=')[1], 10);
    if (!isNaN(n) && n > 0) maxWaitSec = n;
  }

  // --exe=<path>
  let exePath = path.join(__dirname, '..', 'build', 'yoyo.exe');
  const exeArg = args.find(a => a.startsWith('--exe='));
  if (exeArg) {
    const v = exeArg.slice('--exe='.length);
    if (v) exePath = path.isAbsolute(v) ? v : path.resolve(process.cwd(), v);
  }

  const inputFile = args.find(a => !a.startsWith('--') && (a.endsWith('.ky') || a.includes('\\') || a.includes('/')));

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`Usage: node debug.js [mode] [options] [input.ky]
Modes:
  (default)    Crash analysis - trap access violations, dump full analysis
  --trace-api  Place INT3 at every ff-15 (call IAT) site, show API calls
  --checkpoints <rva1,rva2,...>  Place INT3 checkpoints at given RVAs
  --step       Single-stepping mode (after first BP)
  --trace-emit <hH1,hH2,...>   Trace handler entries - when one of these handlers is hit,
                               print state_0e / state_45 / state_4d vs handler_map recorded.
                               Combines with --checkpoints for stop points.
Options:
  --exe=<path>    Target binary (default: build/yoyo.exe; e.g. --exe=build/gen2.exe)
  --wait=N        Max seconds to wait (default: 10)
  --watch-state slot=N[,M,...]  On every checkpoint hit, show these slots + delta vs last
  --audit-rel32   On every hit, if RIP is at E8/E9/0F 8x, decode and print rel32 target
  --filter='state[N]=V[,state[M]opW]'  Only log when predicate matches. Ops: = != < <= > >=
  --count=N       Stop after N checkpoint hits and dump summary
  --handler-range=hH[,hM,...]  Auto-inject RVA checkpoints at each named handler entry
                                  (needs handler_map; combines with --checkpoints)
  --crash-hex-rva=<rva>          On crash (or --count stop), hex-dump 256B around <rva>
        [--crash-hex-before=N]    (default: 64; auto = .text around RIP)
        [--crash-hex-after=N]     (default: 192)
  --memcpy-analysis              On crash, if RIP is at F3 A4 (rep movsb), dump RSI/RDI/RCX
                                  alongside state_03/state_0e/state_08/state_4d for
                                  diagnosis of memcpy pointers
  --dump-lea                    Boot-time scan: dump every LEA rax, [rip+disp32] in .text with
                                  computed target RVA + data-section/IAT classification. Useful to
                                  verify data_base-relative computations (state_08 in yoyo.ty).
  --diff-node [H_hh]             On crash, side-by-side diff current .text bytes with
                                  Node compileFromAnalyzed reference output. Auto-detects
                                  the handler from handler_map unless H_hh is given.
  --help, -h      This help
The debugger automatically:
  1. Parses PE to map sections and IAT
  2. Resolves API call targets
  3. Disassembles around RIP
  4. Walks the call stack
  5. Analyzes register state for common bugs
  6. Names state slots via yoyo.ty convention
  7. Reads handler_map from PE .data+0xFE00 (used by --trace-emit)
  8. Detects hangs every 2s; kills if RIP stalled >6s or code_offset >8s
  9. Saves diagnostic dump to debug-out/diag-*.txt before termination
Examples:
  node tools/debug.js --exe=build/gen2.exe \\
      --checkpoints 0x2ba3,0x34ac,0x3e11 \\
      --trace-emit e0,e6,43,1e --watch-state slot=e,45,4d --count=20`);
    return;
  }

  if (mode === 'analyze') {
    console.log('[!] Post-mortem analysis not yet implemented - use crash mode');
    return;
  }

  if (!fs.existsSync(exePath)) {
    console.error(`[!] target not found: ${exePath}`);
    process.exit(1);
  }

  const dbg = new Debugger(exePath);
  dbg.pe = new PEParser(exePath);

  const textSec = dbg.pe.sections.find(s => s.name === '.text');
  if (textSec) dbg.codeData = dbg.pe.data.slice(textSec.rOff, textSec.rOff + textSec.rSize);

  const hm = readHandlerMap(exePath);
  if (hm) {
    dbg.handlerTable = { rva: 0x18600, entries: hm.table, codeEnd: hm.codeEnd };
    console.log(`[*] Handler map: ${hm.table.size} valid entries, codeEnd=0x${hm.codeEnd.toString(16)}`);
    const interesting = [0,1,0xe0,0xe5,0xe6,0xe7,0x63,0x64,0x37,0x43,0x1e,0x30,0x31,0x33,0x44,0x38];
    for (const hh of interesting) {
      if (hm.table.has(hh)) console.log(`      H_${hh.toString(16).padStart(2,'0')} @ RVA 0x${(hm.table.get(hh) + 0x1000).toString(16)} (.text+0x${hm.table.get(hh).toString(16)})`);
    }
  } else {
    console.log('[*] No handler_map found (--trace-emit disabled)');
  }

  let checkpoints = [];

  let traceEmitHandlers = null;
  const traceEmitArg = args.find(a => a.startsWith('--trace-emit='));
  if (traceEmitArg) {
    traceEmitHandlers = new Set();
    const parts = traceEmitArg.slice('--trace-emit='.length).split(',');
    for (const p of parts) {
      const m = p.trim().match(/^(?:h)?([0-9a-fA-F]+)$/);
      if (m) traceEmitHandlers.add(parseInt(m[1], 16));
    }
  }

  let watchSlots = null;
  const wsArg = args.find(a => a.startsWith('--watch-state='));
  if (wsArg) {
    const val = wsArg.slice('--watch-state='.length);
    if (val) {
      watchSlots = val.split(',').map(s => {
        const t = s.trim();
        const m = t.match(/^(?:slot=)?0x?([0-9a-fA-F]+)$/);
        return m ? parseInt(m[1], 16) : NaN;
      }).filter(n => !isNaN(n));
      if (watchSlots.length === 0) watchSlots = null;
    }
  }

  let filterFn = null;
  const filterArg = args.find(a => a.startsWith('--filter='));
  if (filterArg) {
    const val = filterArg.slice('--filter='.length);
    const conds = val.split(',').map(s => s.trim()).filter(Boolean);
    const parsed = [];
    const re = /^state\[(\d+|0x[0-9a-fA-F]+)\](=|<=|>=|!=|>|<)(0x[0-9a-fA-F]+|\d+)$/i;
    for (const c of conds) {
      const m = c.match(re);
      if (m) {
        const slot = parseInt(m[1].startsWith('0x') || m[1].startsWith('0X') ? m[1].slice(2) : m[1], 10);
        const op = m[2];
        const v = parseInt(m[3].startsWith('0x') || m[3].startsWith('0X') ? m[3].slice(2) : m[3], m[3].startsWith('0x') ? 16 : 10);
        parsed.push({ slot, op, val: v });
      } else {
        console.error(`[!] Bad --filter clause: "${c}" (expected state[N]opV)`);
      }
    }
    if (parsed.length > 0) {
      filterFn = (regs) => {
        if (!regs.R15 || regs.R15 === 0n) return false;
        for (const p of parsed) {
          const v = dbg.readState(regs.R15, p.slot);
          if (v === null) return false;
          const num = Number(BigInt.asUintN(32, v & 0xFFFFFFFFn));
          let ok;
          switch (p.op) {
            case '=':  ok = (num === p.val) || (Number(v) === p.val); break;
            case '!=': ok = !(num === p.val); break;
            case '<':  ok = num <  p.val; break;
            case '<=': ok = num <= p.val; break;
            case '>':  ok = num >  p.val; break;
            case '>=': ok = num >= p.val; break;
            default:   ok = false;
          }
          if (!ok) return false;
        }
        return true;
      };
      console.log('[*] Filter clauses:');
      for (const p of parsed) console.log(`      state[0x${p.slot.toString(16)}] ${p.op} ${p.val}`);
    }
  }

  let maxHits = null;
  const countArg = args.find(a => a.startsWith('--count='));
  if (countArg) {
    const n = parseInt(countArg.slice('--count='.length), 10);
    if (!isNaN(n) && n > 0) maxHits = n;
  }

  const auditRel32 = args.includes('--audit-rel32');
  const dumpLea = args.includes('--dump-lea');

  // --crash-hex-rva=<rva> [--crash-hex-before=N] [--crash-hex-after=N]
  let crashHexRva, crashHexBefore = 64, crashHexAfter = 192;
  const chrArg = args.find(a => a.startsWith('--crash-hex-rva='));
  if (chrArg) {
    const v = chrArg.slice('--crash-hex-rva='.length);
    crashHexRva = parseInt(v.startsWith('0x') ? v.slice(2) : v, 16);
  }
  const chbArg = args.find(a => a.startsWith('--crash-hex-before='));
  if (chbArg) crashHexBefore = parseInt(chbArg.slice('--crash-hex-before='.length), 10);
  const chaArg = args.find(a => a.startsWith('--crash-hex-after='));
  if (chaArg) crashHexAfter = parseInt(chaArg.slice('--crash-hex-after='.length), 10);

  const memcpyAnalysis = args.includes('--memcpy-analysis');

  // --handler-range=hH1[,hH2] : automatically inject RVA checkpoints for handler
  //   hh's start AND each (pe byte + handler offset reach) up to codeEnd
  let extraCheckpoints = [];
  const hrArg = args.find(a => a.startsWith('--handler-range='));
  if (hrArg) {
    const val = hrArg.slice('--handler-range='.length);
    if (dbg.handlerTable) {
      const wanted = new Set(val.split(',').map(s => parseInt(s.trim().startsWith('0x') ? s.trim().slice(2) : s.trim(), 16)));
      for (const [hh, hOff] of dbg.handlerTable.entries) {
        if (wanted.has(hh)) extraCheckpoints.push(hOff + 0x1000);  // RVA
      }
      console.log(`[*] handler-range added ${extraCheckpoints.length} checkpoints: ${extraCheckpoints.map(r => '0x' + r.toString(16)).join(', ')}`);
    }
  }

  

  // --diff-node [H_hh]  -- on crash, dump Node-compiled reference + side-by-side diff
  let diffNodeAtCrash = false;
  let diffNodeHH = undefined;
  const dnArg = args.find(a => a === '--diff-node' || a.startsWith('--diff-node='));
  if (dnArg) {
    diffNodeAtCrash = true;
    if (dnArg.startsWith('--diff-node=')) {
      const v = dnArg.slice('--diff-node='.length);
      const m = v.match(/^(?:h)?([0-9a-fA-F]+)$/);
      if (m) diffNodeHH = parseInt(m[1], 16);
    }
  }
dbg.initInstrumentation({
    traceHandlers: traceEmitHandlers,
    watchSlots,
    filter: filterFn,
    auditRel32,
    maxHits,
    dumpLea,
    crashHexRva,
    crashHexBefore,
    crashHexAfter,
    memcpyAnalysis,
    diffNodeAtCrash,
    diffNodeHH,
  });

  if (mode === 'trace-api') {
    dbg.disasm = new MiniDisassembler(dbg.pe);
    const sites = dbg.findCallSites();
    console.log(`[*] Found ${sites.length} API call sites (place INT3 at each):`);
    for (const s of sites) console.log(`      RVA 0x${s.rva.toString(16)} -> ${s.name}`);
    checkpoints = sites.map(s => s.rva);
    checkpoints.sort((a, b) => a - b);
    if (!checkpoints.includes(0x48fa)) checkpoints.push(0x48fa);
  } else if (mode === 'checkpoints') {
    const hexArgs = args.filter(a => /^0x[0-9a-f]+$/i.test(a));
    if (hexArgs.length > 0) {
      checkpoints = hexArgs.map(a => parseInt(a, 16));
    } else {
      checkpoints = [0x1000, 0x1044, 0x1080, 0x1100, 0x1200, 0x1300, 0x1400];
    }
  }
  // Merge --handler-range checkpoints
  if (extraCheckpoints.length > 0) {
    const seen = new Set(checkpoints);
    for (const r of extraCheckpoints) if (!seen.has(r)) { checkpoints.push(r); seen.add(r); }
    checkpoints.sort((a, b) => a - b);
  }

  if (checkpoints.length > 0) {
    console.log(`[*] INT3 checkpoints: ${checkpoints.map(r => '0x' + r.toString(16)).join(', ')}`);
  } else {
    console.log('[*] Crash analysis mode - will trap any access violation');
  }
  if (traceEmitHandlers && traceEmitHandlers.size > 0) {
    console.log(`[*] Trace handler entries: H_${Array.from(traceEmitHandlers).map(h => h.toString(16).padStart(2,'0')).join(', H_')}`);
  }
  if (watchSlots) {
    console.log(`[*] Watch state slots: ${watchSlots.map(s => '0x' + s.toString(16).padStart(2,'0')).join(', ')}`);
  }
  if (maxHits) console.log(`[*] Stop after ${maxHits} hits`);

  if (dumpLea) dbg.dumpLeaTargets();
  dbg.run(mode, checkpoints, inputFile, maxWaitSec);
}
main();
