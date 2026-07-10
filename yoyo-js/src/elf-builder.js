'use strict';

const SA = 0x1000;
const FA = 0x400;
const align = v => ((v + FA - 1) / FA | 0) * FA;
const alignS = v => ((v + SA - 1) / SA | 0) * SA;

const BASE = 0x400000;

class ELF {
  constructor() {
    this.code = null;
    this.data = null;
    this.entry = BASE + SA;
    this.codeRVA = BASE + SA;
    this.dataRVA = 0;
  }

  setCode(buf) { this.code = buf; }
  setData(buf) { this.data = buf; }

  build() {
    const code = this.code || Buffer.alloc(0);
    const data = this.data || Buffer.alloc(0);
    const textRS = align(code.length);
    const textVS = alignS(code.length);
    const dataRVA = this.codeRVA + textVS;
    const dataRS = align(data.length);
    const dataVS = alignS(data.length);
    const codeFileOff = SA;
    const dataFileOff = codeFileOff + textRS;
    const hasData = data.length > 0;
    const phCount = hasData ? 3 : 2;
    const hdrSize = 64 + 56 * phCount;
    const fileSize = (hasData ? dataFileOff + dataRS : codeFileOff + textRS);

    const out = Buffer.alloc(Math.max(fileSize, codeFileOff + textRS), 0);

    out[0] = 0x7f; out[1] = 0x45; out[2] = 0x4c; out[3] = 0x46;
    out[4] = 2; out[5] = 1; out[6] = 1;
    out.writeUInt16LE(2, 16);
    out.writeUInt16LE(0x3e, 18);
    out.writeUInt32LE(1, 20);
    out.writeBigUInt64LE(BigInt(this.entry), 24);
    out.writeBigUInt64LE(64n, 32);
    out.writeUInt16LE(64, 52);
    out.writeUInt16LE(56, 54);
    out.writeUInt16LE(phCount, 56);

    const ph1 = 64;
    out.writeUInt32LE(1, ph1);
    out.writeUInt32LE(4, ph1 + 4);
    out.writeBigUInt64LE(0n, ph1 + 8);
    out.writeBigUInt64LE(BigInt(BASE), ph1 + 16);
    out.writeBigUInt64LE(BigInt(BASE), ph1 + 24);
    out.writeBigUInt64LE(BigInt(codeFileOff), ph1 + 32);
    out.writeBigUInt64LE(BigInt(codeFileOff), ph1 + 40);
    out.writeBigUInt64LE(BigInt(SA), ph1 + 48);

    const ph2 = 64 + 56;
    out.writeUInt32LE(1, ph2);
    out.writeUInt32LE(5, ph2 + 4);
    out.writeBigUInt64LE(BigInt(codeFileOff), ph2 + 8);
    out.writeBigUInt64LE(BigInt(this.codeRVA), ph2 + 16);
    out.writeBigUInt64LE(BigInt(this.codeRVA), ph2 + 24);
    out.writeBigUInt64LE(BigInt(textRS), ph2 + 32);
    out.writeBigUInt64LE(BigInt(textVS), ph2 + 40);
    out.writeBigUInt64LE(BigInt(SA), ph2 + 48);

    if (hasData) {
      const ph3 = 64 + 56 * 2;
      out.writeUInt32LE(1, ph3);
      out.writeUInt32LE(6, ph3 + 4);
      out.writeBigUInt64LE(BigInt(dataFileOff), ph3 + 8);
      out.writeBigUInt64LE(BigInt(dataRVA), ph3 + 16);
      out.writeBigUInt64LE(BigInt(dataRVA), ph3 + 24);
      out.writeBigUInt64LE(BigInt(dataRS), ph3 + 32);
      out.writeBigUInt64LE(BigInt(dataVS), ph3 + 40);
      out.writeBigUInt64LE(BigInt(SA), ph3 + 48);
    }

    code.copy(out, codeFileOff);
    if (hasData) data.copy(out, dataFileOff);

    this.dataRVA = dataRVA;
    return out.slice(0, fileSize);
  }
}

module.exports = { ELF, alignS, BASE };
