'use strict';

/**
 * Build deterministic Windows output-.text handler image from win-emit-core (Node path).
 * Uses compileFromAnalyzed bytes (correct IAT fixups) relocated into the output layout.
 */
const { parse, analyze } = require('./yoyo.js');
const { compileFromAnalyzed, extractWinHandlerSlices, buildStringLayout } = require('./backends/win-emit-core.js');
const { handlerFileOrder, relocateSlice } = require('./blob-handlers.js');
const { PE_TEXT_FILE_OFF } = require('./platform-config.js');

const H00_HEAD = Buffer.from('48b9000000000000000048ba0000060000', 'hex');

function buildRuntimeData(prog) {
  const { strs, strPos, sOff } = buildStringLayout(prog.strings || {});
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
  return { data, dataLen: dataSize };
}

function buildWinHandlerOverlay(src, textBaseOff) {
  const sanitized = src
    .replace(/__HIMG_LEN__/g, '0')
    .replace(/61 0e 00 ; \+ __HIMG_LEN__ \(patched at yoyo-gen time\)/g, '61 0e 00');
  const order = handlerFileOrder(sanitized);
  const prog = analyze(parse(sanitized));

  const pe = compileFromAnalyzed(prog, { handlerOrder: 'file', handlerOrderList: order });
  const text = pe.slice(PE_TEXT_FILE_OFF, PE_TEXT_FILE_OFF + 0x8000);
  const h0 = text.indexOf(H00_HEAD);
  if (h0 < 0) throw new Error('H_00 VirtualAlloc prologue not found in compileFromAnalyzed output');

  const layout = extractWinHandlerSlices(prog, { handlerOrder: 'file', handlerOrderList: order });
  const blockEnd = layout.codeEnd > h0 ? layout.codeEnd : text.length;
  const block = Buffer.from(text.slice(h0, blockEnd));
  const image = relocateSlice(block, h0, textBaseOff);

  const table = Buffer.alloc(256 * 4, 0);
  for (const hh of order) {
    const off = layout.refOffset.get(hh);
    if (off === undefined || off < h0) continue;
    table.writeUInt32LE(textBaseOff + (off - h0), hh * 4);
  }

  const codeEnd = textBaseOff + block.length;
  const mapBuf = Buffer.alloc(0x404, 0);
  table.copy(mapBuf, 0);
  mapBuf.writeUInt32LE(codeEnd, 0x400);

  const runtime = buildRuntimeData(prog);

  return {
    image,
    mapBuf,
    codeEnd,
    handler0: table.readUInt32LE(0),
    imageLen: block.length,
    runtimeData: runtime.data,
    runtimeDataLen: runtime.dataLen,
  };
}

module.exports = { buildWinHandlerOverlay };
