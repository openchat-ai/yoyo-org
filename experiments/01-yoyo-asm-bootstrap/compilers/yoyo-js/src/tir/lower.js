'use strict';

const { parse, analyze } = require('../yoyo.js');
const { Op, JCC, isForwardFixupOp } = require('./ops.js');
const { createModule, createFunction } = require('./module.js');

/**
 * File-order handler list — matches blob-handlers / runtime layout, not analyze().
 */
function handlerFileOrder(text) {
  const order = [];
  const seen = new Set();
  for (const line of text.split('\n')) {
    const trimmed = line.replace(/;.*$/, '').trim();
    // Hex form: `40 HH` — traditional yoyo bytecode.
    let m = trimmed.match(/^40\s+([0-9a-fA-F]+)$/);
    // TIR intrinsics form: `label H_HH` — readable alias, requires H_ prefix
    // to disambiguate from raw state slot numbers.
    if (!m) m = trimmed.match(/^label\s+H_([0-9a-fA-F]+)$/);
    if (!m) continue;
    const hh = parseInt(m[1], 16);
    if (!seen.has(hh)) {
      seen.add(hh);
      order.push(hh);
    }
  }
  return order;
}

function splitHandlers(text) {
  const tokens = parse(text);
  const top = [];
  const handlers = new Map();
  let current = null;

  for (const t of tokens) {
    if (t.op === 0x40) {
      if (current === null) {
        current = t.args[0].v;
        if (!handlers.has(current)) handlers.set(current, []);
      } else {
        handlers.get(current).push(t);
      }
      continue;
    }
    if (current === null) top.push(t);
    else handlers.get(current).push(t);
  }
  return { top, handlers };
}

function argN(args, i) {
  return args[i] ? args[i].v : 0;
}

function lowerOpcode(op, args) {
  const o = op.op;
  const a = op.args;

  switch (o) {
    case 0x40:
      return [{ kind: Op.LABEL, hh: argN(a, 0) }];
    case 0x41:
      return [{ kind: Op.CALL, hh: argN(a, 0) }];
    case 0x70:
      return [{ kind: Op.JMP, hh: argN(a, 0) }];
    case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76: case 0x77: case 0x78: case 0x7a: case 0x82: case 0x83:
      return [{ kind: Op.JCC, cond: JCC[o] || 'eq', hh: argN(a, 0) }];
    case 0xFF:
      return [{ kind: Op.RET }];
    case 0x30:
      return [{ kind: Op.STATE_SET, slot: argN(a, 0), value: argN(a, 1) }];
    case 0x60:
      return [{ kind: Op.STATE_COPY, dst: argN(a, 0), src: argN(a, 1) }];
    case 0x61:
      return [{ kind: Op.STATE_ADD_IMM, slot: argN(a, 0), imm: argN(a, 1) }];
    case 0x62:
      return [{ kind: Op.STATE_SUB_IMM, slot: argN(a, 0), imm: argN(a, 1) }];
    case 0x66:
      return [{ kind: Op.STATE_INC, slot: argN(a, 0) }];
    case 0x68:
      return [{ kind: Op.STATE_ADD, dst: argN(a, 0), src: argN(a, 1) }];
    case 0x69:
      return [{ kind: Op.STATE_SUB, dst: argN(a, 0), src: argN(a, 1) }];
    case 0x65:
      return [{ kind: Op.STATE_CMP, a: argN(a, 0), b: argN(a, 1) }];
    case 0x80:
      return [{ kind: Op.STATE_LOAD_BYTE, dst: argN(a, 0), base: argN(a, 1), offset: argN(a, 2) }];
    case 0x87:
      return [{ kind: Op.EMIT_STORE_BYTE_IMM, addrSlot: argN(a, 0), valSlot: argN(a, 1), offset: argN(a, 2) || 0 }];
    case 0x20:
      return [{ kind: Op.ALLOC, slot: argN(a, 0), size: argN(a, 1) }];
    case 0x50:
      return [{ kind: Op.LOAD_FILE, stateSlot: argN(a, 0), stringId: argN(a, 1) }];
    case 0x51:
      return [{ kind: Op.WRITE_FILE, fdSlot: argN(a, 0), bufSlot: argN(a, 1), lenSlot: argN(a, 2) }];
    case 0x84:
      return [{ kind: Op.MEMCPY_DATA, dst: argN(a, 0), blobOff: argN(a, 1), len: argN(a, 2) }];
    case 0x85:
      return [{ kind: Op.MEMCPY_STATE, dst: argN(a, 0), src: argN(a, 1), lenSlot: argN(a, 2) }];
    case 0x55:
      return [{ kind: Op.EMIT_STORE_U32, addrSlot: argN(a, 0), valSlot: argN(a, 1) }];
    case 0x57:
      return [{ kind: Op.EMIT_STORE_BYTE, base: argN(a, 0), index: argN(a, 1), val: argN(a, 2) }];
    case 0xA0:
      return [{ kind: Op.RAW_A0, hex: a[0] && a[0].t === 'h' ? a[0].v : '' }];
    case 0xA1:
      return [{ kind: Op.EMIT_U8, value: argN(a, 0) & 0xff }];
    case 0xAB:
      return [{ kind: Op.RAW_BYTES, bytes: op.rawBytes || [] }];
    case 0x12:
      return [{ kind: Op.STRING_DEF, id: argN(a, 0), text: a[1] ? a[1].v : (a[0] && a[0].t === 's' ? a[0].v : '') }];
    case 0x13:
      return [{ kind: Op.DATA_BLOB, offset: argN(a, 0), hex: a[1] && a[1].raw ? a[1].raw.toString('hex') : '' }];
    default:
      return [{ kind: Op.NOP, rawOp: o, arity: (a && a.length) || 0 }];
  }
}

function lowerHandlerBody(ops, mod) {
  const tirOps = [];
  for (const op of ops) {
    if (isForwardFixupOp(op.op) && op.args[0]) {
      mod.fixups.push({ hh: op.args[0].v, site: { handler: null, index: tirOps.length }, rawOp: op.op });
    }
    tirOps.push(...lowerOpcode(op));
  }
  return tirOps;
}

function lowerProgramFromSource(text, opts = {}) {
  const mod = createModule('yoyo');
  const useAnalyze = opts.handlerOrder === 'analyze';

  if (useAnalyze) {
    const prog = analyze(parse(text));
    mod.strings = prog.strings;
    mod.blobs = prog.blobs;

    const topFn = createFunction('__top');
    topFn.blocks[0].ops = lowerHandlerBody(prog.top, mod);
    mod.functions.push(topFn);

    mod.handlerOrder = [];
    const order = Object.keys(prog.handlers).map(k => +k).sort((a, b) => a - b);
    for (const hh of order) {
      const body = prog.handlers[hh] || [];
      const fn = createFunction('H' + hh.toString(16));
      fn.blocks[0].ops = [{ kind: Op.LABEL, hh }, ...lowerHandlerBody(body, mod)];
      mod.handlerOrder.push(hh);
      mod.functions.push(fn);
    }
    mod.meta = {
      handlerCount: order.length,
      fixupCount: mod.fixups.length,
      topOpCount: topFn.blocks[0].ops.length,
      handlerOrder: 'analyze',
    };
    return mod;
  }

  const order = handlerFileOrder(text);
  const { top, handlers } = splitHandlers(text);

  const topFn = createFunction('__top');
  topFn.blocks[0].ops = lowerHandlerBody(top, mod);
  mod.functions.push(topFn);

  for (const op of top) {
    if (op.op === 0x12) {
      const id = op.args[0] ? op.args[0].v : mod.stringCount || 0;
      const textVal = op.args[1] ? op.args[1].v : (op.args[0] && op.args[0].t === 's' ? op.args[0].v : '');
      mod.strings = mod.strings || {};
      mod.strings[id] = { text: textVal };
    } else if (op.op === 0x13) {
      mod.blobs = mod.blobs || [];
      mod.blobs.push({
        off: op.args[0].v,
        data: op.args[1].raw || Buffer.from(op.args[1].v, 'hex'),
      });
    }
  }

  for (const hh of order) {
    const body = handlers.get(hh) || [];
    const fn = createFunction('H' + hh.toString(16));
    fn.blocks[0].ops = [{ kind: Op.LABEL, hh }, ...lowerHandlerBody(body, mod)];
    mod.handlerOrder = mod.handlerOrder || [];
    mod.handlerOrder.push(hh);
    mod.functions.push(fn);
  }

  for (const [, body] of handlers) {
    for (const op of body) {
      if (op.op === 0x12) {
        const id = op.args[0] ? op.args[0].v : 0;
        const textVal = op.args[1] ? op.args[1].v : (op.args[0] && op.args[0].t === 's' ? op.args[0].v : '');
        mod.strings = mod.strings || {};
        mod.strings[id] = { text: textVal };
      } else if (op.op === 0x13) {
        mod.blobs = mod.blobs || [];
        mod.blobs.push({
          off: op.args[0].v,
          data: op.args[1].raw || Buffer.from(op.args[1].v, 'hex'),
        });
      }
    }
  }

  mod.meta = {
    handlerCount: order.length,
    fixupCount: mod.fixups.length,
    topOpCount: topFn.blocks[0].ops.length,
    handlerOrder: 'file',
  };
  return mod;
}

/** @deprecated use lowerProgramFromSource */
function lowerProgram(prog) {
  const mod = createModule('yoyo');
  const handlers = prog.handlers || {};
  for (const key of Object.keys(handlers).map(Number).sort((a, b) => a - b)) {
    mod.functions.push(createFunction('H' + key));
  }
  return mod;
}

module.exports = { lowerProgram, lowerProgramFromSource, handlerFileOrder, splitHandlers, lowerOpcode };
