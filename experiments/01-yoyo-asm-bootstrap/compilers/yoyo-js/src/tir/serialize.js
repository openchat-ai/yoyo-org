'use strict';

/**
 * TIR module serialization — Phase 6 (.ytir export).
 * Text format: one op per line, human-readable and round-trippable.
 */
const { Op } = require('./ops.js');

function esc(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function serializeOp(op) {
  switch (op.kind) {
    case Op.LABEL: return `label ${op.hh.toString(16)}`;
    case Op.CALL: return `call ${op.hh.toString(16)}`;
    case Op.JMP: return `jmp ${op.hh.toString(16)}`;
    case Op.JCC: return `jcc.${op.cond} ${op.hh.toString(16)}`;
    case Op.RET: return 'ret';
    case Op.STATE_SET: return `state.set ${op.slot.toString(16)} ${op.value}`;
    case Op.STATE_COPY: return `state.copy ${op.dst.toString(16)} ${op.src.toString(16)}`;
    case Op.STATE_INC: return `state.inc ${op.slot.toString(16)}`;
    case Op.STATE_ADD_IMM: return `state.add_imm ${op.slot.toString(16)} ${op.imm}`;
    case Op.STATE_SUB_IMM: return `state.sub_imm ${op.slot.toString(16)} ${op.imm}`;
    case Op.STATE_ADD: return `state.add ${op.dst.toString(16)} ${op.src.toString(16)}`;
    case Op.STATE_SUB: return `state.sub ${op.dst.toString(16)} ${op.src.toString(16)}`;
    case Op.STATE_CMP: return `state.cmp ${op.a.toString(16)} ${op.b.toString(16)}`;
    case Op.STATE_LOAD_BYTE: return `state.load_byte ${op.dst.toString(16)} ${op.base.toString(16)} ${op.offset || 0}`;
    case Op.EMIT_U8: return `emit.u8 ${op.value.toString(16)}`;
    case Op.EMIT_STORE_U32: return `emit.store_u32 ${op.addrSlot.toString(16)} ${op.valSlot.toString(16)}`;
    case Op.EMIT_STORE_BYTE: return `emit.store_byte ${op.base.toString(16)} ${op.index.toString(16)} ${op.val.toString(16)}`;
    case Op.ALLOC: return `alloc ${op.slot.toString(16)} ${op.size}`;
    case Op.LOAD_FILE: return `load_file ${op.stateSlot.toString(16)} ${op.stringId}`;
    case Op.WRITE_FILE: return `write_file ${op.fdSlot.toString(16)} ${op.bufSlot.toString(16)} ${op.lenSlot.toString(16)}`;
    case Op.MEMCPY_DATA: return `memcpy_data ${op.dst.toString(16)} ${op.blobOff.toString(16)} ${op.len}`;
    case Op.MEMCPY_STATE: return `memcpy_state ${op.dst.toString(16)} ${op.src.toString(16)} ${op.lenSlot.toString(16)}`;
    case Op.RAW_A0: return `raw.a0 ${op.hex}`;
    case Op.STRING_DEF: return `string.def ${op.id} "${esc(op.text)}"`;
    case Op.DATA_BLOB: return `data.blob ${op.offset.toString(16)} ${op.hex}`;
    case Op.NOP: return `nop ${op.rawOp?.toString(16) || '0'} ${op.arity || 0}`;
    default: return `; unknown ${op.kind}`;
  }
}

function serializeModule(mod) {
  const lines = [];
  lines.push('; .ytir — yoyo TIR module');
  lines.push(`; name: ${mod.name || 'module'}`);
  lines.push(`; handlers: ${mod.meta?.handlerCount ?? mod.functions.length}`);
  lines.push(`; fixups: ${mod.fixups?.length ?? 0}`);
  lines.push(`; order: ${mod.meta?.handlerOrder || 'file'}`);
  lines.push('');

  if (mod.strings) {
    for (const [id, s] of Object.entries(mod.strings)) {
      lines.push(`string.def ${id} "${esc(s.text)}"`);
    }
    lines.push('');
  }

  if (mod.blobs) {
    for (const b of mod.blobs) {
      lines.push(`data.blob ${b.off.toString(16)} ${b.data.toString('hex')}`);
    }
    lines.push('');
  }

  for (const fn of mod.functions) {
    lines.push(`fn ${fn.name}`);
    for (const block of fn.blocks) {
      for (const op of block.ops) {
        if (op.kind === Op.STRING_DEF || op.kind === Op.DATA_BLOB) continue;
        lines.push('  ' + serializeOp(op));
      }
    }
    lines.push('end');
    lines.push('');
  }

  if (mod.fixups?.length) {
    lines.push('; fixups');
    for (const f of mod.fixups) {
      lines.push(`; fixup hh=${f.hh.toString(16)} raw=${f.rawOp?.toString(16) || '?'}`);
    }
  }

  return lines.join('\n') + '\n';
}

function parseYtirLine(line) {
  const t = line.trim();
  if (!t || t.startsWith(';')) return null;
  const parts = t.split(/\s+/);
  const cmd = parts[0];

  const hex = s => parseInt(s, 16);
  const dec = s => parseInt(s, 10);

  switch (cmd) {
    case 'fn': return { type: 'fn_start', name: parts[1] };
    case 'end': return { type: 'fn_end' };
    case 'label': return { kind: Op.LABEL, hh: hex(parts[1]) };
    case 'call': return { kind: Op.CALL, hh: hex(parts[1]) };
    case 'jmp': return { kind: Op.JMP, hh: hex(parts[1]) };
    case 'ret': return { kind: Op.RET };
    case 'state.set': return { kind: Op.STATE_SET, slot: hex(parts[1]), value: dec(parts[2]) };
    case 'emit.u8': return { kind: Op.EMIT_U8, value: hex(parts[1]) };
    case 'alloc': return { kind: Op.ALLOC, slot: hex(parts[1]), size: dec(parts[2]) };
    case 'load_file': return { kind: Op.LOAD_FILE, stateSlot: hex(parts[1]), stringId: dec(parts[2]) };
    case 'write_file': return { kind: Op.WRITE_FILE, fdSlot: hex(parts[1]), bufSlot: hex(parts[2]), lenSlot: hex(parts[3]) };
    case 'raw.a0': return { kind: Op.RAW_A0, hex: parts[1] };
    default:
      if (cmd.startsWith('jcc.')) return { kind: Op.JCC, cond: cmd.slice(4), hh: hex(parts[1]) };
      if (cmd === 'string.def') {
        const m = t.match(/^string\.def\s+(\d+)\s+"(.*)"/);
        if (m) return { kind: Op.STRING_DEF, id: parseInt(m[1], 10), text: m[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\') };
      }
      return { kind: Op.NOP, raw: t };
  }
}

function deserializeModule(text) {
  const { createModule, createFunction } = require('./module.js');
  const mod = createModule('ytir');
  mod.handlerOrder = [];
  let fn = null;

  for (const line of text.split('\n')) {
    const item = parseYtirLine(line);
    if (!item) continue;
    if (item.type === 'fn_start') {
      fn = createFunction(item.name);
      mod.functions.push(fn);
      if (item.name.startsWith('H') && item.name !== '__top') {
        mod.handlerOrder.push(parseInt(item.name.slice(1), 16));
      }
    } else if (item.type === 'fn_end') {
      fn = null;
    } else if (fn && item.kind) {
      fn.blocks[0].ops.push(item);
    }
  }
  return mod;
}

module.exports = { serializeModule, deserializeModule, serializeOp, parseYtirLine };
