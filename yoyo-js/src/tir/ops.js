'use strict';

/** @enum {string} */
const Op = {
  LABEL: 'label',
  CALL: 'call',
  TAIL_CALL: 'tail_call',
  JMP: 'jmp',
  JCC: 'jcc',
  RET: 'ret',
  STATE_SET: 'state.set',
  STATE_GET: 'state.get',
  STATE_COPY: 'state.copy',
  STATE_INC: 'state.inc',
  STATE_ADD_IMM: 'state.add_imm',
  STATE_SUB_IMM: 'state.sub_imm',
  STATE_ADD: 'state.add',
  STATE_SUB: 'state.sub',
  STATE_CMP: 'state.cmp',
  STATE_LOAD_BYTE: 'state.load_byte',
  EMIT_U8: 'emit.u8',
  EMIT_U8_SLOT: 'emit.u8_slot',
  EMIT_STORE_U32: 'emit.store_u32',
  EMIT_STORE_BYTE: 'emit.store_byte',
  EMIT_STORE_BYTE_IMM: 'emit.store_byte_imm',
  ALLOC: 'alloc',
  LOAD_FILE: 'intrinsic.load_file',
  WRITE_FILE: 'intrinsic.write_file',
  // libyoyo_* calls (Phase 4c) - 0x52-0x5A
  LIBYOYO_ALLOC: 'libyoyo.alloc',
  LIBYOYO_FREE: 'libyoyo.free',
  LIBYOYO_OPEN: 'libyoyo.open',
  LIBYOYO_READ: 'libyoyo.read',
  LIBYOYO_WRITE: 'libyoyo.write',
  LIBYOYO_CLOSE: 'libyoyo.close',
  LIBYOYO_EXIT: 'libyoyo.exit',
  LIBYOYO_PRINT: 'libyoyo.print',
  LIBYOYO_TIME: 'libyoyo.time',
  MEMCPY_DATA: 'intrinsic.memcpy_data',
  MEMCPY_STATE: 'intrinsic.memcpy_state',
  RAW_A0: 'raw.a0',
  RAW_BYTES: 'raw.bytes',
  BLOB_LINE: 'blob.line',
  STRING_DEF: 'string.def',
  DATA_BLOB: 'data.blob',
  NOP: 'nop',
};

const JCC = {
  0x71: 'eq',
  0x72: 'ne',
  0x73: 'lt',
  0x74: 'le',
  0x75: 'be',
  0x76: 'gt',
  0x77: 'jb',
  0x78: 'ae',
  0x7a: 'a',
  0x82: 'l',
  0x83: 'g',
};

const FORWARD_FIXUP_OPS = new Set([0x41, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x7a, 0x82, 0x83]);

function isForwardFixupOp(op) {
  return FORWARD_FIXUP_OPS.has(op);
}

module.exports = { Op, JCC, FORWARD_FIXUP_OPS, isForwardFixupOp };
