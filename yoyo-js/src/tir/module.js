'use strict';

/** @typedef {{ kind: string, [key: string]: unknown }} TirOp */
/** @typedef {{ label: string, ops: TirOp[] }} TirBlock */
/** @typedef {{ name: string, params: string[], blocks: TirBlock[] }} TirFunction */
/** @typedef {{ name: string, functions: TirFunction[], fixups: { hh: number, patchPos: number }[] }} TirModule */

function createModule(name = 'module') {
  return { name, functions: [], fixups: [] };
}

function createFunction(name, params = []) {
  return { name, params, blocks: [{ label: 'entry', ops: [] }] };
}

module.exports = { createModule, createFunction };
