'use strict';

const { KNOWN_OPS, OP_MIN_ARGS, OP_RAW_BYTES } = require('./opcode-emit-x64.js');

class CompileError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CompileError';
  }
}

function parseHexArg(raw, line, index) {
  if (raw == null || raw === '') throw new CompileError(`line ${line}: missing hex arg ${index + 1}`);
  if (typeof raw === 'object' && raw.t === 's') return raw;
  if (typeof raw === 'object' && raw.t === 'h') return raw;
  const s = String(raw);
  if (!/^[0-9a-fA-F]+$/.test(s)) {
    throw new CompileError(`line ${line}: invalid hex arg ${index + 1}: ${s}`);
  }
  return parseInt(s, 16);
}

function validateTokens(tokens) {
  const errors = [];
  for (const t of tokens) {
    const line = t.line || '?';
    if (!KNOWN_OPS.has(t.op) && t.op !== 0x12 && t.op !== 0x13 && t.op !== OP_RAW_BYTES) {
      errors.push(`line ${line}: unknown opcode 0x${t.op.toString(16)}`);
      continue;
    }
    const minArgs = OP_MIN_ARGS[t.op];
    if (minArgs !== undefined && t.args.length < minArgs) {
      errors.push(`line ${line}: opcode 0x${t.op.toString(16)} expects at least ${minArgs} args, got ${t.args.length}`);
    }
    if (minArgs !== undefined && t.args.length > minArgs && t.op !== 0x80 && t.op !== 0x87) {
      errors.push(`line ${line}: opcode 0x${t.op.toString(16)} has ${t.args.length - minArgs} extra arg(s)`);
    }
    if (t.op === 0x80 && t.args.length > 3) {
      errors.push(`line ${line}: opcode 0x80 has ${t.args.length - 3} extra arg(s)`);
    }
    if (t.op === 0x87 && t.args.length > 3) {
      errors.push(`line ${line}: opcode 0x87 has ${t.args.length - 3} extra arg(s)`);
    }
  }
  if (errors.length) throw new CompileError(errors.join('\n'));
}

function validateAnalyzed(prog) {
  const errors = [];
  const strCount = Object.keys(prog.strings || {}).length;

  for (const ops of [prog.top || [], ...Object.values(prog.handlers || {})]) {
    for (const op of ops) {
      validateStringRefs(op, strCount, errors);
    }
  }

  if (errors.length) throw new CompileError(errors.join('\n'));
}

function validateStringRefs(op, strCount, errors) {
  const line = op.line || '?';
  const checkIdx = (idx) => {
    if (idx < 0 || idx >= strCount) {
      errors.push(`line ${line}: string index ${idx} out of range (0..${Math.max(0, strCount - 1)})`);
    }
  };
  if (op.op === 0x31 || op.op === 0x33) checkIdx(op.args[0]?.v);
  if (op.op === 0x50 || op.op === 0x51) checkIdx(op.args[1]?.v);
}

function mergeHandlerKeys(inProg, layout, blobSizes) {
  const sorted = [...inProg].sort((a, b) => a - b);
  if (!layout?.order?.length || !blobSizes?.size) return sorted;
  const missingFromLayout = sorted.filter(h => blobSizes.has(h) && !layout.order.includes(h));
  if (missingFromLayout.length) {
    throw new CompileError(
      'handlers with blobs missing from win-blob-layout.json order: ' +
      missingFromLayout.map(h => 'H_' + h.toString(16)).join(', ')
    );
  }
  const fromLayout = layout.order.filter(h => inProg.has(h));
  const tail = sorted.filter(h => !layout.order.includes(h));
  return [...fromLayout, ...tail];
}

function resolveFixupsStrict(code, opts = {}) {
  const missing = [];
  for (const f of code.fixups || []) {
    const t = code.labels[f.n];
    if (t === undefined) missing.push(f.n);
    else code.b.writeInt32LE(t - (f.p + 4), f.p);
  }
  if (missing.length && !opts.allowMissing) {
    const uniq = [...new Set(missing)];
    throw new CompileError('unresolved jump/call target(s): ' + uniq.join(', '));
  }
  return missing;
}

function resolveWinIatFixupsStrict(code, peFix) {
  const missing = [];
  for (const f of code.iatFixups || []) {
    if (f.isLd) {
      const fixDR = peFix.dataRVA;
      code.b.writeInt32LE(fixDR + f.o - f.instrEnd, f.dispPos);
    } else {
      const cr = peFix.ptrMap[f.importName];
      if (cr === undefined) missing.push(f.importName);
      else code.b.writeInt32LE(cr - f.instrEnd, f.dispPos);
    }
  }
  if (missing.length) {
    const uniq = [...new Set(missing)];
    throw new CompileError('unresolved IAT import(s): ' + uniq.join(', '));
  }
}

function assertWinImport(ptrMap, name) {
  if (ptrMap[name] === undefined) {
    throw new CompileError('unknown Win32 import: ' + name);
  }
}

function assertTextLimit(tell, limit, label) {
  if (tell > limit) {
    throw new CompileError(
      `${label || '.text'} size 0x${tell.toString(16)} exceeds TEXT_VS limit 0x${limit.toString(16)}`
    );
  }
}

function validateBeforeCompile(prog, tokens) {
  validateTokens(tokens);
  validateAnalyzed(prog);
}

module.exports = {
  CompileError,
  parseHexArg,
  validateTokens,
  validateAnalyzed,
  validateBeforeCompile,
  mergeHandlerKeys,
  resolveFixupsStrict,
  resolveWinIatFixupsStrict,
  assertWinImport,
  assertTextLimit,
};
