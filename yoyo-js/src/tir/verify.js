'use strict';

function verifyModule(mod) {
  const errors = [];
  if (!mod || !Array.isArray(mod.functions)) {
    errors.push('module missing functions[]');
    return { ok: false, errors };
  }
  const names = new Set();
  for (const fn of mod.functions) {
    if (!fn.name) errors.push('function without name');
    if (names.has(fn.name)) errors.push('duplicate function: ' + fn.name);
    names.add(fn.name);
    if (!fn.blocks || !fn.blocks.length) errors.push(fn.name + ': no blocks');
    for (const block of fn.blocks || []) {
      for (const op of block.ops || []) {
        if (!op.kind) errors.push(fn.name + ': op without kind');
      }
    }
  }
  for (const f of mod.fixups || []) {
    if (f.hh === undefined || f.hh < 0 || f.hh > 255) errors.push('fixup invalid hh: ' + f.hh);
  }
  return { ok: errors.length === 0, errors };
}

module.exports = { verifyModule };
