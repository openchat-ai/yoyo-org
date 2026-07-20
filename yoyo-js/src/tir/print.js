'use strict';

function formatOp(op) {
  switch (op.kind) {
    case 'label': return 'label H' + op.hh.toString(16);
    case 'call': return 'call H' + op.hh.toString(16);
    case 'jmp': return 'jmp H' + op.hh.toString(16);
    case 'jcc': return 'jcc.' + op.cond + ' H' + op.hh.toString(16);
    case 'ret': return 'ret';
    case 'state.set': return 'state[' + op.slot.toString(16) + '] = ' + op.value;
    case 'emit.u8': return 'emit.u8 ' + op.value.toString(16);
    case 'alloc': return 'alloc state_' + op.slot.toString(16) + ' size=0x' + op.size.toString(16);
    case 'raw.a0': return 'raw.a0 ' + (op.hex.length > 32 ? op.hex.slice(0, 32) + '…' : op.hex);
    case 'nop': return 'nop raw=0x' + (op.rawOp || 0).toString(16);
    default:
      return op.kind + ' ' + JSON.stringify(Object.fromEntries(
        Object.entries(op).filter(([k]) => k !== 'kind')
      ));
  }
}

function printModule(mod, opts = {}) {
  const lines = [];
  lines.push('; TIR module ' + mod.name);
  lines.push('; handlers: ' + (mod.meta?.handlerCount ?? mod.functions.length));
  lines.push('; fixups: ' + (mod.meta?.fixupCount ?? mod.fixups?.length ?? 0));
  lines.push('');

  const limit = opts.limit || 0;
  let count = 0;

  for (const fn of mod.functions) {
    lines.push('fn ' + fn.name + ' {');
    for (const block of fn.blocks) {
      lines.push('  ' + block.label + ':');
      for (const op of block.ops) {
        lines.push('    ' + formatOp(op));
        count++;
        if (limit && count >= limit) {
          lines.push('    …');
          lines.push('}');
          return lines.join('\n');
        }
      }
    }
    lines.push('}');
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = { printModule, formatOp };
