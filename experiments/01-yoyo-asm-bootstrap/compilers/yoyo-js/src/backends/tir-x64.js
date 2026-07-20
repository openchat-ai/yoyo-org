'use strict';

/**
 * TIR → x64 backend (Phase 2 — partial).
 * Routes to tir-emit-{linux,win}.js based on opts.target.
 */
const { verifyModule } = require('../tir/verify.js');

function compile(_src, opts, mod) {
  const v = verifyModule(mod);
  if (!v.ok) {
    throw new Error('TIR verify failed:\n' + v.errors.join('\n'));
  }
  if (opts && opts.verbose) {
    console.error('[tir-x64] handlers:', mod.meta?.handlerCount, 'fixups:', mod.meta?.fixupCount,
      'order:', mod.meta?.handlerOrder || opts.handlerOrder || 'file',
      'target:', opts.target || 'linux');
  }
  const handlerOrder = opts?.handlerOrder || process.env.TIR_HANDLER_ORDER || 'analyze';
  const emitModule = (opts?.target === 'win' || opts?.target === 'windows')
    ? require('./tir-emit-win.js').emitModule
    : require('./tir-emit-linux.js').emitModule;
  return emitModule(mod, { ...opts, handlerOrder, source: _src });
}

module.exports = { compile };
