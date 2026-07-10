'use strict';

const tir = require('../tir/index.js');
const tirX64 = require('./tir-x64.js');

function compileX64(src, opts) {
  const yoyo = require('../yoyo.js');
  return yoyo.compile(src, { ...opts, backend: 'x64' });
}

const backends = {
  x64: {
    id: 'x64',
    description: 'Direct x64 meta-emitter (default bootstrap path)',
    compile: compileX64,
  },
  tir: {
    id: 'tir',
    description: 'TIR lowering + x64 fallback (semantic slice)',
    compile(src, opts) {
      const mod = tir.lowerProgramFromSource(src);
      if (opts && opts.verbose) {
        console.error('[tir] handlers:', mod.meta.handlerCount, 'fixups:', mod.meta.fixupCount);
      }
      const v = tir.verifyModule(mod);
      if (!v.ok) throw new Error('TIR verify: ' + v.errors.join('; '));
      return compileX64(src, opts);
    },
  },
  'tir-x64': {
    id: 'tir-x64',
    description: 'TIR → x64 (Phase 2)',
    compile(src, opts) {
      const handlerOrder = opts?.handlerOrder || process.env.TIR_HANDLER_ORDER || 'analyze';
      const mod = tir.lowerProgramFromSource(src, { handlerOrder });
      return tirX64.compile(src, { ...opts, handlerOrder }, mod);
    },
  },
  'tir-wasm': {
    id: 'tir-wasm',
    description: 'TIR → WASM (Phase 4 skeleton)',
    compile(src, opts) {
      const handlerOrder = opts?.handlerOrder || process.env.TIR_HANDLER_ORDER || 'file';
      const mod = tir.lowerProgramFromSource(src, { handlerOrder });
      const wasm = require('./tir-wasm.js');
      return wasm.compile(src, opts, mod);
    },
  },
};

function resolveBackend(name) {
  const id = (name || 'x64').toLowerCase();
  const backend = backends[id];
  if (!backend) {
    throw new Error('Unknown backend: ' + id + ' (available: ' + Object.keys(backends).join(', ') + ')');
  }
  return backend;
}

module.exports = { backends, resolveBackend };
