'use strict';

/**
 * TIR → x64 Linux emitter (Phase 2).
 * Uses shared linux-emit-core for opcode mapping.
 */
const { compileFromTirModule, compileFromAnalyzed } = require('./linux-emit-core.js');
const { parse, analyze } = require('../yoyo.js');

function emitModule(mod, opts = {}) {
  if (opts.handlerOrder === 'analyze') {
    const prog = analyze(parse(opts.source || ''));
    return compileFromAnalyzed(prog, opts);
  }
  return compileFromTirModule(mod, opts);
}

module.exports = { emitModule, compileFromAnalyzed, compileFromTirModule };
