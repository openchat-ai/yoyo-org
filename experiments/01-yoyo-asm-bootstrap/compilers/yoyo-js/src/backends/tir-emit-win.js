'use strict';

/**
 * TIR → x64 Windows emitter (Phase 2, port of tir-emit-linux.js).
 *
 * analyze path: delegate to yoyo.js compileWin so byte output matches
 *   --backend=x64 (M2 gate). This avoids re-implementing compileWin's
 *   prologue/handler/relocation logic in win-emit-core.
 *
 * tir path: emit TIR module via win-emit-core's compileFromTirModule.
 */
const { compileFromTirModule } = require('./win-emit-core.js');
const { parse, analyze } = require('../yoyo.js');

function emitModule(mod, opts = {}) {
  if (opts.handlerOrder === 'analyze') {
    const yoyo = require('../yoyo.js');
    return yoyo.compile(opts.source || '', { target: 'win' });
  }
  return compileFromTirModule(mod, opts);
}

module.exports = { emitModule, compileFromTirModule };