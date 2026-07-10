'use strict';

const { createModule, createFunction } = require('./module.js');
const { lowerProgram, lowerProgramFromSource } = require('./lower.js');
const { verifyModule } = require('./verify.js');
const { printModule } = require('./print.js');
const { serializeModule, deserializeModule } = require('./serialize.js');
const { Op, JCC, isForwardFixupOp } = require('./ops.js');

module.exports = {
  createModule,
  createFunction,
  lowerProgram,
  lowerProgramFromSource,
  verifyModule,
  printModule,
  serializeModule,
  deserializeModule,
  Op,
  JCC,
  isForwardFixupOp,
};
