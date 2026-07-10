#!/usr/bin/env node
'use strict';

/**
 * Smoke tests for compile-time validation (yoyo.js).
 */
const assert = require('assert');
const path = require('path');
const { compile, parse, analyze, CompileError } = require('../src/yoyo.js');

function expectAnalyzeError(src, pattern) {
  let threw = false;
  try {
    analyze(parse(src));
  } catch (e) {
    threw = true;
    assert(e instanceof CompileError, `expected CompileError, got ${e}`);
    if (pattern) assert.match(e.message, pattern);
  }
  assert(threw, 'expected analyze to throw');
}

const root = path.join(__dirname, '..');

function expectCompileError(src, pattern) {
  let threw = false;
  try {
    compile(src, { target: 'win' });
  } catch (e) {
    threw = true;
    assert(e instanceof CompileError, `expected CompileError, got ${e}`);
    if (pattern) assert.match(e.message, pattern);
  }
  assert(threw, 'expected compile to throw');
}

console.log('[1] valid minimal compile');
compile('12 s6100\n41 00\n40 00\nFF\n', { target: 'win' });

console.log('[2] invalid opcode token');
expectCompileError('zz 00\n', /invalid opcode token/);

console.log('[3] extra arg');
expectCompileError('30 50 00 99\n41 00\n40 00\nFF\n', /extra arg/);

console.log('[4] unclosed handler at EOF');
expectAnalyzeError('41 00\n40 01\n30 50 00\n', /not closed with FF before EOF/);

console.log('[5] missing jump target (strict fixups)');
process.env.YOYO_STRICT_FIXUPS = '1';
expectCompileError('41 00\n40 00\n41 99\nFF\n', /unresolved jump/);
delete process.env.YOYO_STRICT_FIXUPS;

console.log('[6] invalid hex arg');
expectCompileError('30 50 gg\n41 00\n40 00\nFF\n', /invalid hex/);

console.log('[7] compile projects/yoyo.ty');
const fs = require('fs');
const ty = fs.readFileSync(path.join(root, 'projects/yoyo.ty'), 'utf8');
compile(ty, { target: 'win' });

console.log('compile-validator-check: PASS');
