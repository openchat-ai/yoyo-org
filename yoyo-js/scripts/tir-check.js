#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { lowerProgramFromSource, verifyModule, printModule } = require('../src/tir/index.js');

const srcPath = process.argv[2] || path.join(__dirname, '..', 'projects', 'yoyo.ty');
const verbose = process.argv.includes('--verbose');
const dump = process.argv.includes('--dump');
const limit = process.argv.includes('--limit') ? parseInt(process.argv[process.argv.indexOf('--limit') + 1], 10) : 0;

const text = fs.readFileSync(srcPath, 'utf8');
const mod = lowerProgramFromSource(text);
const v = verifyModule(mod);

console.log('TIR check:', srcPath);
console.log('  handlers:', mod.meta.handlerCount);
console.log('  top ops:', mod.meta.topOpCount);
console.log('  fixups:', mod.meta.fixupCount);
console.log('  verify:', v.ok ? 'OK' : 'FAIL');
if (!v.ok) {
  for (const e of v.errors) console.log('   -', e);
  process.exit(1);
}

if (verbose || dump) {
  console.log('');
  console.log(printModule(mod, { limit: dump ? 0 : limit || 40 }));
}

// M1 gate for evolution.md
const M1_HANDLERS = 120;
const M1_FIXUPS = 500;
if (mod.meta.handlerCount < M1_HANDLERS || mod.meta.fixupCount < M1_FIXUPS) {
  console.warn('  warn: below M1 thresholds (' + M1_HANDLERS + ' handlers, ' + M1_FIXUPS + ' fixups)');
}
