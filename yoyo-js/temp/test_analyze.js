#!/usr/bin/env node
const fs = require('fs');
const { parse, analyze } = require('F:/yoyo-ide/src/yoyo.js');

const ty = fs.readFileSync('F:/yoyo-ide/projects/yoyo.ty', 'utf-8');
const tokens = parse(ty);
console.log('Total tokens:', tokens.length);

// Try to analyze
try {
  const prog = analyze(tokens);
  const handlerKeys = Object.keys(prog.handlers).map(k => +k).sort((a, b) => a - b);
  console.log('Handlers found:', handlerKeys.length);
  console.log('Handler IDs:', handlerKeys.map(h => 'H_' + h.toString(16)).join(', '));
  for (const h of handlerKeys) {
    console.log(`  H_${h.toString(16)}: ${prog.handlers[h].length} ops`);
  }
  console.log('Top-level ops:', prog.top.length);
  console.log('Strings:', Object.keys(prog.strings).length);
  console.log('Blobs:', prog.blobs.length);
} catch (e) {
  console.log('ERROR:', e.message);
}