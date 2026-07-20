'use strict';
const fs = require('fs');
const { ELF_TEXT_FILE_OFF } = require('../src/platform-config.js');

const gen2Path = process.argv[2] || '/tmp/gen2.elf';
const b = fs.readFileSync(gen2Path);
const text = b.slice(ELF_TEXT_FILE_OFF, ELF_TEXT_FILE_OFF + 0x8000);

const bad = [];
for (let i = 0; i < text.length - 4; i++) {
  if (text[i] === 0xe8 && text[i + 1] === 0 && text[i + 2] === 0 && text[i + 3] === 0 && text[i + 4] === 0) {
    bad.push(i);
  }
}
console.log('bad e8 count', bad.length);
console.log('first 10 patch_pos (rel32 field):', bad.slice(0, 10).map(p => '0x' + (p + 1).toString(16)));

// Heuristic: rel32=0 means call next insn — check if target would be state_0E+5 at emit time
for (const p of bad.slice(0, 5)) {
  const patchPos = p + 1;
  console.log('site text+0x' + p.toString(16), 'patch_pos=0x' + patchPos.toString(16),
    'ctx', text.slice(Math.max(0, p - 8), p + 8).toString('hex'));
}
