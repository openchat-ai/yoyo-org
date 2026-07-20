'use strict';
const fs = require('fs');
const { ELF_TEXT_FILE_OFF } = require('../src/platform-config.js');

const b = fs.readFileSync('/tmp/gen2.elf');
const textOff = ELF_TEXT_FILE_OFF;
const text = b.slice(textOff, textOff + 0x8000);
const rva = 0x401000;

for (let i = 0; i < text.length - 4; i++) {
  if (text[i] === 0xe8 && text[i+1]===0 && text[i+2]===0 && text[i+3]===0 && text[i+4]===0) {
    console.log('bad call at text+' + i.toString(16) + ' file+' + (textOff+i).toString(16) + ' rva 0x' + (rva+i).toString(16));
    if (i > 0) console.log('  prev bytes:', text.slice(Math.max(0,i-8), i+5).toString('hex'));
  }
}
