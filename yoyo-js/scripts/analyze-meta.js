'use strict';
const fs = require('fs');
const { execSync } = require('child_process');
const { ELF_TEXT_FILE_OFF } = require('../src/platform-config.js');

function analyze(label, path) {
  const b = fs.readFileSync(path);
  const text = b.slice(ELF_TEXT_FILE_OFF, ELF_TEXT_FILE_OFF + 0x8000);
  let nops = 0, code = 0, badcalls = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === 0x90) nops++;
    else code++;
    if (text[i] === 0xe8 && text[i + 1] === 0 && text[i + 2] === 0 && text[i + 3] === 0 && text[i + 4] === 0) badcalls++;
  }
  console.log(label, 'size', b.length, 'text nops', nops, 'non-nop', code, 'bad e8', badcalls);
}

const root = require('path').join(__dirname, '..');
process.chdir(root);
execSync('echo yoyo-gen.js deleted - skipping pre-lockdown regeneration', { stdio: 'ignore' });
execSync('node src/yoyo.js --target=linux projects/yoyo.ty build/yoyo', { stdio: 'ignore' });
execSync('cp projects/yoyo.ty input.ky');
execSync('./build/yoyo', { stdio: 'ignore' });
fs.copyFileSync('output', '/tmp/gen2.elf');
analyze('gen2', '/tmp/gen2.elf');
execSync('chmod +x /tmp/gen2.elf');
execSync('cp projects/yoyo.ty input.ky');
execSync('/tmp/gen2.elf', { stdio: 'ignore' });
fs.copyFileSync('output', '/tmp/gen3.elf');
analyze('gen3', '/tmp/gen3.elf');
execSync('rm -f input.ky output');
