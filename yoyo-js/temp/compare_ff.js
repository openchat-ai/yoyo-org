#!/usr/bin/env node
const fs = require('fs');

function analyzeTy(name, path) {
  const ty = fs.readFileSync(path, 'utf-8');
  const lines = ty.split('\n');
  let ffs = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t || t[0] === ';' || t[0] === '#') continue;
    const body = t.replace(/;.*$/, '').trim();
    if (!body) continue;
    const parts = body.split(/\s+/);
    if (parts[0] === 'FF') {
      ffs.push(i + 1);
    }
  }
  return { name, lines: lines.length, size: ty.length, ffs };
}

const win = analyzeTy('windows', 'F:/yoyo-ide/projects/yoyo.ty.win-bak');
const lin = analyzeTy('linux', 'F:/yoyo-ide/projects/yoyo.ty');

console.log('=== Comparison ===');
console.log('Windows: ' + win.lines + ' lines, ' + win.size + ' bytes, ' + win.ffs.length + ' FF');
console.log('Linux:   ' + lin.lines + ' lines, ' + lin.size + ' bytes, ' + lin.ffs.length + ' FF');
console.log('');

// Show FF locations side by side
const maxFf = Math.max(win.ffs.length, lin.ffs.length);
console.log('FF positions (line numbers):');
console.log('idx  Win     Lin');
for (let i = 0; i < maxFf; i++) {
  const w = i < win.ffs.length ? win.ffs[i].toString().padStart(6) : '      ';
  const l = i < lin.ffs.length ? lin.ffs[i].toString().padStart(6) : '      ';
  console.log(i.toString().padStart(3) + ' ' + w + ' ' + l);
}

// Check for consecutive FF without 40 hh between them
console.log('');
console.log('=== Missing FF checks ===');
for (const { name, ffs } of [win, lin]) {
  let gaps = 0;
  for (let i = 1; i < ffs.length; i++) {
    const gap = ffs[i] - ffs[i-1];
    if (gap < 5) {
      console.log(name + ': FF at line ' + ffs[i-1] + ' and ' + ffs[i] + ' (gap=' + gap + ' lines)');
      gaps++;
    }
  }
  if (gaps === 0) console.log(name + ': no consecutive FFs');
}