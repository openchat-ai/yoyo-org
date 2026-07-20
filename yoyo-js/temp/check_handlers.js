#!/usr/bin/env node
// Diagnostic: count handlers in yoyo.ty and check for missing FF
const fs = require('fs');
const path = require('path');

const ty = fs.readFileSync('F:/yoyo-ide/projects/yoyo.ty', 'utf-8');
const lines = ty.split('\n');

let handlerLabels = []; // { line, hh }
let handlerFF = []; // line numbers of FF that close handlers
let raw40s = 0;
let rawFFs = 0;

for (let i = 0; i < lines.length; i++) {
  const l = lines[i];
  const t = l.trim();
  if (!t || t[0] === ';' || t[0] === '#') continue;
  const body = t.replace(/;.*$/, '').trim();
  if (!body) continue;
  const parts = body.split(/\s+/);
  const op = parts[0];
  if (op === '40') {
    raw40s++;
    handlerLabels.push({ line: i+1, hh: parseInt(parts[1], 16), text: t });
  }
  if (op === 'FF') {
    rawFFs++;
    handlerFF.push(i+1);
  }
}

console.log('Total handler labels (40 hh):', handlerLabels.length);
console.log('Total FF (ret) instructions:', rawFFs);
console.log('');

// Check for consecutive 40 hh without FF between them
for (let i = 1; i < handlerLabels.length; i++) {
  const prev = handlerLabels[i-1];
  const curr = handlerLabels[i];
  // Count FFs between prev and curr
  const ffsBetween = handlerFF.filter(ffLine => ffLine > prev.line && ffLine < curr.line).length;
  if (ffsBetween === 0) {
    console.log(`WARN: H_${prev.hh.toString(16)} (line ${prev.line}) -> H_${curr.hh.toString(16)} (line ${curr.line}): NO FF between them!`);
    // Show lines between
    for (let j = prev.line; j <= curr.line && j < prev.line + 10; j++) {
      console.log(`  ${j}: ${lines[j-1]}`);
    }
  }
}
console.log('');

// Check for missing final FF
const lastLabel = handlerLabels[handlerLabels.length-1];
const ffsAfter = handlerFF.filter(ffLine => ffLine > lastLabel.line).length;
if (ffsAfter === 0) {
  console.log(`WARN: Last handler H_${lastLabel.hh.toString(16)} (line ${lastLabel.line}): no FF after it`);
  // Show last 5 lines
  for (let j = Math.max(0, lines.length - 5); j < lines.length; j++) {
    console.log(`  ${j+1}: ${lines[j]}`);
  }
}

console.log('\nHandler list:');
for (const h of handlerLabels) {
  console.log(`  H_${h.hh.toString(16).padStart(2, '0')}: line ${h.line}`);
}