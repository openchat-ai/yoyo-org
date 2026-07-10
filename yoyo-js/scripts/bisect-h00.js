#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const text = fs.readFileSync(path.join(root, 'projects/yoyo.ty'), 'utf8');
const lines = text.split('\n');

const header = [];
for (const l of lines) {
  if (/^40 00/i.test(l.trim())) break;
  header.push(l);
}

const h00 = [];
let inside = false;
for (const l of lines) {
  const t = l.trim();
  if (/^40 00/i.test(t)) { inside = true; continue; }
  if (!inside) continue;
  if (/^40 [0-9a-f]+/i.test(t)) break;
  if (/^ff/i.test(t.split(/[\s;]/)[0])) break;
  if (t && !t.startsWith(';')) h00.push(l);
}

function buildTy(nOps) {
  const short = h00.slice(0, nOps);
  return [...header, '41 00', '40 00', ...short, 'ff'].join('\n');
}

function test(nOps) {
  const ty = buildTy(nOps);
  fs.writeFileSync(path.join(root, 'projects/test-prefix.ty'), ty);
  execSync('node src/yoyo.js --target=win projects/test-prefix.ty build/test-prefix.exe', {
    cwd: root,
    stdio: 'pipe',
  });
  fs.copyFileSync(path.join(root, 'projects/test-prefix.ty'), path.join(root, 'input.ky'));
  const r = spawnSync(path.join(root, 'build/test-prefix.exe'), { cwd: root, timeout: 60000 });
  const code = r.status;
  const label = code === 0 ? 'OK' : (code === null ? 'crash/timeout' : `exit ${code}`);
  console.log(`ops ${nOps}: ${label}`);
  return code;
}

const counts = [1, 2, 3, 4, 5, 8, 10, 15, 20, 30, 40, 50, 60, 70, 80, 90, 100, 120];
for (const n of counts) {
  const code = test(n);
  if (code !== 0) {
    console.log(`First failure at ${n} ops`);
    if (n > 1) test(n - 1);
    break;
  }
}
