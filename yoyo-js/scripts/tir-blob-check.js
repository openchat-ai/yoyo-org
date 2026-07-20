#!/usr/bin/env node
'use strict';

/**
 * Verify YOYO_TIR_BLOB=1 yoyo-gen path (cross-platform, no Linux ELF execution required on Windows).
 *
 * Usage:
 *   node scripts/tir-blob-check.js
 *   node scripts/tir-blob-check.js --target=win
 *   node scripts/tir-blob-check.js --target=linux
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const yoyoTy = path.join(root, 'projects/yoyo.ty');
const backup = path.join(root, 'build', 'yoyo.ty.pre-blob');

function parseTarget(argv) {
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--target=')) return argv[i].slice(9).toLowerCase();
    if (argv[i] === '--target' && argv[i + 1]) return argv[i + 1].toLowerCase();
  }
  return process.env.YOYO_TARGET || 'linux';
}

const target = parseTarget(process.argv);

function run(cmd, env = {}) {
  execSync(cmd, {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, YOYO_TARGET: target, ...env },
  });
}

function countBlobLines(src) {
  return src.split('\n').filter(l => /; blob \d+ bytes from (tir|node|scan) reference/.test(l)).length;
}

try {
  if (fs.existsSync(yoyoTy)) fs.copyFileSync(yoyoTy, backup);

  console.log(`[1] yoyo-gen with YOYO_TIR_BLOB=1 --target=${target} — SKIPPED: yoyo-gen.js deleted post-lockdown (Part 5.6)`);
  // yoyo-gen.js deleted post-lockdown (Part 5.6); this script is now an audit reference only
  const skipped = true;
  if (skipped) {
    console.error('FAIL: yoyo-gen.js deleted; this script no longer functional');
    process.exit(1);
  }

  const content = fs.readFileSync(yoyoTy, 'utf8');
  const blobs = countBlobLines(content);
  console.log('  blob sections:', blobs);
  if (blobs === 0) {
    console.error('FAIL: no TIR blob sections embedded');
    process.exit(1);
  }

  console.log('[2] M1 tir-check');
  run('node scripts/tir-check.js projects/yoyo.ty');

  if (target === 'linux') {
    console.log('[3] M2 compare-backends');
    run('node scripts/compare-backends.js');
  } else {
    console.log('[3] compile gen1 (win/x64)');
    run(`node src/yoyo.js --target=${target} projects/yoyo.ty build/yoyo.exe`);
    const size = fs.statSync(path.join(root, 'build/yoyo.exe')).size;
    console.log('  gen1 size:', size);
  }

  console.log('tir-blob-check: PASS');
} finally {
  if (fs.existsSync(backup)) {
    fs.copyFileSync(backup, yoyoTy);
    fs.unlinkSync(backup);
    console.log('Restored projects/yoyo.ty');
  }
}
