#!/usr/bin/env node
'use strict';

/**
 * Verify YOYO_BLOB_MODE=scan yoyo-gen path on Windows (or Linux).
 *
 * Usage:
 *   node scripts/scan-blob-check.js --target=win
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  blobHandlers,
  readPeHandlerLayout,
  readHandlerLayout,
  captureScanReferencePe,
  captureScanReferenceElf,
} = require('../src/blob-handlers.js');

const root = path.join(__dirname, '..');
const yoyoTy = path.join(root, 'projects/yoyo.ty');
const backup = path.join(root, 'build', 'yoyo.ty.pre-scan-blob');

function parseTarget(argv) {
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--target=')) return argv[i].slice(9).toLowerCase();
    if (argv[i] === '--target' && argv[i + 1]) return argv[i + 1].toLowerCase();
  }
  return process.env.YOYO_TARGET || 'win';
}

const target = parseTarget(process.argv);

function countBlobLines(src) {
  return src.split('\n').filter(l => /; blob \d+ bytes from scan reference/.test(l)).length;
}

try {
  if (fs.existsSync(yoyoTy)) fs.copyFileSync(yoyoTy, backup);

  const pre = fs.readFileSync(backup, 'utf8');

  console.log('[1] capture scan reference');
  const refExe = target === 'win'
    ? captureScanReferencePe(pre, root)
    : captureScanReferenceElf(pre, root);
  const layout = target === 'win' ? readPeHandlerLayout(refExe) : readHandlerLayout(refExe);
  const defined = layout.table.filter(v => v > 0 && v < 0x8000).length;
  console.log('  defined handlers:', defined, 'codeEnd:', '0x' + layout.codeEnd.toString(16));
  if (defined < 10) {
    console.error('FAIL: handler map looks empty (scan snapshot broken?)');
    process.exit(1);
  }

  console.log('[2] blobHandlers mode=scan');
  const blobbed = blobHandlers(pre, root, { mode: 'scan', target, verbose: true });
  fs.writeFileSync(yoyoTy, blobbed);
  const blobs = countBlobLines(blobbed);
  console.log('  blob sections:', blobs);
  if (blobs === 0) {
    console.error('FAIL: no scan blob sections embedded');
    process.exit(1);
  }

  console.log('[3] compile gen1');
  execSync(`node src/yoyo.js --target=${target} projects/yoyo.ty build/yoyo.exe`, {
    cwd: root,
    stdio: 'inherit',
  });

  console.log('scan-blob-check: PASS');
} finally {
  if (fs.existsSync(backup)) {
    fs.copyFileSync(backup, yoyoTy);
    fs.unlinkSync(backup);
    console.log('Restored projects/yoyo.ty');
  }
}
