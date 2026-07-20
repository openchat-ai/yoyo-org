#!/usr/bin/env node
/**
 * M3 bootstrap auto-checker.
 * Run BEFORE and AFTER any yoyo.ty change.
 *
 * Usage: node scripts/check-m3.js
 * Exit 0 = all gates pass
 * Exit 1 = something failed (details printed)
 */
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto'), { execSync, spawnSync } = require('child_process');
const ROOT = path.join(__dirname, '..');
const YOYO_TY = path.join(ROOT, 'projects/yoyo.ty');
const GEN1 = path.join(ROOT, 'build/yoyo.exe');
const GEN2 = path.join(ROOT, 'build/gen2.exe');
const BASELINE_SHA = '1D12F6C113799DC40FFED6A96A17725CC14033BDBB3564D2AEBB2805872E7FF7';

let passed = 0, failed = 0;
function check(name, ok, detail) {
    if (ok) { console.log(`  ✓ ${name}`); passed++; }
    else { console.log(`  ✗ ${name}: ${detail || 'FAIL'}${detail ? '\n    ' + detail : ''}`); failed++; }
}
function sha256(f) { return fs.existsSync(f) ? crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex') : '(missing)'; }
function run(script, args) {
    const all = [path.join(ROOT, 'scripts', script)];
    for (const a of (args || [])) all.push(a);
    const r = spawnSync(process.execPath, all, { cwd: ROOT, timeout: 60000, encoding: 'utf8' });
    return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}
function runExe(exePath) {
    const outExe = path.join(ROOT, 'output.exe');
    const inKy = path.join(ROOT, 'input.ky');
    const label = path.basename(exePath).replace('.exe', '');
    [outExe, inKy].forEach(f => { try { fs.unlinkSync(f); } catch (e) { /* ok */ } });
    try {
        fs.copyFileSync(YOYO_TY, inKy);
        execSync(`"${exePath}"`, { cwd: ROOT, stdio: 'pipe', timeout: 60000 });
        if (fs.existsSync(outExe)) {
            const dest = path.join(ROOT, 'build', label + '-out.exe');
            fs.copyFileSync(outExe, dest);
            return { ok: true, path: dest, sha: sha256(dest), size: fs.statSync(dest).size };
        }
        return { ok: false, error: 'no output.exe' };
    } catch (e) {
        return { ok: false, exitCode: e.status || -1, error: e.message };
    }
}
function handlerMapCount(exePath) {
    if (!fs.existsSync(exePath)) return -1;
    const b = fs.readFileSync(exePath);
    const mapOff = 0x8800 + 0xFE00;
    if (b.length < mapOff + 0x404) return -1;
    let n = 0;
    for (let i = 0; i < 256; i++) { const v = b.readUInt32LE(mapOff + i * 4); if (v > 0 && v < 0x8000) n++; }
    return n;
}
function codeEnd(exePath) {
    if (!fs.existsSync(exePath)) return -1;
    const b = fs.readFileSync(exePath);
    return b.readUInt32LE(0x8800 + 0xFE00 + 0x400);
}

console.log('═══ M3 auto-checker ═══\n');

console.log('[pre] yoyo.ty exists');
check('yoyo.ty exists', fs.existsSync(YOYO_TY));

console.log('\n[M1] tir-check');
const m1 = run('tir-check.js');
check('M1 exit 0', m1.code === 0, m1.out.slice(0, 200));

console.log('\n[M2] compare-backends (win)');
const m2w = run('compare-backends.js', ['--target=win']);
check('M2 win exit 0', m2w.code === 0, m2w.out.slice(0, 200));

console.log('\n[M2] compare-backends (linux)');
const m2l = run('compare-backends.js', ['--target=linux']);
check('M2 linux exit 0', m2l.code === 0, m2l.out.slice(0, 200));

console.log('\n[build] node → gen1');
execSync(`node "${ROOT}/src/yoyo.js" --target=win "${YOYO_TY}" "${GEN1}"`, { cwd: ROOT, stdio: 'pipe' });
const g1sha = sha256(GEN1);
check('gen1 SHA = baseline', g1sha.toUpperCase() === BASELINE_SHA, g1sha);

console.log('\n[gen1→gen2] run yoyo.exe');
fs.existsSync(GEN2) && fs.unlinkSync(GEN2);
const g1r = runExe(GEN1);
if (g1r.ok) {
    check('gen1 exit 0', true);
    fs.copyFileSync(g1r.path, GEN2);
    const hc = handlerMapCount(GEN2);
    const ce = codeEnd(GEN2);
    check('gen2 handlers >= 2', hc >= 2, `${hc} handlers`);
    check('gen2 codeEnd > 100', ce > 100, `codeEnd=0x${ce.toString(16)}`);
    console.log('  gen2: ' + hc + ' handlers, codeEnd=0x' + ce.toString(16));
} else {
    check('gen1→gen2 CRASH', false, `exit=${g1r.exitCode} ${g1r.error || ''}`);
}

console.log('\n[gen2→gen3] (critical test)');
if (fs.existsSync(GEN2)) {
    const g2r = runExe(GEN2);
    if (g2r.ok) {
        check('gen2→gen3 exited 0', true);
        const hc3 = handlerMapCount(path.join(ROOT, 'build/gen2-out.exe'));
        check('gen3 handler count >= 2', hc3 >= 2, `${hc3} handlers`);
        // Compare gen2 vs gen3
        const b2 = fs.readFileSync(GEN2), b3 = fs.readFileSync(path.join(ROOT, 'build/gen2-out.exe'));
        let diffs = 0;
        for (let i = 0; i < Math.min(b2.length, b3.length); i++) if (b2[i] !== b3[i]) diffs++;
        diffs += Math.abs(b2.length - b3.length);
        check('gen2 ≡ gen3 byte-identical', diffs === 0, `${diffs} byte diffs`);
    } else {
        check('gen2→gen3 (CRASH)', false, `exit=${g2r.exitCode} ${g2r.error || ''}`);
    }
} else {
    check('gen2→gen3 (skip)', false, 'gen2 not available');
}

console.log(`\n═══ Result: ${passed} passed, ${failed} failed ═══`);
process.exit(failed > 0 ? 1 : 0);
