'use strict';

/**
 * TIR → WASM backend (Phase 4 skeleton).
 * Emits a minimal valid WASM module with placeholder functions per handler.
 */
const { verifyModule } = require('../tir/verify.js');

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);
const WASM_VERSION = Buffer.from([0x01, 0x00, 0x00, 0x00]);

function leb128(n) {
  const out = [];
  let v = n >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return Buffer.from(out);
}

function section(id, payload) {
  return Buffer.concat([Buffer.from([id]), leb128(payload.length), payload]);
}

function compile(_src, opts, mod) {
  const v = verifyModule(mod);
  if (!v.ok) throw new Error('TIR verify failed:\n' + v.errors.join('\n'));

  const handlerCount = mod.meta?.handlerCount || mod.functions.length;
  if (opts?.verbose) {
    console.error('[tir-wasm] handlers:', handlerCount, '(skeleton — no real codegen yet)');
  }

  // Type section: () -> ()
  const types = section(1, Buffer.concat([
    leb128(1),
    Buffer.from([0x60, 0x00, 0x00]),
  ]));

  // Function section: one func per handler + top
  const funcCount = mod.functions.length;
  const funcs = section(3, Buffer.concat([
    leb128(funcCount),
    Buffer.alloc(funcCount, 0),
  ]));

  // Export section: memory + "main"
  const exportName = Buffer.from('memory\0');
  const exports = section(7, Buffer.concat([
    leb128(2),
    Buffer.concat([
      Buffer.from([exportName.length - 1]), exportName.slice(0, -1),
      Buffer.from([0x02]), leb128(0),
    ]),
    Buffer.from([4]), Buffer.from('main'), Buffer.from([0x00]), leb128(0),
  ]));

  // Memory section: 1 page min
  const memory = section(5, Buffer.concat([
    leb128(1),
    Buffer.from([0x00]), leb128(1),
  ]));

  // Code section: empty bodies (unreachable end)
  const codeBodies = [];
  for (let i = 0; i < funcCount; i++) {
    const body = Buffer.concat([
      leb128(0),
      Buffer.from([0x0b]),
    ]);
    codeBodies.push(Buffer.concat([leb128(body.length), body]));
  }
  const code = section(10, Buffer.concat([leb128(funcCount), ...codeBodies]));

  const wasm = Buffer.concat([WASM_MAGIC, WASM_VERSION, types, funcs, memory, exports, code]);

  if (opts?.stub !== false) {
    const comment = Buffer.from(
      `; tir-wasm skeleton: ${handlerCount} handlers — Phase 4 placeholder\n`,
      'utf8'
    );
    return Buffer.concat([comment, wasm]);
  }
  return wasm;
}

module.exports = { compile };
