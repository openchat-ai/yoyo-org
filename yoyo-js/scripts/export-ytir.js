#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { lowerProgramFromSource } = require('../src/tir/lower.js');
const { serializeModule } = require('../src/tir/serialize.js');

const srcPath = process.argv[2] || path.join(__dirname, '..', 'projects', 'yoyo.ty');
const outPath = process.argv[3] || srcPath.replace(/\.(ty|ky)$/, '.ytir');
const handlerOrder = process.env.TIR_HANDLER_ORDER || 'file';

const text = fs.readFileSync(srcPath, 'utf8');
const mod = lowerProgramFromSource(text, { handlerOrder });
const ytir = serializeModule(mod);

fs.writeFileSync(outPath, ytir);
console.log('Wrote', outPath, '(' + ytir.length + ' bytes,', mod.meta.handlerCount, 'handlers)');
