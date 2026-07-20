const E=require('./encode-x64.js');
const{PE}=require('./pe-builder.js');
const{TEXT_VS,CODE_RVA,STATE_TARGET,STATE_BUF_OFF,WIN_FUNCS}=require('./platform-config.js');
const{ELF,alignS,BASE}=require('./elf-builder.js');
const{buildLinuxStartup,makeLinuxEmit}=require('./linux-runtime.js');
const{relocateSliceWithLayout,parseBlobRefOffsets,parseBlobHandlers,readWinBlobLayout,isBlobHandlerOps,blobRawFromOps,buildActualRefFromLabels}=require('./blob-handlers.js');
const{CompileError,validateBeforeCompile,mergeHandlerKeys,resolveFixupsStrict,resolveWinIatFixupsStrict,assertWinImport,assertTextLimit}=require('./compile-validator.js');
const{KNOWN_OPS,emitStoreByte87,OP_RAW_BYTES,TIR_KEYWORDS}=require('./opcode-emit-x64.js');

const RCX=1,RDX=2,RSP=4,RSI=6,RDI=7,R8=8,R9=9,R12=12,R13=13,R14=14,R15=15;
const RAX=0;

E.mov_mi64=function(b,b2,d,v){E.mov_ri(b,RAX,v);E.mov_mr64(b,b2,d,RAX);};
E.lea_rr=function(b,d,s,disp){
  b.rex(1,d>7,0,s>7);b.u8(0x8D);
  function w(m){if((s&7)===4){b.modrm(m,d&7,4);b.sib(0,4,s&7);}else{b.modrm(m,d&7,s&7);}}
  if(disp===0&&s!==5)w(0);else if(disp>=-128&&disp<=127){w(1);b.u8(disp&255);}else{w(2);b.u32(disp);}
};

function parse(text){
  const r=[];
  const lines=text.split('\n');
  for(let li=0;li<lines.length;li++){
    const l=lines[li];
    const line=li+1;
    const t=l.trim();if(!t||t[0]===';'||t[0]==='#')continue;
    const body=t.replace(/;.*$/,'').trim();if(!body)continue;
    let p=body.split(/\s+/);
    let op;
    let tirRawHex = false;
    if(TIR_KEYWORDS[p[0]]!==undefined){
      // TIR intrinsics form: e.g. "call H_01", "state.set 5 0", "ret"
      op=TIR_KEYWORDS[p[0]];
      // For data.blob (0x13) the second arg is a hex literal that may exceed
      // JS number precision. Mark it so the args mapper below keeps it as a
      // string instead of converting to a number.
      if (op === 0x13) tirRawHex = true;
      p=p.slice(1).map(x=>x.startsWith('H_')?x.slice(2):x);
      p=[String(op),...p];
    }else{
      op=parseInt(p[0],16);
      if(isNaN(op))throw new CompileError(`line ${line}: invalid opcode token "${p[0]}"`);
    }
    if(!KNOWN_OPS.has(op)&&op!==0x12&&op!==0x13){
      const bytes=[];
      for(const part of p){
        if(!/^[0-9a-fA-F]{1,2}$/.test(part))throw new CompileError(`line ${line}: invalid raw byte "${part}"`);
        bytes.push(parseInt(part,16));
      }
      r.push({op:OP_RAW_BYTES,rawBytes:bytes,line});
      continue;
    }
const args=p.slice(1).map((x, i)=>{
      if(x[0]==='s'){const b=[];for(let i=1;i<x.length;i+=2)b.push(parseInt(x.substr(i,2),16)||0);const B=Buffer.from(b);return{t:'s',v:B.toString('utf8'),raw:B};}
      if(op===0xA0){return{t:'h',v:x};}
      if(op===0xA1){if(!/^[0-9a-fA-F]+$/.test(x))throw new CompileError(`line ${line}: invalid hex byte "${x}"`);return{t:'n',v:parseInt(x,16)};}
      // data.blob (0x13) raw hex arg — args[1] is the long hex blob; keep as
      // string to preserve precision. args[0] is the offset (number).
      if (op === 0x13 && tirRawHex && i === 1) return {t:'h',v:x};
      if(!/^[0-9a-fA-F]+$/.test(x))throw new CompileError(`line ${line}: invalid hex arg "${x}"`);
      return{t:'n',v:parseInt(x,16)};
    });
    r.push({op,args,line});
  }return r;
}

function analyze(tokens){
  const S={},B=[],O=[],H={};let si=0,ch=null;
  for(const t of tokens){
    if(ch!==null){
      if(t.op===0xFF){H[ch].push(t);ch=null;continue;}
      H[ch].push(t);
      continue;
    }
    if(t.op===0x12){S[si]={text:t.args[1]?t.args[1].v:(t.args[0].t==='s'?t.args[0].v:'')};si++;}
    else if(t.op===0x13){B.push({off:t.args[0].v,data:t.args[1].raw||Buffer.from(t.args[1].v,'hex')});}
    else if(t.op===0x40){
      const hh=t.args[0].v;
      if(ch!==null){
        throw new CompileError(`line ${t.line}: handler H_${ch.toString(16)} not closed with FF before H_${hh.toString(16)}`);
      }
      if(H[hh]&&H[hh].length>0){
        if(process.env.YOYO_WARN_DUP_HANDLER==='1'){
          console.warn(`warn: line ${t.line}: handler H_${hh.toString(16)} redefined (last section wins)`);
        }
        H[hh]=[];
      }else if(!H[hh]){
        H[hh]=[];
      }
      ch=hh;
    }
    else O.push(t);
  }
  if(ch!==null)throw new CompileError(`handler H_${ch.toString(16)} not closed with FF before EOF`);
  return{strings:S,blobs:B,top:O,handlers:H};
}

function compile(src,opts={}){
  const target=(opts.target||'win').toLowerCase();
  const backend=(opts.backend||'x64').toLowerCase();
  if(backend!=='x64'){
    const {resolveBackend}=require('./backends/registry.js');
    return resolveBackend(backend).compile(src,{...opts,target});
  }
  return target==='linux'?compileLinux(src):compileWin(src);
}

function compileWin(src){
  const tokens=parse(src);
  const prog=analyze(tokens);
  validateBeforeCompile(prog,tokens);
  const {compileFromAnalyzed}=require('./backends/win-emit-core.js');
  return compileFromAnalyzed(prog);
}

function compileLinux(src){
  const tokens=parse(src);
  const prog=analyze(tokens);
  validateBeforeCompile(prog,tokens);
  const {compileFromAnalyzed}=require('./backends/linux-emit-core.js');
  return compileFromAnalyzed(prog);
}

module.exports={compile,parse,analyze,CompileError};

if(require.main===module){(async()=>{
  const fs=require('fs');
  const path=require('path');
  const args=process.argv.slice(2);
  let target='win';
  let backend='x64';
  const rest=[];
  // --input=FNAME: override the input .ty file (default: first positional)
  let inputFile=null;
  // --output=FNAME: override the output .exe file (default: derived from input)
  let outputFile=null;
  for(let i=0;i<args.length;i++){
    if(args[i].startsWith('--target=')){target=args[i].slice(9).toLowerCase();}
    else if(args[i]==='--target'&&args[i+1]){target=args[i+1].toLowerCase();i++;}
    else if(args[i].startsWith('--backend=')){backend=args[i].slice(10).toLowerCase();}
    else if(args[i]==='--backend'&&args[i+1]){backend=args[i+1].toLowerCase();i++;}
    else if(args[i].startsWith('--input=')){inputFile=args[i].slice(8);}
    else if(args[i]==='--input'&&args[i+1]){inputFile=args[i+1];i++;}
    else if(args[i].startsWith('--output=')){outputFile=args[i].slice(9);}
    else if(args[i]==='--output'&&args[i+1]){outputFile=args[i+1];i++;}
    else rest.push(args[i]);
  }
  // Resolve input: --input wins, else first positional
  const inFile=inputFile||rest[0];
  if(!inFile){
    process.stderr.write('usage: yoyo.js [--input=FNAME] [--output=FNAME] [--target=win|linux] [--backend=x64] <input.ty>\n');
    process.exit(2);
  }
  const ky=fs.readFileSync(inFile,'utf8');
  const exe=compile(ky,{target,backend});
  // Resolve output: --output wins, else second positional, else derived from input
  const out=outputFile||rest[1]||inFile.replace(/\.(ty|ky)$/,'')+(target==='linux'?'':'.exe');
  fs.mkdirSync(path.dirname(out),{recursive:true});
  fs.writeFileSync(out,exe);
  fs.chmodSync(out,0o755);
  console.log(`Compiled [${target}/${backend}] to ${out} (${exe.length} bytes)`);
})();}
