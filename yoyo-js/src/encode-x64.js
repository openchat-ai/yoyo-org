// x64 instruction encodings — each function maps to a .ky handler
const R0=0,R1=1,R2=2,R3=3,R4=4,R5=5,R6=6,R7=7,R8=8,R9=9,R10=10,R11=11,R12=12,R13=13,R14=14,R15=15;

class Buf{
  constructor(){this.b=Buffer.alloc(65536);this.off=0;}
  u8(v){this.b[this.off++]=v;}
  u16(v){this.b.writeUInt16LE(v,this.off);this.off+=2;}
  u32(v){this.b.writeUInt32LE(v>>>0,this.off);this.off+=4;}
  u64(v){this.b.writeBigInt64LE(BigInt(v),this.off);this.off+=8;}
  tell(){return this.off;}
  rex(w,r,x,b){if(w||r||x||b)this.u8(0x40|(w<<3)|(r<<2)|(x<<1)|b);}
  modrm(m,reg,rm){this.u8((m<<6)|((reg&7)<<3)|(rm&7));}
  sib(sc,idx,base){this.u8((sc<<6)|((idx&7)<<3)|(base&7));}
}

// ——— Emit helpers ———
function u8(b,v){b.u8(v);}
function u16(b,v){b.u16(v);}
function u32(b,v){b.u32(v);}
function u64(b,v){b.u64(v);}
function tell(b){return b.tell();}

function rex(b,w,r,x,b2){b.rex(w,r,x,b2);}
function modrm(b,m,reg,rm){b.modrm(m,reg,rm);}
function sib(b,sc,idx,base){b.sib(sc,idx,base);}

// ——— REX prefix helper ———
function emitRex(b,w,reg,base){
  b.rex(w,reg>7,0,base>7);
}

// ——— ModRM helper for [base+disp] addressing ———
function _mrm(b,mod,reg,base){
  if((base&7)===4){b.modrm(mod,reg,4);b.sib(0,4,base&7);}
  else if(mod===0&&base===5){b.modrm(1,reg,5);b.u8(0);}
  else b.modrm(mod,reg,base&7);
}
function _disp(b,base,disp){
  if(disp===0&&base!==5)_mrm(b,0,0,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,0,base);b.u8(disp&255);}
  else{_mrm(b,2,0,base);b.u32(disp);}
}

// ——— Instruction forms ———
function call_rip(b,disp){b.u8(0xFF);b.u8(0x15);b.u32(disp);}
function jmp_rip(b,disp){b.u8(0xFF);b.u8(0x25);b.u32(disp);}
function call_rel(b,off){b.u8(0xE8);b.u32(off);}
function jmp_rel(b,off){b.u8(0xE9);b.u32(off);}
function ret(b){b.u8(0xC3);}

function lea_rip(b,r,disp){
  b.rex(1,r>7,0,0);b.u8(0x8D);b.modrm(0,r&7,5);b.u32(disp);
}
function mov_ri(b,r,val){
  b.rex(1,0,0,r>7);b.u8(0xB8|(r&7));
  if(typeof val==='bigint')b.u64(val);
  else if(val>=-0x80000000&&val<=0xFFFFFFFF)b.u32(val>>>0);
  else b.u64(val);
}
function mov_rr(b,d,s){b.rex(1,s>7,0,d>7);b.u8(0x89);b.modrm(3,s&7,d&7);}
function mov_mr(b,base,disp,reg,is8){
  if(is8)b.u8(0x88);else{b.rex(0,reg>7,0,base>7);b.u8(0x89);}
  if(disp===0&&base!==5)_mrm(b,0,reg&7,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,reg&7,base);b.u8(disp&255);}
  else{_mrm(b,2,reg&7,base);b.u32(disp);}
}
function mov_rm(b,reg,base,disp){
  b.rex(0,reg>7,0,base>7);b.u8(0x8B);
  if(disp===0&&base!==5)_mrm(b,0,reg&7,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,reg&7,base);b.u8(disp&255);}
  else{_mrm(b,2,reg&7,base);b.u32(disp);}
}
function mov_mr64(b,base,disp,reg){
  b.rex(1,reg>7,0,base>7);b.u8(0x89);
  if(disp===0&&base!==5)_mrm(b,0,reg&7,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,reg&7,base);b.u8(disp&255);}
  else{_mrm(b,2,reg&7,base);b.u32(disp);}
}
function mov_rm64(b,reg,base,disp){
  b.rex(1,reg>7,0,base>7);b.u8(0x8B);
  if(disp===0&&base!==5)_mrm(b,0,reg&7,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,reg&7,base);b.u8(disp&255);}
  else{_mrm(b,2,reg&7,base);b.u32(disp);}
}
function mov_mi32(b,base,disp,val){
  b.rex(1,0,0,base>7);b.u8(0xC7);
  if(disp===0&&base!==5)_mrm(b,0,0,base);
  else if(disp>=-128&&disp<=127){_mrm(b,1,0,base);b.u8(disp&255);}
  else{_mrm(b,2,0,base);b.u32(disp);}
  b.u32(val);
}
function xor_rr(b,d,s){b.rex(1,s>7,0,d>7);b.u8(0x31);b.modrm(3,s&7,d&7);}
function cmp_rr(b,a,b2){b.rex(1,b2>7,0,a>7);b.u8(0x39);b.modrm(3,b2&7,a&7);}
function test_rr(b,d,s){b.rex(1,s>7,0,d>7);b.u8(0x85);b.modrm(3,s&7,d&7);}
function add_rr(b,d,s){b.rex(1,s>7,0,d>7);b.u8(0x01);b.modrm(3,s&7,d&7);}
function sub_rr(b,d,s){b.rex(1,s>7,0,d>7);b.u8(0x29);b.modrm(3,s&7,d&7);}
function add_ri(b,r,val){
  if(val>=-128&&val<=127){b.rex(1,0,0,r>7);b.u8(0x83);b.modrm(3,0,r&7);b.u8(val&255);}
  else{b.rex(1,0,0,r>7);b.u8(0x81);b.modrm(3,0,r&7);b.u32(val);}
}
function sub_ri(b,r,val){
  if(val>=-128&&val<=127){b.rex(1,0,0,r>7);b.u8(0x83);b.modrm(3,5,r&7);b.u8(val&255);}
  else{b.rex(1,0,0,r>7);b.u8(0x81);b.modrm(3,5,r&7);b.u32(val);}
}
function and_ri(b,r,val){
  if(val>=-128&&val<=127){b.rex(1,0,0,r>7);b.u8(0x83);b.modrm(3,4,r&7);b.u8(val&255);}
  else{b.rex(1,0,0,r>7);b.u8(0x81);b.modrm(3,4,r&7);b.u32(val);}
}
function cmp_ri(b,r,val){
  if(val>=-128&&val<=127){b.rex(1,0,0,r>7);b.u8(0x83);b.modrm(3,7,r&7);b.u8(val&255);}
  else{b.rex(1,0,0,r>7);b.u8(0x81);b.modrm(3,7,r&7);b.u32(val);}
}
function push_r(b,r){if(r<8)b.u8(0x50|r);else{b.rex(0,0,0,1);b.u8(0x50|(r&7));}}
function pop_r(b,r){if(r<8)b.u8(0x58|r);else{b.rex(0,0,0,1);b.u8(0x58|(r&7));}}

function jcc32(b,cc,off){
  const tbl=[0x84,0x85,0x8C,0x8D,0x8E,0x8F,0x82,0x83,0x86,0x87];
  b.u8(0x0F);b.u8(tbl[cc]||0x84);b.u32(off);
}
function jmp_rel8(b,off){b.u8(0xEB);b.u8(off&255);}

function imul_rr(b,d,s){b.rex(1,d>7,0,s>7);b.u8(0x0F);b.u8(0xAF);b.modrm(3,d&7,s&7);}

// ——— SSE2 scalar double (state slots hold IEEE754 f64 bits) ———
function _xmm_rex(b, xmm, base, idx){
  const rexR = (xmm & 8) ? 1 : 0;
  const rexX = idx !== null && (idx & 8) ? 1 : 0;
  const rexB = (base & 8) ? 1 : 0;
  if (rexR || rexX || rexB) b.rex(0, rexR, rexX, rexB);
}

function movsd_xmm_m64(b, xmm, base, disp, idx, scale){
  // F2 0F 10 /r — movsd xmm, m64
  b.u8(0xF2); b.u8(0x0F); b.u8(0x10);
  const reg = xmm & 7;
  if (idx !== null && idx !== undefined) {
    _xmm_rex(b, xmm, base, idx);
    b.modrm(0, reg, 4);
    b.sib(scale === 8 ? 3 : 0, idx & 7, base & 7);
  } else if (disp === 0 && (base & 7) !== 5) {
    _xmm_rex(b, xmm, base, null);
    b.modrm(0, reg, base & 7);
  } else if (disp >= -128 && disp <= 127) {
    _xmm_rex(b, xmm, base, null);
    b.modrm(1, reg, base & 7);
    b.u8(disp & 255);
  } else {
    _xmm_rex(b, xmm, base, null);
    b.modrm(2, reg, base & 7);
    b.u32(disp >>> 0);
  }
}

function movsd_m64_xmm(b, base, disp, xmm, idx, scale){
  // F2 0F 11 /r — movsd m64, xmm
  b.u8(0xF2); b.u8(0x0F); b.u8(0x11);
  const reg = xmm & 7;
  if (idx !== null && idx !== undefined) {
    _xmm_rex(b, xmm, base, idx);
    b.modrm(0, reg, 4);
    b.sib(scale === 8 ? 3 : 0, idx & 7, base & 7);
  } else if (disp === 0 && (base & 7) !== 5) {
    _xmm_rex(b, xmm, base, null);
    b.modrm(0, reg, base & 7);
  } else if (disp >= -128 && disp <= 127) {
    _xmm_rex(b, xmm, base, null);
    b.modrm(1, reg, base & 7);
    b.u8(disp & 255);
  } else {
    _xmm_rex(b, xmm, base, null);
    b.modrm(2, reg, base & 7);
    b.u32(disp >>> 0);
  }
}

function addsd_xmm_xmm(b, dst, src){
  b.u8(0xF2); b.u8(0x0F); b.u8(0x58);
  if ((dst & 8) || (src & 8)) b.rex(0, (dst & 8) ? 1 : 0, 0, (src & 8) ? 1 : 0);
  b.modrm(3, dst & 7, src & 7);
}
function subsd_xmm_xmm(b, dst, src){
  b.u8(0xF2); b.u8(0x0F); b.u8(0x5C);
  if ((dst & 8) || (src & 8)) b.rex(0, (dst & 8) ? 1 : 0, 0, (src & 8) ? 1 : 0);
  b.modrm(3, dst & 7, src & 7);
}
function mulsd_xmm_xmm(b, dst, src){
  b.u8(0xF2); b.u8(0x0F); b.u8(0x59);
  if ((dst & 8) || (src & 8)) b.rex(0, (dst & 8) ? 1 : 0, 0, (src & 8) ? 1 : 0);
  b.modrm(3, dst & 7, src & 7);
}
function divsd_xmm_xmm(b, dst, src){
  b.u8(0xF2); b.u8(0x0F); b.u8(0x5E);
  if ((dst & 8) || (src & 8)) b.rex(0, (dst & 8) ? 1 : 0, 0, (src & 8) ? 1 : 0);
  b.modrm(3, dst & 7, src & 7);
}

function mov_rm32(b, reg, base, disp){
  b.rex(0, reg > 7, 0, base > 7);
  b.u8(0x8B);
  if (disp === 0 && (base & 7) !== 5) b.modrm(0, reg & 7, base & 7);
  else if (disp >= -128 && disp <= 127) { b.modrm(1, reg & 7, base & 7); b.u8(disp & 255); }
  else { b.modrm(2, reg & 7, base & 7); b.u32(disp >>> 0); }
}
function mov_mr32(b, base, disp, reg){
  b.rex(0, reg > 7, 0, base > 7);
  b.u8(0x89);
  if (disp === 0 && (base & 7) !== 5) b.modrm(0, reg & 7, base & 7);
  else if (disp >= -128 && disp <= 127) { b.modrm(1, reg & 7, base & 7); b.u8(disp & 255); }
  else { b.modrm(2, reg & 7, base & 7); b.u32(disp >>> 0); }
}

module.exports={
  Buf,
  R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,R12,R13,R14,R15,
  u8,u16,u32,u64,tell,rex,modrm,sib,
  call_rip,jmp_rip,call_rel,jmp_rel,ret,
  lea_rip,mov_ri,mov_rr,mov_mr,mov_rm,mov_mr64,mov_rm64,mov_mi32,
  xor_rr,cmp_rr,test_rr,add_rr,sub_rr,
  add_ri,sub_ri,and_ri,cmp_ri,
  push_r,pop_r,jcc32,jmp_rel8,imul_rr,
  movsd_xmm_m64,movsd_m64_xmm,addsd_xmm_xmm,subsd_xmm_xmm,mulsd_xmm_xmm,divsd_xmm_xmm,
  mov_rm32,mov_mr32
};
