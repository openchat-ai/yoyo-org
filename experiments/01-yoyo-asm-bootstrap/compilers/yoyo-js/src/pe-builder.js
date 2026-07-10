const SA=0x1000,FA=0x400,IB=0x140000000n;
const _=v=>((v+FA-1)/FA|0)*FA;
const _s=v=>((v+SA-1)/SA|0)*SA;

class PE{
  constructor(){this.code=null;this.data=null;this.imports=[];this.ptrMap={};this.dataRVA=0;this.subsys=3;}
  setCode(b){this.code=b;}
  setData(b){this.data=b;}
  addImport(dll,funcs){
    this.imports.push({dll,funcs});
    for(const fn of funcs){
      const key=dll+'.'+fn;
      if(this.ptrMap[key]===undefined)this.ptrMap[key]=0x2000+Object.keys(this.ptrMap).length*8;
    }
  }
  build(){
    const cs=this.code?this.code.length:0,ds=this.data?this.data.length:0;
    const cR=0x1000,textRS=_(cs),textVS=_s(cs);
    const dR=cR+textVS; // .rdata VA = end of .text
    const rdataRO=0x400+textRS;
    const funcList=[],kf=[],nkf=[];
    for(const imp of this.imports)for(const f of imp.funcs)(imp.dll==='KERNEL32.dll'?kf:nkf).push({dll:imp.dll,fn:f});
    const all=kf.concat(nkf);const nf=all.length,nk=kf.length;
    let sl=[];const dllFirst={};
    for(let fi=0;fi<nk;fi++)sl.push({t:'f',fi});sl.push({t:'t'});
    let pD=null;
    for(let fi=nk;fi<nf;fi++){const d=all[fi].dll;if(pD&&d!==pD)sl.push({t:'t'});if(dllFirst[d]===undefined)dllFirst[d]=sl.length;sl.push({t:'f',fi});pD=d;}
    sl.push({t:'t'});dllFirst['KERNEL32.dll']=0;
    const iatSz=sl.length*8;const fiSlot={};
    for(let si=0;si<sl.length;si++)if(sl[si].t==='f')fiSlot[sl[si].fi]=si;
    let hnOff=0;for(let fi=0;fi<nf;fi++)hnOff+=2+all[fi].fn.length+1;
    const hnBuf=Buffer.alloc(hnOff,0);hnOff=0;
    for(let fi=0;fi<nf;fi++){const fn=all[fi].fn;hnBuf.writeUInt16LE(0,hnOff);hnOff+=2;for(let j=0;j<fn.length;j++)hnBuf[hnOff++]=fn.charCodeAt(j);hnBuf[hnOff++]=0;}
    const iat=Buffer.alloc(iatSz,0);
    for(let fi=0;fi<nf;fi++){let off=0;for(let j=0;j<fi;j++)off+=2+all[j].fn.length+1;iat.writeUInt32LE(dR+iatSz+off,fiSlot[fi]*8);}
    for(const imp of this.imports)for(const f of imp.funcs){const fi=all.findIndex(x=>x.dll===imp.dll&&x.fn===f);if(fi>=0)this.ptrMap[imp.dll+'.'+f]=dR+fiSlot[fi]*8;}
    const dllNames=[];for(const imp of this.imports)if(dllNames.indexOf(imp.dll)<0)dllNames.push(imp.dll);
    const dllStrBuf=Buffer.alloc(8192,0);const dllStrMap={};let dllOff=0;
    for(const dn of dllNames){dllStrMap[dn]=dllOff;Buffer.from(dn+'\0','ascii').copy(dllStrBuf,dllOff);dllOff+=dn.length+1;}
    const iidBuf=Buffer.alloc((dllNames.length+1)*20,0);
    for(let dni=0;dni<dllNames.length;dni++){const dn=dllNames[dni];const nameRVA=dR+iatSz+hnBuf.length+dllStrMap[dn];const slotOff=dllFirst[dn]*8;const ftRVA=dR+slotOff;iidBuf.writeUInt32LE(nameRVA,dni*20+12);iidBuf.writeUInt32LE(ftRVA,dni*20);iidBuf.writeUInt32LE(ftRVA,dni*20+16);}
    const dataOff=_(iatSz+hnBuf.length+dllOff+iidBuf.length);
    const rdataRS=_(dataOff+ds),rdataVS=_s(dataOff+ds);
    const imgSize=_s(dR+rdataVS);
    const rawEnd=rdataRO+rdataRS;const pe=Buffer.alloc(rawEnd+0x1000,0);
    pe[0]=0x4D;pe[1]=0x5A;pe.writeUInt32LE(0xF0,0x3C);
    pe[0xF0]=0x50;pe[0xF1]=0x45;pe[0xF2]=0;pe[0xF3]=0;
    pe.writeUInt16LE(0x8664,0xF4);pe.writeUInt16LE(2,0xF6);
    pe.writeUInt16LE(0xF0,0x104);pe.writeUInt16LE(0x23,0x106);
    const oh=0x108;
    pe.writeUInt16LE(0x20B,oh);pe.writeUInt8(14,oh+2);
    pe.writeUInt32LE(cs,oh+4);pe.writeUInt32LE(ds,oh+8);
    pe.writeUInt32LE(cR,oh+16);pe.writeUInt32LE(cR,oh+20);
    pe.writeBigInt64LE(IB,oh+24);
    pe.writeUInt32LE(SA,oh+32);pe.writeUInt32LE(FA,oh+36);
    pe.writeUInt16LE(6,oh+40);pe.writeUInt16LE(0,oh+42);
    pe.writeUInt16LE(0,oh+44);pe.writeUInt16LE(0,oh+46);
    pe.writeUInt16LE(6,oh+48);pe.writeUInt16LE(0,oh+50);
    pe.writeUInt32LE(imgSize,oh+56);pe.writeUInt32LE(0x400,oh+60);
    pe.writeUInt16LE(this.subsys,oh+0x44);pe.writeUInt16LE(0x40,oh+0x46);
    pe.writeBigInt64LE(0x100000n,oh+0x48);pe.writeBigInt64LE(0x1000n,oh+0x50);
    pe.writeBigInt64LE(0x100000n,oh+0x58);pe.writeBigInt64LE(0x1000n,oh+0x60);
    pe.writeUInt32LE(16,oh+0x6C);
    for(let i=0;i<16;i++){pe.writeUInt32LE(0,oh+0x70+i*8);pe.writeUInt32LE(0,oh+0x74+i*8);}
    pe.writeUInt32LE(dR+iatSz+hnBuf.length+dllOff,oh+0x78);pe.writeUInt32LE(iidBuf.length,oh+0x7C);
    pe.writeUInt32LE(dR,oh+0x70+12*8);pe.writeUInt32LE(iatSz,oh+0x74+12*8);
    const sh=0x1F8;
    '.text\0\0\0'.split('').forEach((c,i)=>pe[sh+i]=c.charCodeAt(0));
    pe.writeUInt32LE(textVS,sh+8);pe.writeUInt32LE(cR,sh+12);
    pe.writeUInt32LE(textRS,sh+16);pe.writeUInt32LE(0x400,sh+20);
    pe.writeUInt32LE(0x60000020,sh+36);
    const sh2=sh+40;
    '.rdata\0\0'.split('').forEach((c,i)=>pe[sh2+i]=c.charCodeAt(0));
    pe.writeUInt32LE(rdataVS,sh2+8);pe.writeUInt32LE(dR,sh2+12);
    pe.writeUInt32LE(rdataRS,sh2+16);pe.writeUInt32LE(rdataRO,sh2+20);
    pe.writeUInt32LE(0xC0000040,sh2+36);
    if(this.code)this.code.copy(pe,0x400);
    iat.copy(pe,rdataRO);hnBuf.copy(pe,rdataRO+iatSz);dllStrBuf.slice(0,dllOff).copy(pe,rdataRO+iatSz+hnBuf.length);
    iidBuf.copy(pe,rdataRO+iatSz+hnBuf.length+dllOff);
    if(this.data)this.data.copy(pe,rdataRO+dataOff);
    this.dataRVA=dR+dataOff;
    return pe.slice(0,rawEnd);
  }
}
module.exports={PE};
