/** Pure RGB8/index8 comparator. Decode to explicit RGB bytes outside this module. */
export const OURS = Object.freeze([[0,0,0],[255,255,255],[129,51,56],[117,206,200],[142,60,151],[86,172,77],[46,44,155],[237,241,113],[142,80,41],[85,56,0],[196,108,113],[74,74,74],[123,123,123],[169,255,159],[112,109,235],[178,178,178]].map(Object.freeze));
export const PEPTO = Object.freeze([[0,0,0],[255,255,255],[104,55,43],[112,164,178],[111,61,134],[88,141,67],[53,40,121],[184,199,111],[111,79,37],[67,57,0],[154,103,89],[68,68,68],[108,108,108],[154,210,132],[108,94,181],[149,149,149]].map(Object.freeze));
const integer = n => Number.isSafeInteger(n) && n >= 0;
function image(im, channels, indexed=false) {
  if (!im || !integer(im.width) || !integer(im.height) || !im.width || !im.height ||
      !Number.isSafeInteger(im.width*im.height*channels) ||
      !(im.data instanceof Uint8Array || im.data instanceof Uint8ClampedArray) ||
      im.data.length !== im.width*im.height*channels) throw new RangeError('invalid typed image geometry/data');
  if (indexed && im.data.some(v => v > 15)) throw new RangeError('index outside palette');
}
export function nearestRGB(rgb, palette) {
  if ((!Array.isArray(rgb) && !(rgb instanceof Uint8Array)) || rgb.length !== 3 ||
      [...rgb].some(v => !integer(v) || v > 255) || (palette !== OURS && palette !== PEPTO)) throw new TypeError('RGB8 and named palette required');
  let best=0, distance=Infinity;
  for (let i=0;i<16;i++) {
    let d=0; for(let c=0;c<3;c++) d+=(rgb[c]-palette[i][c])**2;
    if(d<distance) { distance=d; best=i; } // First index wins equal-distance ties, like Python min.
  }
  return best;
}
export function quantizeRGB(im, palette) {
  image(im,3); if(palette!==OURS && palette!==PEPTO) throw new TypeError('named palette required');
  const data=new Uint8Array(im.width*im.height), cache=new Map();
  for(let i=0;i<data.length;i++) {
    const p=i*3, key=(im.data[p]<<16)|(im.data[p+1]<<8)|im.data[p+2];
    let v=cache.get(key); if(v===undefined) { v=nearestRGB([im.data[p],im.data[p+1],im.data[p+2]],palette); cache.set(key,v); }
    data[i]=v;
  }
  return {width:im.width,height:im.height,data};
}
function geometry(ref,ours,{ox,oy,rx=32,ry=35}={}) {
  image(ref,1,true); image(ours,1,true);
  if(![ox,oy,rx,ry].every(integer)) throw new RangeError('nonnegative integer crop origins required');
  const x1=Math.max(rx-ox,0), x2=Math.max(ox-rx,0), y1=Math.max(ry-oy,0), y2=Math.max(oy-ry,0);
  const width=Math.min(ref.width-x1,ours.width-x2), height=Math.min(ref.height-y1,ours.height-y2);
  if(width<=0 || height<=0) throw new RangeError('empty crop is unsupported');
  return {x1,x2,y1,y2,width,height,rx,ry,ox,oy};
}
const at=(im,x,y)=>im.data[y*im.width+x];
export function compareIndexed(ref,ours,alignment) {
  const g=geometry(ref,ours,alignment), cells=new Map(); let bad=0, real=0;
  for(let y=0;y<g.height;y++) for(let x=0;x<g.width;x++) {
    const X=x+g.x1,Y=y+g.y1;
    if(at(ref,X,Y)===at(ours,x+g.x2,y+g.y2)) continue;
    bad++;
    const key=Y-g.ry>=0 && Y-g.ry<200 && X-g.rx>=0 && X-g.rx<320 ? `${Math.floor((Y-g.ry)/8)},${Math.floor((X-g.rx)/8)}` : null;
    cells.set(key,(cells.get(key)||0)+1);
  }
  for(const key of cells.keys()) {
    if(key===null) { real++; continue; }
    const [cy,cx]=key.split(',').map(Number), ca=new Set(),cb=new Set();
    const X=g.rx+cx*8,Y=g.ry+cy*8,BX=X-g.x1+g.x2,BY=Y-g.y1+g.y2;
    if(X<0 || Y<0 || X+8>ref.width || Y+8>ref.height || BX<0 || BY<0 || BX+8>ours.width || BY+8>ours.height) throw new RangeError('incomplete mismatched 8x8 cell unsupported');
    for(let yy=0;yy<8;yy++) for(let xx=0;xx<8;xx++) { ca.add(at(ref,X+xx,Y+yy)); cb.add(at(ours,BX+xx,BY+yy)); }
    if(ca.size>2 || ca.size!==cb.size || [...ca].some(v=>!cb.has(v))) real++;
  }
  return {bad,total:g.width*g.height,real,cells:[...cells].map(([key,count])=>({cell:key===null?null:key.split(',').map(Number),count})),geometry:g};
}
function compareGlyphProbes(ref,ours,ones,zeros,bits,alignment,probeCount) {
  const g=geometry(ref,ours,alignment);
  if(!Array.isArray(bits)||bits.length!==probeCount) throw new RangeError(`exactly ${probeCount} identity variants required`);
  const variants=[ones,zeros,...bits];
  for(const v of variants) { image(v,1,true); if(v.width!==ours.width||v.height!==ours.height) throw new RangeError('variant geometry differs from ours'); }
  let bad=0,glyph=0; const seen=new Map();
  for(let y=0;y<g.height;y++) for(let x=0;x<g.width;x++) {
    const X=x+g.x2,Y=y+g.y2,r=at(ref,x+g.x1,y+g.y1), sig=variants.map(v=>at(v,X,Y));
    if(sig.every(v=>v===sig[0])) { if(r!==at(ours,X,Y)) bad++; continue; }
    glyph++;
    if(!sig.includes(r)) { bad++; continue; } // Rejected colours do not enter seen.
    const key=sig.join(','); if(!seen.has(key)) seen.set(key,r);
    if(seen.get(key)!==r) bad++;
  }
  return {bad,total:g.width*g.height,glyph,identitiesSeen:seen.size,geometry:g};
}
export const compareGlyphIndexed=(ref,ours,ones,zeros,bits,alignment)=>compareGlyphProbes(ref,ours,ones,zeros,bits,alignment,15);
export const compareBalanced28Indexed=(ref,ours,ones,zeros,bits,alignment)=>compareGlyphProbes(ref,ours,ones,zeros,bits,alignment,28);
export const compareRGB=(ref,ours,alignment)=>compareIndexed(quantizeRGB(ref,PEPTO),quantizeRGB(ours,OURS),alignment);
export const compareGlyphRGB=(ref,ours,ones,zeros,bits,alignment)=>compareGlyphIndexed(quantizeRGB(ref,PEPTO),quantizeRGB(ours,OURS),quantizeRGB(ones,OURS),quantizeRGB(zeros,OURS),bits.map(v=>quantizeRGB(v,OURS)),alignment);
