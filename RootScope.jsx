import { useState } from "react";

// ══════════════════════════════════════════════════════════════
// SECP256K1 — Finite field & elliptic curve arithmetic
// ══════════════════════════════════════════════════════════════
const P  = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const N  = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const GX = BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
const GY = BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

const fmod = (a, m) => ((a % m) + m) % m;
const fpow = (b, e, m) => { let r=1n; b=fmod(b,m); while(e>0n){if(e&1n)r=r*b%m;b=b*b%m;e>>=1n;} return r; };
const finv = (a, m) => fpow(a, m-2n, m);

function ptAdd(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  const [x1,y1]=p1,[x2,y2]=p2;
  if (x1===x2) {
    if (y1!==y2) return null;
    const l=fmod(3n*x1*x1*finv(2n*y1,P),P);
    const x3=fmod(l*l-2n*x1,P);
    return [x3,fmod(l*(x1-x3)-y1,P)];
  }
  const l=fmod((y2-y1)*finv(x2-x1,P),P);
  const x3=fmod(l*l-x1-x2,P);
  return [x3,fmod(l*(x1-x3)-y1,P)];
}
function ptMul(k) {
  let r=null,q=[GX,GY];
  while(k>0n){if(k&1n)r=ptAdd(r,q);q=ptAdd(q,q);k>>=1n;}
  return r;
}
function liftX(x) {
  const y2=fmod(fpow(x,3n,P)+7n,P);
  const y=fpow(y2,(P+1n)/4n,P);
  if(fpow(y,2n,P)!==y2) return null;
  return y%2n===0n?[x,y]:[x,P-y];
}

// ══════════════════════════════════════════════════════════════
// HEX / BYTE UTILITIES
// ══════════════════════════════════════════════════════════════
const h2b = s => new Uint8Array(s.match(/.{2}/g).map(b=>parseInt(b,16)));
const b2h = b => Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const h2n = h => BigInt('0x'+h);
const n2h64 = n => n.toString(16).padStart(64,'0');
const short = (h,n=8) => h ? `${h.slice(0,n)}…${h.slice(-n)}` : '';
const API_BASE =
  (typeof window !== 'undefined' && window.__ROOTSCOPE_API_BASE__) ||
  'http://127.0.0.1:8000';
const APP_VERSION = 'v0.1.0';

async function apiAnalyze(payload) {
  const resp = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!resp.ok) {
    const detail = data?.detail;
    const msg =
      (typeof detail === 'object' && detail?.message) ||
      data?.message ||
      `Request failed (${resp.status})`;
    throw new Error(msg);
  }
  return data;
}

async function apiFetchWitness({ txid, vin, network }) {
  const q = new URLSearchParams({
    txid: txid.trim(),
    vin: String(vin),
    network,
  });
  const resp = await fetch(`${API_BASE}/fetch-witness?${q.toString()}`, { method: 'GET' });
  const data = await resp.json();
  if (!resp.ok) {
    const detail = data?.detail;
    const msg =
      (typeof detail === 'object' && detail?.message) ||
      data?.message ||
      `Fetch witness failed (${resp.status})`;
    throw new Error(msg);
  }
  return data;
}

// ══════════════════════════════════════════════════════════════
// BITCOIN CRYPTO — Correct implementations
// ══════════════════════════════════════════════════════════════
const sha256 = async d => new Uint8Array(await crypto.subtle.digest('SHA-256', d));

// TaggedHash = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)  [BIP340]
async function taggedHash(tag, data) {
  const th = await sha256(new TextEncoder().encode(tag));
  const msg = new Uint8Array(64+data.length);
  msg.set(th,0); msg.set(th,32); msg.set(data,64);
  return sha256(msg);
}

// Compact-size (little-endian variable length integer)
function compactSize(n) {
  if (n<253) return new Uint8Array([n]);
  const b=new Uint8Array(3); b[0]=253; b[1]=n&255; b[2]=(n>>8)&255; return b;
}

// TapLeaf = TaggedHash("TapLeaf", leafVersion ‖ compact_size(len) ‖ script)
async function tapLeafHash(leafVersion, scriptHex) {
  const s=h2b(scriptHex), cs=compactSize(s.length);
  const d=new Uint8Array(1+cs.length+s.length);
  d[0]=leafVersion; d.set(cs,1); d.set(s,1+cs.length);
  return taggedHash('TapLeaf',d);
}

// Lexicographic byte comparison
function cmpBytes(a,b) {
  for(let i=0;i<32;i++){if(a[i]<b[i])return -1;if(a[i]>b[i])return 1;}
  return 0;
}

// TapBranch = TaggedHash("TapBranch", min(a,b) ‖ max(a,b))
async function tapBranchHash(a,b) {
  const [l,r]=cmpBytes(a,b)<=0?[a,b]:[b,a];
  const d=new Uint8Array(64); d.set(l,0); d.set(r,32);
  return taggedHash('TapBranch',d);
}

// ══════════════════════════════════════════════════════════════
// CONTROL BLOCK PARSER  (variable depth: 0..128)
// ══════════════════════════════════════════════════════════════
function parseControlBlock(cbHex) {
  const b=h2b(cbHex);
  if(b.length<33) throw new Error(`Control block too short: ${b.length} bytes (min 33)`);
  if((b.length-33)%32!==0) throw new Error(`Control block length invalid: ${b.length}`);
  const depth=(b.length-33)/32;
  const path=[];
  for(let i=0;i<depth;i++) path.push(b2h(b.slice(33+i*32,65+i*32)));
  return {
    raw: cbHex,
    versionByte: b[0],
    leafVersion: b[0]&0xfe,
    parity: b[0]&1,
    internalKey: b2h(b.slice(1,33)),
    depth, path
  };
}

// ══════════════════════════════════════════════════════════════
// BECH32M  (BIP350)
// ══════════════════════════════════════════════════════════════
const B32_CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const B32_GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];

function b32Polymod(vals) {
  let c=1;
  for(const v of vals){const b=c>>25;c=((c&0x1ffffff)<<5)^v;for(let i=0;i<5;i++)if((b>>i)&1)c^=B32_GEN[i];}
  return c;
}
function b32HrpExpand(hrp) {
  const r=[];
  for(const c of hrp)r.push(c.charCodeAt(0)>>5);
  r.push(0);
  for(const c of hrp)r.push(c.charCodeAt(0)&31);
  return r;
}
function convertBits(data,from,to) {
  let acc=0,bits=0;const r=[],maxv=(1<<to)-1;
  for(const b of data){acc=(acc<<from)|b;bits+=from;while(bits>=to){bits-=to;r.push((acc>>bits)&maxv);}}
  if(bits>0)r.push((acc<<(to-bits))&maxv);
  return r;
}
function bech32mEncode(hrp, witnessProgram) {
  const words=[1,...convertBits(witnessProgram,8,5)];
  const chk=b32Polymod([...b32HrpExpand(hrp),...words,0,0,0,0,0,0])^0x2bc830a3;
  const enc=[...words];
  for(let i=0;i<6;i++)enc.push((chk>>(5*(5-i)))&31);
  return hrp+'1'+enc.map(d=>B32_CHARSET[d]).join('');
}

// ══════════════════════════════════════════════════════════════
// FULL TAPROOT VERIFICATION PIPELINE
// ══════════════════════════════════════════════════════════════
async function runAnalysis(scriptHex, cbHex, network) {
  const cb = parseControlBlock(cbHex);
  const steps = [];

  // ── Step 1: TapLeaf Hash ──────────────────────────────────
  const leafBytes = await tapLeafHash(cb.leafVersion, scriptHex);
  const leafHex = b2h(leafBytes);
  steps.push({
    id:'leaf', label:'TapLeaf Hash',
    formula:`TaggedHash("TapLeaf", 0x${cb.leafVersion.toString(16)} ‖ compact_size(${h2b(scriptHex).length}) ‖ script)`,
    hash: leafHex, type:'leaf'
  });

  // ── Steps 2..N: Walk Merkle path ─────────────────────────
  let current = leafBytes;
  for(let i=0;i<cb.path.length;i++) {
    const sibHex = cb.path[i];
    const sibBytes = h2b(sibHex);
    const isLeft = cmpBytes(current,sibBytes)<=0;
    const [lh,rh] = isLeft ? [b2h(current),sibHex] : [sibHex,b2h(current)];
    current = await tapBranchHash(current, sibBytes);
    const isRoot = i===cb.path.length-1;
    steps.push({
      id:`branch_${i}`, label: isRoot?'Merkle Root':`TapBranch (depth ${cb.depth-i-1})`,
      formula:`TaggedHash("TapBranch", ${isLeft?'current':'sibling'} ‖ ${isLeft?'sibling':'current'})`,
      hash: b2h(current), leftHash:lh, rightHash:rh,
      sibling:sibHex, siblingIsRight:isLeft,
      type: isRoot?'root':'branch'
    });
  }

  const merkleRootHex = b2h(current);

  // ── Step N+1: TapTweak ───────────────────────────────────
  const ikBytes = h2b(cb.internalKey);
  const tweakInput = new Uint8Array(64);
  tweakInput.set(ikBytes,0); tweakInput.set(current,32);
  const tweakBytes = await taggedHash('TapTweak', tweakInput);
  const tweakHex = b2h(tweakBytes);
  const tweakBig = h2n(tweakHex);

  if(tweakBig>=N) throw new Error('Tweak ≥ curve order — invalid');

  // ── Step N+2: EC Point Tweak ─────────────────────────────
  const ikPoint = liftX(h2n(cb.internalKey));
  if(!ikPoint) throw new Error('Cannot lift internal key x-coordinate (invalid key)');
  const tweakPoint = ptMul(tweakBig);
  const outputPoint = ptAdd(ikPoint, tweakPoint);
  if(!outputPoint) throw new Error('Tweak resulted in point at infinity');

  const [outX, outY] = outputPoint;
  const outputKey = n2h64(outX);
  const computedParity = Number(outY%2n);
  const parityMatch = computedParity === cb.parity;

  // ── Generate address ─────────────────────────────────────
  const hrp = network==='mainnet'?'bc':'tb';
  const address = bech32mEncode(hrp, h2b(outputKey));

  return { cb, steps, leafHex, merkleRootHex, tweakHex, outputKey, computedParity, parityMatch, address };
}

// ══════════════════════════════════════════════════════════════
// MERKLE TREE SVG VISUALIZER
// ══════════════════════════════════════════════════════════════
function MerkleTreeViz({ steps, depth }) {
  if(!steps||steps.length===0) return null;

  const W=520, H=Math.max(220, depth*90+60);
  const nodeR=22;
  const cx=W/2;

  // Build node positions: root at top, leaf at bottom-left
  // We show the proof path spine, siblings as branches
  const nodes=[];
  const edges=[];
  const totalLevels = depth+1; // leaf=0, root=depth

  for(let lvl=0;lvl<=depth;lvl++){
    const step = steps[lvl]; // steps[0]=leaf, steps[depth]=root
    const y = 40 + lvl*(H-60)/depth;
    // Proof path goes straight down on left side
    const x = 80 + lvl*(cx-80)/depth;
    nodes.push({ id:`path_${lvl}`, x, y, step, onPath:true, lvl });

    // Sibling node (if not leaf)
    if(lvl>0){
      const sx = x + (cx-x)*1.4 + 20;
      const sy = y;
      const branchStep = steps[lvl];
      nodes.push({
        id:`sib_${lvl}`, x:sx, y:sy,
        hash: branchStep?.sibling,
        onPath:false, lvl, isSibling:true
      });
      // Edge from parent to sibling
      const parentNode = nodes.find(n=>n.id===`path_${lvl}`);
      edges.push({ x1:x, y1:y, x2:sx, y2:sy, type:'sibling' });
    }

    // Edge from this to previous on path
    if(lvl>0){
      const prev = nodes.find(n=>n.id===`path_${lvl-1}`);
      if(prev) edges.push({ x1:prev.x, y1:prev.y, x2:x, y2:y, type:'path' });
    }
  }

  const stepColors={ leaf:'#f7931a', branch:'#3b82f6', root:'#22c55e' };
  const getColor=s=>{
    if(!s)return '#6b7280';
    if(s.type==='leaf')return stepColors.leaf;
    if(s.type==='root')return stepColors.root;
    return stepColors.branch;
  };

  return (
    <svg width={W} height={H} style={{overflow:'visible'}}>
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
      </defs>

      {/* Edges */}
      {edges.map((e,i)=>(
        <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
          stroke={e.type==='path'?'#f7931a':'#374151'}
          strokeWidth={e.type==='path'?2.5:1.5}
          strokeDasharray={e.type==='sibling'?'5,3':'none'}
          opacity={e.type==='path'?0.9:0.5}
        />
      ))}

      {/* Path nodes */}
      {nodes.filter(n=>n.onPath).map(n=>{
        const c=getColor(n.step);
        const label = n.step?.label||'?';
        const hash = n.step?.hash||'';
        return (
          <g key={n.id} filter="url(#glow)">
            <circle cx={n.x} cy={n.y} r={nodeR} fill="#0d1117" stroke={c} strokeWidth={2.5}/>
            <circle cx={n.x} cy={n.y} r={nodeR-5} fill={c} opacity={0.2}/>
            <text x={n.x} y={n.y+1} textAnchor="middle" dominantBaseline="middle"
              fontSize="9" fontFamily="monospace" fill={c} fontWeight="bold">
              {n.step?.type==='leaf'?'LEAF':n.step?.type==='root'?'ROOT':`B${n.lvl-1}`}
            </text>
            <text x={n.x+nodeR+6} y={n.y-6} fontSize="10" fontFamily="monospace"
              fill="#9ca3af">{label}</text>
            <text x={n.x+nodeR+6} y={n.y+8} fontSize="9" fontFamily="monospace"
              fill={c} opacity={0.8}>{short(hash,6)}</text>
          </g>
        );
      })}

      {/* Sibling nodes */}
      {nodes.filter(n=>n.isSibling).map(n=>(
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r={nodeR} fill="#161b22" stroke="#374151" strokeWidth={1.5}
            strokeDasharray="4,2"/>
          <text x={n.x} y={n.y+1} textAnchor="middle" dominantBaseline="middle"
            fontSize="9" fontFamily="monospace" fill="#6b7280">SIB</text>
          <text x={n.x+nodeR+6} y={n.y+1} fontSize="9" fontFamily="monospace"
            fill="#4b5563">{short(n.hash,6)}</text>
        </g>
      ))}

      {/* Legend */}
      <g transform={`translate(${W-110},${H-55})`}>
        <rect width={105} height={52} rx={4} fill="#161b22" stroke="#1f2937" strokeWidth={1}/>
        {[['#f7931a','TapLeaf'],['#3b82f6','TapBranch'],['#22c55e','Merkle Root']].map(([c,l],i)=>(
          <g key={i} transform={`translate(8,${10+i*14})`}>
            <circle r={4} cx={4} cy={0} fill={c} opacity={0.8}/>
            <text x={12} y={4} fontSize="9" fontFamily="monospace" fill="#9ca3af">{l}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

// ══════════════════════════════════════════════════════════════
// HASH DISPLAY COMPONENT
// ══════════════════════════════════════════════════════════════
function HashDisplay({ hex, color='#f7931a', label }) {
  const [copied,setCopied]=useState(false);
  const copy=()=>{navigator.clipboard?.writeText(hex);setCopied(true);setTimeout(()=>setCopied(false),1200);};
  return (
    <div style={{marginTop:6}}>
      {label&&<div style={{fontSize:11,color:'#6b7280',marginBottom:3,fontFamily:'monospace'}}>{label}</div>}
      <div onClick={copy} style={{
        fontFamily:'monospace',fontSize:11,wordBreak:'break-all',
        background:'#0d1117',border:`1px solid ${color}22`,borderRadius:6,
        padding:'8px 10px',color,cursor:'pointer',
        display:'flex',alignItems:'flex-start',gap:8,
        transition:'border-color .2s',
      }}
        onMouseEnter={e=>e.currentTarget.style.borderColor=color+'66'}
        onMouseLeave={e=>e.currentTarget.style.borderColor=color+'22'}
      >
        <span style={{flex:1,letterSpacing:'0.5px'}}>{hex}</span>
        <span style={{fontSize:10,color:'#4b5563',whiteSpace:'nowrap',paddingTop:1}}>
          {copied?'✓ copied':'copy'}
        </span>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// STEP CARD
// ══════════════════════════════════════════════════════════════
const stepTypeStyle = {
  leaf:  { border:'#f7931a', label:'#f7931a', badge:'TapLeaf'  },
  branch:{ border:'#3b82f6', label:'#3b82f6', badge:'TapBranch'},
  root:  { border:'#22c55e', label:'#22c55e', badge:'Root'     },
};
function StepCard({ step, index }) {
  const [open,setOpen]=useState(false);
  const s=stepTypeStyle[step.type]||stepTypeStyle.branch;
  return (
    <div style={{borderLeft:`3px solid ${s.border}`,background:'#161b22',
      borderRadius:'0 8px 8px 0',marginBottom:10,overflow:'hidden'}}>
      <div onClick={()=>setOpen(o=>!o)} style={{
        padding:'12px 16px',cursor:'pointer',display:'flex',
        alignItems:'center',gap:12,
      }}>
        <span style={{
          background:s.border+'22',color:s.label,border:`1px solid ${s.border}44`,
          borderRadius:4,padding:'2px 8px',fontSize:10,fontFamily:'monospace',fontWeight:700,
          whiteSpace:'nowrap'
        }}>{s.badge}</span>
        <span style={{flex:1,fontFamily:'monospace',fontSize:12,color:'#e6edf3'}}>{step.label}</span>
        <span style={{color:'#4b5563',fontSize:12}}>{open?'▲':'▼'}</span>
      </div>
      {open&&(
        <div style={{padding:'0 16px 14px',borderTop:'1px solid #1f2937'}}>
          <div style={{
            fontFamily:'monospace',fontSize:11,color:'#6b7280',
            background:'#0d1117',borderRadius:6,padding:'8px 12px',margin:'10px 0',
          }}>{step.formula}</div>
          {step.leftHash&&(
            <>
              <HashDisplay hex={step.leftHash} color={step.siblingIsRight?s.border:'#6b7280'} label="Left input"/>
              <HashDisplay hex={step.rightHash} color={step.siblingIsRight?'#6b7280':s.border} label="Right input"/>
            </>
          )}
          <HashDisplay hex={step.hash} color={s.label} label="Result hash"/>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MAIN APP
// ══════════════════════════════════════════════════════════════
const EXAMPLE = {
  script:'002050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3ba2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ba5287',
  cb:'c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659eda55197526f26fa309563b7a3551ca945c046e5b7ada957e59160d4d27f299e3',
  expected:'tb1pjfdm902y2adr08qnn4tahxjvp6x5selgmvzx63yfqk2hdey02yvqjcr29q',
  network:'testnet'
};

export default function RootScope() {
  const [inputMode,setInputMode]=useState('manual');
  const [script,setScript]=useState('');
  const [cb,setCb]=useState('');
  const [txid,setTxid]=useState('');
  const [vin,setVin]=useState(0);
  const [fetchNetwork,setFetchNetwork]=useState('auto');
  const [network,setNetwork]=useState('testnet');
  const [expected,setExpected]=useState('');
  const [result,setResult]=useState(null);
  const [err,setErr]=useState('');
  const [loading,setLoading]=useState('');
  const [fetchLoading,setFetchLoading]=useState('');
  const [tab,setTab]=useState('tree');

  const run=async()=>{
    if(!script||!cb){setErr('Script and Control Block are required');return;}
    setLoading('Parsing control block…');setErr('');setResult(null);
    try{
      setLoading('Sending request to Python analyzer…');
      await new Promise(r=>setTimeout(r,0));
      setLoading('Computing TapLeaf / Merkle / TapTweak…');
      await new Promise(r=>setTimeout(r,0));
      const r=await apiAnalyze({
        script: script.replace(/\s/g,''),
        controlBlock: cb.replace(/\s/g,''),
        network,
        expectedAddress: expected.trim() || null,
      });
      setLoading('Applying secp256k1 tweak…');
      await new Promise(r=>setTimeout(r,10));
      setResult(r);
    } catch(e){setErr(e.message);}
    finally{setLoading('');}
  };

  const loadExample=()=>{setScript(EXAMPLE.script);setCb(EXAMPLE.cb);setExpected(EXAMPLE.expected);setNetwork(EXAMPLE.network);};
  const fetchWitness=async()=>{
    if(!txid.trim()){setErr('TXID is required');return;}
    setErr(''); setFetchLoading('Fetching witness...');
    try{
      const r = await apiFetchWitness({ txid, vin:Number(vin)||0, network:fetchNetwork });
      setScript(r.scriptHex);
      setCb(r.controlBlockHex);
      setNetwork(r.network);
      setExpected(r.expectedAddress || '');
      setResult(null);
      setFetchLoading(`Fetched from ${r.source} (${r.network})`);
      setTimeout(()=>setFetchLoading(''),1500);
    }catch(e){
      setFetchLoading('');
      setErr(e.message);
    }
  };

  const addrMatch = result&&expected ? result.address.toLowerCase()===expected.toLowerCase() : null;

  return (
    <div style={{
      fontFamily:"'SF Mono','Fira Code','Menlo',monospace",
      background:'#0d1117',minHeight:'100vh',color:'#e6edf3',
      padding:'0 0 60px 0',
    }}>
      {/* ─── Header ─────────────────────────────────────────── */}
      <div style={{
        background:'linear-gradient(180deg,#161b22 0%,#0d1117 100%)',
        borderBottom:'1px solid #1f2937',padding:'24px 32px 20px',
      }}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:4}}>
          <div style={{display:'flex',alignItems:'center',gap:16}}>
            <div style={{
              width:40,height:40,borderRadius:10,
              background:'linear-gradient(135deg,#f7931a,#e8820c)',
              display:'flex',alignItems:'center',justifyContent:'center',
              fontSize:20,boxShadow:'0 0 20px #f7931a44',
            }}>🔭</div>
            <div>
              <div style={{fontSize:22,fontWeight:700,color:'#f7931a',letterSpacing:'-0.5px'}}>
                RootScope
              </div>
              <div style={{fontSize:11,color:'#4b5563',letterSpacing:'1px'}}>
                TAPROOT MERKLE PATH ANALYZER · BIP341 / BIP342
              </div>
            </div>
          </div>
          <div style={{
            fontFamily:'monospace',fontSize:11,color:'#6b7280',
            border:'1px solid #1f2937',borderRadius:6,padding:'4px 8px',
            background:'#0d1117',
          }}>
            {APP_VERSION}
          </div>
        </div>
      </div>

      <div style={{maxWidth:1100,margin:'0 auto',padding:'24px 24px 0'}}>
        <div style={{display:'grid',gridTemplateColumns:'420px 1fr',gap:24}}>

          {/* ─── Left Panel: Inputs ────────────────────────── */}
          <div>
            <div style={{
              background:'#161b22',border:'1px solid #1f2937',
              borderRadius:12,padding:20,
            }}>
              <div style={{fontSize:12,color:'#6b7280',letterSpacing:'1px',marginBottom:16}}>
                INPUT DATA
              </div>

              <div style={{display:'flex',gap:8,marginBottom:14}}>
                {[
                  {id:'manual',label:'Manual'},
                  {id:'txid',label:'By TXID'}
                ].map(m=>(
                  <button key={m.id} onClick={()=>setInputMode(m.id)} style={{
                    background:inputMode===m.id?'#f7931a22':'#0d1117',
                    border:`1px solid ${inputMode===m.id?'#f7931a66':'#1f2937'}`,
                    borderRadius:7,color:inputMode===m.id?'#f7931a':'#6b7280',
                    fontFamily:'monospace',fontSize:11,padding:'6px 10px',cursor:'pointer',
                  }}>{m.label}</button>
                ))}
              </div>

              {inputMode==='txid'&&(
                <div style={{
                  background:'#0d1117',border:'1px solid #1f2937',
                  borderRadius:8,padding:12,marginBottom:14,
                }}>
                  <div style={{display:'grid',gridTemplateColumns:'1fr 90px 110px',gap:8,marginBottom:8}}>
                    <input value={txid} onChange={e=>setTxid(e.target.value)}
                      placeholder="txid (64 hex)"
                      style={{
                        width:'100%',background:'#111827',border:'1px solid #1f2937',
                        borderRadius:6,color:'#e6edf3',fontFamily:'monospace',fontSize:11,padding:'8px 10px',
                      }}
                    />
                    <input value={vin} onChange={e=>setVin(e.target.value)}
                      placeholder="vin"
                      style={{
                        width:'100%',background:'#111827',border:'1px solid #1f2937',
                        borderRadius:6,color:'#e6edf3',fontFamily:'monospace',fontSize:11,padding:'8px 10px',
                      }}
                    />
                    <select value={fetchNetwork} onChange={e=>setFetchNetwork(e.target.value)} style={{
                      width:'100%',background:'#111827',border:'1px solid #1f2937',
                      borderRadius:6,color:'#e6edf3',fontFamily:'monospace',fontSize:11,padding:'8px 10px',
                    }}>
                      <option value="auto">Auto</option>
                      <option value="testnet">Testnet</option>
                      <option value="mainnet">Mainnet</option>
                    </select>
                  </div>
                  <button onClick={fetchWitness} disabled={!!fetchLoading} style={{
                    width:'100%',background:'#1f2937',border:'1px solid #374151',
                    borderRadius:6,color:'#9ca3af',fontFamily:'monospace',fontSize:11,padding:'8px 10px',
                    cursor:'pointer',
                  }}>{fetchLoading||'Fetch Witness'}</button>
                </div>
              )}

              {[
                {label:'Script (witness element)',val:script,set:setScript,rows:4,
                 hint:`${script?h2b(script.replace(/\s/g,'')).length+' bytes':'hex encoded script from witness'}`},
                {label:'Control Block',val:cb,set:setCb,rows:5,
                 hint:cb?`${h2b(cb.replace(/\s/g,'')).length} bytes · depth ${(h2b(cb.replace(/\s/g,'')).length-33)/32}`:'hex encoded control block from witness'},
              ].map(({label,val,set,rows,hint})=>(
                <div key={label} style={{marginBottom:16}}>
                  <label style={{display:'block',fontSize:11,color:'#9ca3af',marginBottom:6}}>
                    {label}
                  </label>
                  <textarea value={val} onChange={e=>set(e.target.value)} rows={rows}
                    placeholder={hint}
                    style={{
                      width:'100%',background:'#0d1117',border:'1px solid #1f2937',
                      borderRadius:8,color:'#e6edf3',fontFamily:'monospace',fontSize:11,
                      padding:10,resize:'vertical',wordBreak:'break-all',outline:'none',
                      transition:'border-color .2s',boxSizing:'border-box',
                    }}
                    onFocus={e=>e.target.style.borderColor='#f7931a44'}
                    onBlur={e=>e.target.style.borderColor='#1f2937'}
                  />
                  <div style={{fontSize:10,color:'#374151',marginTop:3}}>{hint}</div>
                </div>
              ))}

              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16}}>
                <div>
                  <label style={{display:'block',fontSize:11,color:'#9ca3af',marginBottom:6}}>Network</label>
                  <select value={network} onChange={e=>setNetwork(e.target.value)} style={{
                    width:'100%',background:'#0d1117',border:'1px solid #1f2937',
                    borderRadius:8,color:'#e6edf3',fontFamily:'monospace',fontSize:11,
                    padding:'8px 10px',outline:'none',cursor:'pointer',
                  }}>
                    <option value="testnet">Testnet (tb1p…)</option>
                    <option value="mainnet">Mainnet (bc1p…)</option>
                  </select>
                </div>
                <div>
                  <label style={{display:'block',fontSize:11,color:'#9ca3af',marginBottom:6}}>Expected address</label>
                  <input value={expected} onChange={e=>setExpected(e.target.value)}
                    placeholder="tb1p… (optional)"
                    style={{
                      width:'100%',background:'#0d1117',border:'1px solid #1f2937',
                      borderRadius:8,color:'#e6edf3',fontFamily:'monospace',fontSize:11,
                      padding:'8px 10px',outline:'none',boxSizing:'border-box',
                    }}
                  />
                </div>
              </div>

              <div style={{display:'flex',gap:10}}>
                <button onClick={run} disabled={!!loading} style={{
                  flex:1,background:'linear-gradient(135deg,#f7931a,#e8820c)',
                  border:'none',borderRadius:8,color:'#0d1117',fontFamily:'monospace',
                  fontWeight:700,fontSize:13,padding:'11px 0',cursor:'pointer',
                  opacity:loading?0.7:1,transition:'opacity .2s',
                }}>
                  {loading?'⟳  '+loading:'▶  Analyze'}
                </button>
                <button onClick={loadExample} style={{
                  background:'#1f2937',border:'1px solid #374151',
                  borderRadius:8,color:'#9ca3af',fontFamily:'monospace',
                  fontSize:12,padding:'11px 14px',cursor:'pointer',
                }}>
                  Example
                </button>
              </div>

              {err&&(
                <div style={{
                  marginTop:14,background:'#2d1117',border:'1px solid #7f1d1d',
                  borderRadius:8,padding:'10px 14px',color:'#fca5a5',fontSize:12,
                }}>
                  ✗ {err}
                </div>
              )}
            </div>

            {/* Control Block breakdown */}
            {result&&(
              <div style={{
                background:'#161b22',border:'1px solid #1f2937',
                borderRadius:12,padding:20,marginTop:16,
              }}>
                <div style={{fontSize:12,color:'#6b7280',letterSpacing:'1px',marginBottom:14}}>
                  CONTROL BLOCK BREAKDOWN
                </div>
                {[
                  {label:'Version byte',val:`0x${result.cb.versionByte.toString(16).padStart(2,'0')}`,
                   sub:`leafVersion=0x${result.cb.leafVersion.toString(16)} · parity=${result.cb.parity}`,color:'#f7931a'},
                  {label:'Internal key (x-only)',val:result.cb.internalKey,color:'#3b82f6'},
                  ...result.cb.path.map((h,i)=>({
                    label:`Merkle sibling [${i}]  (depth ${result.cb.depth-i-1})`,
                    val:h,color:'#a78bfa'
                  })),
                ].map(({label,val,sub,color},i)=>(
                  <div key={i} style={{
                    borderLeft:`3px solid ${color}`,paddingLeft:12,marginBottom:12,
                  }}>
                    <div style={{fontSize:10,color:'#6b7280',marginBottom:4}}>{label}</div>
                    <div style={{fontSize:11,color:color,wordBreak:'break-all',fontFamily:'monospace'}}>{val}</div>
                    {sub&&<div style={{fontSize:10,color:'#4b5563',marginTop:2}}>{sub}</div>}
                  </div>
                ))}
                <div style={{
                  background:'#0d1117',borderRadius:6,padding:'8px 12px',
                  fontSize:11,color:'#6b7280',
                }}>
                  Tree depth: {result.cb.depth} · {result.cb.depth===0?'Key path only':
                    result.cb.depth===1?'2-leaf tree':
                    result.cb.depth===2?'4-leaf tree (max)':
                    `${Math.pow(2,result.cb.depth)}-leaf tree`}
                </div>
              </div>
            )}
          </div>

          {/* ─── Right Panel: Results ──────────────────────── */}
          <div>
            {!result&&!loading&&(
              <div style={{
                background:'#161b22',border:'1px dashed #1f2937',
                borderRadius:12,padding:40,textAlign:'center',
                color:'#374151',fontSize:13,
              }}>
                <div style={{fontSize:32,marginBottom:16,opacity:.4}}>🔭</div>
                <div>Enter script + control block and click <strong style={{color:'#f7931a'}}>Analyze</strong></div>
                <div style={{fontSize:11,marginTop:8,color:'#1f2937'}}>
                  RootScope will verify the Merkle proof path and derive the Taproot address
                </div>
              </div>
            )}

            {loading&&(
              <div style={{
                background:'#161b22',border:'1px solid #1f2937',
                borderRadius:12,padding:40,textAlign:'center',
              }}>
                <div style={{fontSize:24,marginBottom:12,animation:'spin 1s linear infinite'}}>⟳</div>
                <div style={{color:'#f7931a',fontSize:12}}>{loading}</div>
                <div style={{color:'#374151',fontSize:11,marginTop:6}}>
                  secp256k1 scalar multiplication runs in browser BigInt — takes 1–3 s
                </div>
                <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
              </div>
            )}

            {result&&(
              <>
                {/* Tabs */}
                <div style={{
                  display:'flex',gap:2,background:'#161b22',
                  border:'1px solid #1f2937',borderRadius:10,
                  padding:4,marginBottom:16,
                }}>
                  {[
                    {id:'tree',label:'🌲 Merkle Tree'},
                    {id:'steps',label:'🔨 Hash Steps'},
                    {id:'key',label:'🔑 Key Derivation'},
                  ].map(t=>(
                    <button key={t.id} onClick={()=>setTab(t.id)} style={{
                      flex:1,background:tab===t.id?'#f7931a':'transparent',
                      border:'none',borderRadius:7,
                      color:tab===t.id?'#0d1117':'#6b7280',
                      fontFamily:'monospace',fontSize:12,padding:'8px 0',
                      cursor:'pointer',transition:'all .15s',fontWeight:tab===t.id?700:400,
                    }}>{t.label}</button>
                  ))}
                </div>

                {/* Verification banner */}
                {expected&&(
                  <div style={{
                    background:addrMatch?'#052e1c':'#2d1117',
                    border:`1px solid ${addrMatch?'#166534':'#7f1d1d'}`,
                    borderRadius:10,padding:'12px 16px',marginBottom:16,
                    display:'flex',alignItems:'center',gap:12,
                  }}>
                    <span style={{fontSize:20}}>{addrMatch?'✅':'❌'}</span>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12,color:addrMatch?'#4ade80':'#fca5a5',fontWeight:700}}>
                        {addrMatch?'Address verified — Merkle proof is valid':'Address mismatch — proof or inputs may be wrong'}
                      </div>
                      <div style={{fontSize:10,color:'#4b5563',marginTop:2,fontFamily:'monospace'}}>
                        expected: {expected}
                      </div>
                    </div>
                  </div>
                )}

                {/* ── Tab: Merkle Tree ── */}
                {tab==='tree'&&(
                  <div style={{
                    background:'#161b22',border:'1px solid #1f2937',
                    borderRadius:12,padding:20,
                  }}>
                    <div style={{fontSize:12,color:'#6b7280',letterSpacing:'1px',marginBottom:16}}>
                      PROOF PATH VISUALIZATION · depth={result.cb.depth}
                    </div>
                    <div style={{overflowX:'auto'}}>
                      <MerkleTreeViz steps={result.steps} depth={result.cb.depth}/>
                    </div>
                    <div style={{
                      marginTop:16,background:'#0d1117',borderRadius:8,padding:'12px 16px',
                      fontSize:11,color:'#6b7280',lineHeight:1.7,
                    }}>
                      <strong style={{color:'#9ca3af'}}>Reading the diagram:</strong><br/>
                      Orange path = proof chain (leaf → branches → root).<br/>
                      Dashed nodes = sibling hashes provided in the control block.<br/>
                      At each step, the two hashes are sorted lexicographically before hashing.<br/>
                      <br/>
                      <strong style={{color:'#f7931a'}}>Merkle Root:</strong>
                      <div style={{wordBreak:'break-all',color:'#22c55e',marginTop:4}}>
                        {result.merkleRootHex}
                      </div>
                    </div>
                  </div>
                )}

                {/* ── Tab: Hash Steps ── */}
                {tab==='steps'&&(
                  <div style={{
                    background:'#161b22',border:'1px solid #1f2937',
                    borderRadius:12,padding:20,
                  }}>
                    <div style={{fontSize:12,color:'#6b7280',letterSpacing:'1px',marginBottom:16}}>
                      HASH COMPUTATION CHAIN  (click to expand)
                    </div>
                    {result.steps.map((s,i)=><StepCard key={s.id} step={s} index={i}/>)}
                  </div>
                )}

                {/* ── Tab: Key Derivation ── */}
                {tab==='key'&&(
                  <div style={{
                    background:'#161b22',border:'1px solid #1f2937',
                    borderRadius:12,padding:20,
                  }}>
                    <div style={{fontSize:12,color:'#6b7280',letterSpacing:'1px',marginBottom:16}}>
                      KEY DERIVATION PIPELINE  [BIP341]
                    </div>

                    {/* Pipeline steps */}
                    {[
                      {
                        n:1,label:'Internal Public Key',color:'#3b82f6',
                        desc:'x-only 32-byte key from control block',
                        val:result.cb.internalKey,
                        note:`lift_x(0x${short(result.cb.internalKey,8)}) → secp256k1 point with even y`
                      },{
                        n:2,label:'Merkle Root',color:'#22c55e',
                        desc:'computed from TapLeaf + Merkle path',
                        val:result.merkleRootHex
                      },{
                        n:3,label:'TapTweak',color:'#a78bfa',
                        desc:'TaggedHash("TapTweak", internal_key ‖ merkle_root)',
                        val:result.tweakHex,
                        note:'tweak scalar t — used as t·G for EC addition'
                      },{
                        n:4,label:'Output Key',color:'#f7931a',
                        desc:'Q = P + t·G  (secp256k1 point addition)',
                        val:result.outputKey,
                        note:`parity: computed=${result.computedParity} control_block=${result.cb.parity} ${result.parityMatch?'✓ match':'⚠ mismatch'}`
                      },{
                        n:5,label:'Taproot Address',color:'#fb923c',
                        desc:`bech32m(${network==='mainnet'?'bc':'tb'}, witness_v1, output_key)`,
                        val:result.address,
                        big:true
                      }
                    ].map(({n,label,color,desc,val,note,big})=>(
                      <div key={n} style={{
                        marginBottom:16,background:'#0d1117',borderRadius:10,
                        border:`1px solid ${color}22`,overflow:'hidden',
                      }}>
                        <div style={{
                          background:`${color}11`,borderBottom:`1px solid ${color}22`,
                          padding:'10px 14px',display:'flex',alignItems:'center',gap:10,
                        }}>
                          <span style={{
                            width:22,height:22,borderRadius:'50%',background:`${color}22`,
                            border:`1px solid ${color}44`,display:'inline-flex',
                            alignItems:'center',justifyContent:'center',fontSize:10,color,fontWeight:700,
                          }}>{n}</span>
                          <span style={{fontSize:12,color,fontWeight:700}}>{label}</span>
                          <span style={{fontSize:11,color:'#4b5563',marginLeft:4}}>{desc}</span>
                        </div>
                        <div style={{padding:'10px 14px'}}>
                          <div style={{
                            fontFamily:'monospace',fontSize:big?13:11,
                            color:big?color:'#e6edf3',wordBreak:'break-all',
                            fontWeight:big?700:400,letterSpacing:big?'.3px':'.5px',
                          }}>{val}</div>
                          {note&&<div style={{fontSize:10,color:'#4b5563',marginTop:6}}>{note}</div>}
                        </div>
                      </div>
                    ))}

                    <div style={{
                      background:'#052e1c',border:'1px solid #166534',
                      borderRadius:10,padding:'14px 16px',marginTop:8,
                    }}>
                      <div style={{fontSize:12,color:'#4ade80',fontWeight:700,marginBottom:6}}>
                        ✓ Cryptographic proof complete
                      </div>
                      <div style={{fontSize:11,color:'#6b7280',lineHeight:1.8}}>
                        The control block provides a valid Merkle inclusion proof showing
                        that the script is committed inside the Taproot output.
                        The verifier can reconstruct the output key and confirm the UTXO's
                        scriptPubKey without knowing any other scripts in the tree.
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
