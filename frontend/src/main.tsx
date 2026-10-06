import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import './styles.css';

const API=import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
type Row={id:number;original_name:string;size_bytes:number;detected_type:string;detected_mime:string;confidence:number;claimed_extension:string|null;risk_score:number;risk_level:string;sha256:string;entropy:number;};
type Detail=Row & {claimed_mime:string|null;md5:string;sha512:string;findings:{severity:string;code:string;message:string}[];indicators:any};
function App(){
 const [token,setToken]=useState(localStorage.getItem('filesentry_token')||'');
 const [email,setEmail]=useState(''); const [password,setPassword]=useState(''); const [mode,setMode]=useState<'login'|'register'>('login');
 const [rows,setRows]=useState<Row[]>([]); const [selected,setSelected]=useState<Detail|null>(null); const [busy,setBusy]=useState(false); const [message,setMessage]=useState('');
 const auth=async(path:string,body:any)=>{const r=await fetch(API+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok) throw new Error(await r.text());return r.json()};
 useEffect(()=>{
  if(!token)return;
  fetch(API+'/api/v1/analyses',{headers:{Authorization:'Bearer '+token}})
    .then(async r=>{if(!r.ok)throw new Error(`Cases request failed (${r.status}): ${await r.text()}`);return r.json();})
    .then(setRows)
    .catch(e=>setMessage(String(e)));
},[token]);
 const submitAuth=async()=>{try{const x=await auth('/api/v1/auth/'+mode,{email,password});setToken(x.access_token);localStorage.setItem('filesentry_token',x.access_token);setMessage('Authenticated.');}catch(e){setMessage(String(e));}};
 const upload=async(f:File)=>{setBusy(true);setMessage('Analyzing binary safely…');const fd=new FormData();fd.append('upload',f);try{const r=await fetch(API+'/api/v1/analyses',{method:'POST',headers:{Authorization:'Bearer '+token},body:fd});if(!r.ok)throw new Error(await r.text());const x=await r.json();setRows(v=>[x,...v]);setSelected(await loadDetail(x.id));setMessage('Analysis complete.');}catch(e){setMessage(String(e));}finally{setBusy(false)}};
 const loadDetail=async(id:number)=>{
  const r=await fetch(API+'/api/v1/analyses/'+id,{headers:{Authorization:'Bearer '+token}});
  if(!r.ok) throw new Error(`Detail request failed (${r.status}): ${await r.text()}`);
  return r.json();
};
 const downloadReport=async(id:number)=>{const r=await fetch(API+'/api/v1/analyses/'+id+'/report',{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw new Error(await r.text());const blob=await r.blob();const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download=`filesentry-${id}.pdf`;a.click();URL.revokeObjectURL(u)};
 if(!token)return <main className="auth"><div className="card auth-card"><div className="brand">FILESENTRY</div><h1>Binary forensics, without executing the evidence.</h1><p className="muted">Identify file types, expose extension spoofing, inspect entropy, and generate defensible findings.</p><input placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)}/><input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)}/><button onClick={submitAuth}>{mode==='login'?'Sign in':'Create account'}</button><button className="ghost" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Need an account? Register':'Already registered? Sign in'}</button><p className="error">{message}</p></div></main>;
 return <main><header><div><div className="brand">FILESENTRY</div><div className="muted">Binary File Forensics & File-Type Intelligence</div></div><button className="ghost" onClick={()=>{localStorage.removeItem('filesentry_token');setToken('')}}>Sign out</button></header><section className="hero"><h1>Forensic intake</h1><p>Upload a suspicious file and compare what it claims to be with what its bytes say it is.</p><label className="drop">{busy?'ANALYZING…':'DROP FILE / CLICK TO ANALYZE'}<input type="file" onChange={e=>e.target.files?.[0]&&upload(e.target.files[0])}/></label><p className="muted">Max 25 MB in this build. Uploaded samples are treated as untrusted bytes and are never executed.</p></section><section className="grid"><div className="card"><div className="section-title">Recent cases</div>{rows.length===0?<p className="muted">No cases yet.</p>:rows.map(r=><button className={'row '+(selected?.id===r.id?'active':'')} key={r.id} onClick={async()=>setSelected(await loadDetail(r.id))}><span><b>{r.original_name}</b><small>{r.detected_type}</small></span><span className={'pill '+r.risk_level}>{r.risk_level} {r.risk_score}</span></button>)}</div><div className="card">{selected?<><div className="case-head"><div><div className="section-title">Case #{String(selected.id).padStart(6,'0')}</div><h2>{selected.original_name}</h2></div><button className="button" onClick={()=>downloadReport(selected.id)}>PDF report</button></div><div className="metrics"><div><small>Detected</small><b>{selected.detected_type}</b></div><div><small>Confidence</small><b>{selected.confidence}%</b></div><div><small>Entropy</small><b>{selected.entropy.toFixed(3)}</b></div><div><small>Risk</small><b className={selected.risk_level}>{selected.risk_level.toUpperCase()} · {selected.risk_score}</b></div></div><h3>Hashes</h3><code>SHA-256 {selected.sha256}</code><code>MD5 {selected.md5}</code><h3>Findings</h3>{selected.findings.length?selected.findings.map(f=><div className="finding" key={f.code}><b>{f.severity.toUpperCase()}</b><span>{f.message}</span></div>):<p className="muted">No rule-based findings.</p>}</>:<div className="empty"><b>Select a case</b><span>Your forensic evidence and report-ready findings appear here.</span></div>}</div></section><p className="status">{message}</p></main>}
createRoot(document.getElementById('root')!).render(<App/>);
