"""Build the analyst dashboard (one self-contained HTML file) and a PNG screenshot of it.

  python build_dashboard.py --cases out/cases.json --triage out/triage.json --out out/dashboard.html --png out/dashboard.png

The HTML works offline: click a case in the queue, switch hosts in the SHAP panel, press
TP / FP, then "Export labels" downloads labels.csv for train_feedback.py.
"""
import argparse
import datetime as dt
import json

HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSM Hunt Console</title>
<style>
:root{--bg:#0b0f17;--panel:#121826;--panel2:#182032;--line:#243049;--txt:#e6ebf5;--mut:#8b97b0;--acc:#5aa9ff;
--crit:#ff4d6d;--high:#ff9f43;--med:#ffd166;--low:#4cc9a6;--c2:#c77dff;--lm:#5aa9ff;--cred:#ff7b54;--disc:#7bdff2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:13px/1.45 "Segoe UI",Inter,DejaVu Sans,Arial,sans-serif}
header{display:flex;align-items:center;gap:18px;padding:12px 20px;border-bottom:1px solid var(--line);background:#0e1420}
.logo{font-weight:700;font-size:16px;letter-spacing:.3px}.logo span{color:var(--acc)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border:1px solid var(--line);border-radius:999px;color:var(--mut);font-size:11.5px;white-space:nowrap}
.chip b{color:var(--txt);font-weight:600}.dot{width:7px;height:7px;border-radius:50%;background:var(--low)}
.kpis{display:flex;gap:10px;padding:12px 20px}
.kpi{flex:1;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.kpi .v{font-size:22px;font-weight:700}.kpi .l{color:var(--mut);font-size:11.5px}
main{display:grid;grid-template-columns:330px 1fr 430px;gap:12px;padding:0 20px 20px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);font-weight:600}
.tabs{display:flex;gap:6px;margin-bottom:10px}.tab{padding:4px 10px;border-radius:6px;background:var(--panel2);color:var(--mut);cursor:pointer;font-size:12px}
.tab.on{background:var(--acc);color:#04101f;font-weight:600}
.case{display:flex;gap:10px;padding:10px;border:1px solid var(--line);border-radius:9px;margin-bottom:8px;cursor:pointer;background:var(--panel2);position:relative}
.case.on{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc) inset}
.score{flex:0 0 46px;height:46px;border-radius:50%;display:grid;place-items:center;font-weight:800;font-size:15px;border:3px solid}
.case .t{font-weight:600;font-size:12.5px}.case .m{color:var(--mut);font-size:11.5px;margin-top:3px}
.tags{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}.tag{font-size:10.5px;padding:1px 7px;border-radius:5px;background:#0d1320;border:1px solid var(--line)}
.lab{position:absolute;top:8px;right:8px;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px}
.sev-critical{color:var(--crit);border-color:var(--crit)}.sev-high{color:var(--high);border-color:var(--high)}.sev-medium{color:var(--med);border-color:var(--med)}.sev-low{color:var(--low);border-color:var(--low)}
.center{display:flex;flex-direction:column;gap:12px;min-width:0}
.ch{display:flex;align-items:center;gap:12px}.ch .id{color:var(--mut);font-weight:600}.ch .title{font-size:17px;font-weight:700}
.chain{display:flex;gap:6px;align-items:center;margin-top:8px;flex-wrap:wrap}.arrow{color:var(--mut)}
.row2{display:grid;grid-template-columns:1.25fr 1fr;gap:12px}
svg text{fill:var(--txt);font-size:11px}
.bar{display:grid;grid-template-columns:200px 1fr 46px;align-items:center;gap:8px;margin:7px 0}
.bar .n{font-size:12px}.bar .n small{display:block;color:var(--mut);font-size:10.5px}
.track{height:14px;background:#0d1320;border-radius:4px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#ff7b54,#ff4d6d);border-radius:4px}
.bar .val{color:var(--mut);font-size:11px;text-align:right}
table{width:100%;border-collapse:collapse;font-size:12px}th{color:var(--mut);text-align:left;font-weight:600;padding:6px;border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td{padding:6px;border-bottom:1px solid #1c2538;vertical-align:top}td.mono,.mono{font-family:"DejaVu Sans Mono",Consolas,monospace;font-size:11px;color:#9fb3d9}
.hid{white-space:nowrap;font-weight:700;font-size:11px;padding:1px 6px;border-radius:4px}
.tri .badge{display:inline-block;padding:3px 10px;border-radius:6px;font-weight:700;font-size:12px}
.tri .hl{font-size:15px;font-weight:700;margin:10px 0 6px}.tri p{margin:6px 0;color:#cdd6e8}
.tri ol,.tri ul{margin:4px 0 8px;padding-left:18px}.tri li{margin:3px 0}
.sec{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.7px;margin-top:12px;font-weight:600}
.cite{color:var(--acc);font-family:"DejaVu Sans Mono",monospace;font-size:10.5px}
.foot{margin-top:10px;padding-top:8px;border-top:1px solid var(--line);color:var(--mut);font-size:11px}
.dec{display:flex;gap:8px;margin-top:10px}.btn{flex:1;padding:9px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);font-weight:700;cursor:pointer;font-size:13px}
.btn.tp{border-color:var(--crit);color:var(--crit)}.btn.fp{border-color:var(--low);color:var(--low)}.btn.on.tp{background:var(--crit);color:#fff}.btn.on.fp{background:var(--low);color:#04101f}
select,textarea{width:100%;margin-top:8px;background:#0d1320;color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:7px;font:inherit}
.small{font-size:11px;color:var(--mut)}
.answer{white-space:pre-wrap;margin-top:10px;font-size:13px;line-height:1.55;color:#dbe3f3}.answer:empty{display:none}
.jg{display:inline-flex;gap:6px;flex-wrap:wrap;margin-top:8px}.preset{cursor:pointer}
.flowwrap{padding:12px 20px 0}
.flow{display:flex;align-items:stretch;overflow-x:auto;padding-bottom:4px}
.stage{flex:1 1 0;min-width:122px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:9px 11px}
.stage .sn{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.stage .sv{font-size:15px;font-weight:700;margin:3px 0 1px}.stage .sd{font-size:10.5px;color:var(--mut);line-height:1.3}
.stage.ml{border-color:var(--acc)}.stage.ml .sv{color:var(--acc)}
.stage.shap{border-color:var(--cred)}.stage.shap .sv{color:var(--cred)}
.stage.llm{border-color:var(--c2)}.stage.llm .sv{color:var(--c2)}
.flowarrow{display:flex;align-items:center;color:var(--mut);padding:0 5px;font-size:15px;flex:0 0 auto}
.ribbon{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.ribbon .rb{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 11px;font-size:12px;color:var(--mut)}
.ribbon .rb b{color:var(--txt)}.ribbon .rb.good b{color:var(--low)}.ribbon .rb.crit b{color:var(--crit)}
@media (max-width:1100px){main{grid-template-columns:1fr}.row2{grid-template-columns:1fr}.kpis{flex-wrap:wrap}.kpi{min-width:40%}}
</style></head><body>
<header><div class="logo">NSM <span>Hunt Console</span></div>
<span class="chip">Hunt day <b id="day"></b></span>
<span class="chip"><span class="dot"></span>Zeek sensor <b id="src">logs</b></span>
<span class="chip">ML <b id="model"></b> + SHAP</span>
<span class="chip">LLM <b id="llmname">Ollama</b> · self-hosted · open source</span>
<span style="flex:1"></span><span class="chip">Analyst <b>SOC T2</b></span></header>
<section class="flowwrap"><h3 style="margin:0 0 8px">Pipeline · packets become an answer the analyst can read</h3>
 <div class="flow" id="flow"></div><div class="ribbon" id="ribbon"></div></section>
<div class="kpis" id="kpis"></div>
<main>
 <section class="panel"><h3>Hunt queue · ranked</h3>
  <div class="tabs"><span class="tab on" data-f="all">All</span><span class="tab" data-f="Lateral Movement">Lateral movement</span><span class="tab" data-f="Command and Control">C2</span></div>
  <div id="queue"></div>
  <div class="small" style="margin-top:6px" id="supp"></div>
  <h3 style="margin-top:16px">Hunt library · hits today</h3><div id="lib"></div>
 </section>
 <section class="center">
  <div class="panel ask" id="askp"><h3>Ask the network · answers come from the stored ML + SHAP + hunt output</h3>
   <div style="display:flex;gap:8px"><input id="q" placeholder="e.g. What abnormal behaviour happened on the network today?" style="flex:1;background:#0d1320;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:10px;font:inherit">
   <button class="btn" style="flex:0 0 90px;border-color:var(--acc);color:var(--acc)" onclick="askQ()">Ask</button></div>
   <div class="tags" style="margin-top:8px" id="presets"></div>
   <div id="ans" class="answer"></div></div>
  <div class="panel"><div class="ch"><div class="score" id="cscore"></div><div><div class="id" id="cid"></div><div class="title" id="ctitle"></div></div></div>
   <div class="chain" id="chain"></div></div>
  <div class="row2">
   <div class="panel"><h3>Attack path (from hunt findings)</h3><svg id="graph" width="100%" height="360" viewBox="0 0 620 360"></svg></div>
   <div class="panel"><h3>Why the ML flagged it · SHAP</h3><div class="tabs" id="htabs"></div><div id="shap"></div>
     <div class="small" id="mlnote" style="margin-top:6px"></div></div>
  </div>
  <div class="panel"><h3>Hunt findings · timeline (UTC)</h3><table><thead><tr><th>Time</th><th>Hunt</th><th>Source → target</th><th>ATT&CK</th><th>What Zeek saw</th><th>Evidence</th></tr></thead><tbody id="tl"></tbody></table></div>
 </section>
 <section class="panel tri" id="tri"></section>
</main>
<script>
const D=__DATA__, T=__TRIAGE__, LIVE=__LIVE__, QA=__QA__, MET=__METRICS__;
const COL={"Lateral Movement":"var(--lm)","Command and Control":"var(--c2)","Credential Access":"var(--cred)","Discovery":"var(--disc)"};
const SHORT={"Lateral Movement":"Lateral Movement","Command and Control":"C2","Credential Access":"Credential Access","Discovery":"Discovery"};
const labels={}; let cur=0, curHost=0, filt="all";
const $=id=>document.getElementById(id);
const hhmm=ts=>{const h=(ts%86400)/3600;return String(Math.floor(h)).padStart(2,"0")+":"+String(Math.floor(h%1*60)).padStart(2,"0")};
$("day").textContent=D.day; $("model").textContent=D.model; if(D.llm_model)$("llmname").textContent=D.llm_model; if(D.source)$("src").textContent=D.source;
const crit=D.cases.filter(c=>c.severity==="critical").length;
$("kpis").innerHTML=[[D.hosts_scored,"hosts scored today"],[D.findings_total,"hunt hits (12 hunts)"],[D.findings_suppressed,"auto-suppressed (known admin behaviour)"],[D.cases.length,"cases in queue"],[crit,"critical"],[D.touched_total!=null?D.touched_total:"-","hosts the attack reached"]]
 .map(([v,l],i)=>`<div class="kpi"><div class="v" style="${i==4?'color:var(--crit)':''}">${v}</div><div class="l">${l}</div></div>`).join("");
$("supp").textContent=`${D.findings_suppressed} hits hidden: SCCM01 creates remote services on most baseline days (allow-listed by the baseline, not by hand).`;
(function(){const S=[
 ["Zeek sensor","9 log types","packets → JSON logs",""],
 ["Feature extraction","per host","conn/dns/ssl/kerberos/smb…",""],
 ["Isolation Forest",(D.hosts_scored!=null?D.hosts_scored+" hosts":"hosts"),"risk score vs the host's own baseline","ml"],
 ["SHAP","top reasons","why each score is high","shap"],
 ["Store",(D.findings_total!=null?D.findings_total+" findings":"findings"),"SQLite · the LLM reads only this",""],
 ["Analyst asks","question","plain language",""],
 ["LLM answer",(MET.llm_short||"qwen3"),"local Ollama · cites finding ids","llm"],
 ["LLM judge",(MET.verdict||"faithfulness"),"a 2nd model grades the answer","llm"]];
 $("flow").innerHTML=S.map((s,i)=>`<div class="stage ${s[3]}"><div class="sn">${s[0]}</div><div class="sv">${s[1]}</div><div class="sd">${s[2]}</div></div>`+(i<S.length-1?'<div class="flowarrow">→</div>':'')).join("");
 const m=MET.detection||{},rb=[];
 if(m.techniques_detected!=null)rb.push(["good",`<b>${m.techniques_detected}/${m.techniques_total}</b> attack techniques detected`]);
 if(m.compromised_case_rank)rb.push(["crit",`compromised host ranked <b>#${m.compromised_case_rank}</b>`]);
 if(m.host_precision!=null)rb.push(["good",`host precision / recall <b>${Math.round(m.host_precision*100)}% / ${Math.round(m.host_recall*100)}%</b>`]);
 if(m.suppressed_known_admin!=null)rb.push(["",`<b>${m.suppressed_known_admin}</b> known-admin hits auto-suppressed`]);
 rb.push(["",`LLM + judge run <b>locally</b> (docker compose · open-source models)`]);
 $("ribbon").innerHTML=rb.map(r=>`<span class="rb ${r[0]}">${r[1]}</span>`).join("")})();
const HUNTS=__HUNTS__;
function lib(){const n={};D.cases.forEach(c=>c.findings.forEach(f=>n[f.hunt]=(n[f.hunt]||0)+1));
 $("lib").innerHTML=Object.entries(HUNTS).map(([id,h])=>`<div style="display:flex;gap:8px;align-items:center;margin:4px 0;font-size:11.5px">
 <span class="hid" style="background:${COL[h[1]]};color:#04101f;min-width:42px;text-align:center">${id}</span><span style="flex:1;color:${n[id]?'var(--txt)':'var(--mut)'}">${h[0].split(" (")[0]}</span>
 <b style="color:${n[id]?'var(--crit)':'var(--mut)'}">${n[id]||0}</b></div>`).join("")}
lib();
function tacticTags(c){return c.tactics.map(t=>`<span class="tag" style="color:${COL[t]};border-color:${COL[t]}">${SHORT[t]}</span>`).join("")}
function queue(){ $("queue").innerHTML=D.cases.map((c,i)=>({c,i})).filter(({c})=>filt==="all"||c.tactics.includes(filt)).map(({c,i})=>`
 <div class="case ${i==cur?'on':''}" onclick="sel(${i})"><div class="score sev-${c.severity}">${Math.round(c.score)}</div>
 <div style="min-width:0"><div class="t">${c.case_id} · ${c.hosts[0].name}</div><div class="m">${c.title.split(": ").slice(1).join(": ")}</div>
 <div class="tags">${tacticTags(c)}<span class="tag">${c.hosts.length} host${c.hosts.length>1?'s':''}</span>${c.kill_chain?'<span class="tag" style="color:var(--crit);border-color:var(--crit)">kill chain</span>':''}</div></div>
 ${labels[c.case_id]?`<span class="lab" style="background:${labels[c.case_id]=='TP'?'var(--crit)':'var(--low)'};color:#04101f">${labels[c.case_id]}</span>`:''}</div>`).join("") }
document.querySelectorAll(".tab[data-f]").forEach(t=>t.onclick=()=>{document.querySelectorAll(".tab[data-f]").forEach(x=>x.classList.remove("on"));t.classList.add("on");filt=t.dataset.f;queue()});
function graph(c){
 const ext=[...new Set(c.findings.filter(f=>["C2-01","C2-02"].includes(f.hunt)).map(f=>f.dst_name))];
 const E=[]; const pth={};
 c.attack_path.forEach(e=>{ if(e.hunt==="LM-05"){(pth[e.src]=pth[e.src]||[]).push(e.dst)} else E.push(e) });
 Object.entries(pth).forEach(([s,d])=>E.push({src:s,dst:`${d.length} hosts`,hunt:"LM-05",cluster:true}));
 const inc={}; E.forEach(e=>{if(["LM-01","LM-02","LM-03","LM-04"].includes(e.hunt))inc[e.dst]=1});
 const hosts=[...new Set(c.hosts.filter(h=>h.hunt_score>0).map(h=>h.name))];
 const roots=hosts.filter(h=>!inc[h]); const lvl={}; roots.forEach(r=>lvl[r]=1);
 for(let k=0;k<4;k++)E.forEach(e=>{if(lvl[e.src]&&!(e.dst in lvl)&&!ext.includes(e.dst))lvl[e.dst]=lvl[e.src]+1});
 ext.forEach(x=>lvl[x]=0); hosts.forEach(h=>{if(!(h in lvl))lvl[h]=1});
 const cols={}; Object.entries(lvl).forEach(([n,l])=>(cols[l]=cols[l]||[]).push(n));
 const maxL=Math.max(...Object.keys(cols).map(Number)); const pos={};
 Object.entries(cols).forEach(([l,ns])=>ns.forEach((n,i)=>pos[n]={x:50+ (l)*(520/Math.max(1,maxL)), y:(i+1)*360/(ns.length+1), crowd:ns.length>4}));
 const ec=h=>h.startsWith("C2")?"#c77dff":["LM-05","LM-06","LM-07"].includes(h)?"#ff7b54":"#5aa9ff";
 const lines=[...E.map(e=>({...e,c:ec(e.hunt)})), ...ext.map(x=>({src:roots[0]||hosts[0],dst:x,hunt:c.findings.find(f=>f.dst_name===x).hunt,c:"#c77dff"}))];
 let s=`<defs>${["#c77dff","#ff7b54","#5aa9ff"].map((k,i)=>`<marker id="a${i}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L10,5L0,10z" fill="${k}"/></marker>`).join("")}</defs>`;
 const mk={"#c77dff":0,"#ff7b54":1,"#5aa9ff":2};
 lines.forEach(e=>{const a=pos[e.src],b=pos[e.dst]; if(!a||!b)return; const dx=b.x-a.x,dy=b.y-a.y,L=Math.hypot(dx,dy)||1,r=24;
  const x1=a.x+dx/L*r,y1=a.y+dy/L*r,x2=b.x-dx/L*r,y2=b.y-dy/L*r;
  s+=`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${e.c}" stroke-width="2" marker-end="url(#a${mk[e.c]})" opacity=".9"/>`;
  s+=`<text x="${(x1+x2)/2}" y="${(y1+y2)/2-5}" text-anchor="middle" style="font-size:10px;fill:${e.c};font-weight:700">${e.hunt}</text>`});
 Object.entries(pos).forEach(([n,p])=>{const h=c.hosts.find(x=>x.name===n); const isExt=ext.includes(n); const isCl=/hosts$/.test(n);
  const fill=isExt?"#2a1840":h&&h.hunt_score>0?"#3a1420":"#16233a"; const st=isExt?"#c77dff":h&&h.hunt_score>0?"#ff4d6d":"#5aa9ff";
  const label=isExt? n.replace(/^(.{16}).+$/,"$1…"):n;
  s+=`<circle cx="${p.x}" cy="${p.y}" r="22" fill="${fill}" stroke="${st}" stroke-width="2" ${isCl?'stroke-dasharray="4 3"':''}/>`;
  s+=`<text x="${p.x}" y="${p.y+4}" text-anchor="middle" style="font-size:${isExt?9:10.5}px;font-weight:700">${isExt?'C2':isCl?n.split(' ')[0]:n.replace('WS-','WS‑')}</text>`;
  s+=`<text x="${p.x}" y="${p.y+36}" text-anchor="middle" style="fill:#8b97b0;font-size:10px">${isExt?label:isCl?'NTLM targets':(h&&!p.crowd?h.role:'')}</text>`});
 if(!lines.length){s+=`<text x="310" y="180" text-anchor="middle" style="fill:#8b97b0">No lateral movement edges: single-host case</text>`}
 $("graph").innerHTML=s }
function shapPanel(c){
 const hs=c.hosts.filter(h=>h.shap.length).slice(0,4); if(curHost>=hs.length)curHost=0;
 $("htabs").innerHTML=hs.map((h,i)=>`<span class="tab ${i==curHost?'on':''}" onclick="curHost=${i};shapPanel(D.cases[cur])">${h.name} · ${Math.round(h.ml_risk)}</span>`).join("");
 const h=hs[curHost]; if(!h){$("shap").innerHTML='<div class="small">No SHAP reasons</div>';return}
 const mx=Math.max(...h.shap.map(r=>r.contribution));
 $("shap").innerHTML=h.shap.map(r=>`<div class="bar"><div class="n">${r.text}<small>today ${fmt(r.value)} · this host usually ${fmt(r.baseline_median)}</small></div>
  <div class="track"><div class="fill" style="width:${(100*r.contribution/mx).toFixed(0)}%"></div></div><div class="val">+${r.contribution.toFixed(2)}</div></div>`).join("");
 $("mlnote").innerHTML=`ML risk <b>${h.ml_risk.toFixed(0)}/100</b> = how unusual today is <i>for this host</i> vs its own 5-day baseline. Hunt score ${h.hunt_score.toFixed(0)}.`}
const fmt=v=>Math.abs(v)<10&&v%1?v.toFixed(2):Math.round(v).toLocaleString();
function timeline(c){ $("tl").innerHTML=c.findings.map(f=>`<tr><td class="mono">${hhmm(f.first_ts)}</td>
 <td><span class="hid" style="background:${COL[f.tactic]};color:#04101f">${f.hunt}</span></td>
 <td><b>${f.src_name}</b> → ${f.dst_name}</td><td class="mono">${f.attack.split(",")[0]}</td><td>${f.detail}</td><td class="mono">${f.evidence_uids[0]}${f.evidence_uids.length>1?` +${f.evidence_uids.length-1}`:''}</td></tr>`).join("") }
function tri(c){ const t=T[c.case_id]; if(!t){$("tri").innerHTML="";return}
 const col={likely_malicious:"var(--crit)",suspicious:"var(--high)",likely_benign:"var(--low)"}[t.assessment];
 $("tri").innerHTML=`<h3>LLM triage summary</h3>
 <span class="badge" style="background:${col};color:#04101f">${t.assessment.replace("_"," ").toUpperCase()}</span> <span class="chip">confidence <b>${t.confidence}</b></span>
 <div class="hl">${t.headline}</div><p>${t.summary}</p>
 ${t.attack_story.length?`<div class="sec">Attack story</div><ol>${t.attack_story.slice(0,9).map(s=>`<li>${s}</li>`).join("")}${t.attack_story.length>9?`<li class="small">+${t.attack_story.length-9} more in timeline</li>`:''}</ol>`:''}
 <div class="sec">Evidence (cited)</div><ul>${t.evidence.slice(0,4).map(e=>`<li>${e.claim} <span class="cite">[${e.source}]</span></li>`).join("")}</ul>
 ${t.benign_explanations&&t.benign_explanations.length?`<div class="sec">Could it be benign?</div><ul>${t.benign_explanations.map(s=>`<li>${s}</li>`).join("")}</ul>`:''}
 <div class="sec">Recommended next steps</div><ol>${t.next_steps.slice(0,5).map(s=>`<li>${s}</li>`).join("")}</ol>
 <div class="foot">Generated by <b>${t.generated_by.startsWith("offline")?(D.llm_model||"Ollama")+" (configured)":t.generated_by}</b> · self-hosted, no data leaves the network · evidence pulled from the store by Zeek uid${t.generated_by.startsWith("offline")?` · <i>demo text: ${t.generated_by}</i>`:''}</div>
 <div class="sec">Analyst decision</div>
 <div class="dec"><button class="btn tp ${labels[c.case_id]=='TP'?'on':''}" onclick="mark('TP')">✓ True positive</button><button class="btn fp ${labels[c.case_id]=='FP'?'on':''}" onclick="mark('FP')">✕ False positive</button></div>
 <select id="reason"><option>Reason: confirmed malicious (EDR / host evidence)</option><option>Known admin activity (change ticket)</option><option>Benign software / update agent</option><option>Needs more data</option></select>
 <div class="small" style="margin-top:8px">Labels feed <span class="mono">train_feedback.py</span> → XGBoost re-ranks tomorrow's queue. <a href="#" onclick="exportCSV();return false" style="color:var(--acc)">Export labels.csv</a></div>`}
function mark(l){labels[D.cases[cur].case_id]=l;tri(D.cases[cur]);queue();
 if(LIVE){const c=D.cases[cur];fetch("/api/label",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({case_id:c.case_id,host:c.hosts[0].name,label:l,reason:($("reason")||{}).value||""})})}}
const PRESETS=["What abnormal behaviour happened on the network today?","Which hosts should I investigate first, and why did the model flag them?","Is there any sign of credential theft or lateral movement?"];
$("presets").innerHTML=PRESETS.map(p=>`<span class="tag preset" onclick="$('q').value=this.textContent;askQ()">${p}</span>`).join("");
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function showAnswer(r){const j=r.judge||{};const vc=j.verdict==="pass"?"var(--low)":j.verdict==="fail"?"var(--crit)":"var(--mut)";
 $("ans").innerHTML=`<div>${esc(r.answer)}</div><div class="jg"><span class="chip">answered by <b>${esc(r.model||"-")}</b>${r.latency_s?` · ${r.latency_s}s`:""}</span>
 <span class="chip" style="border-color:${vc}">LLM judge <b style="color:${vc}">&nbsp;${esc(j.verdict||"n/a")}</b>${j.faithfulness?` · faithfulness ${j.faithfulness}/5 · relevance ${j.relevance}/5 · completeness ${j.completeness}/5 · actionability ${j.actionability}/5`:""}</span>
 ${j.judge_model?`<span class="chip">judge <b>${esc(j.judge_model)}</b></span>`:""}${(j.unsupported_claims||[]).length?`<span class="chip" style="border-color:var(--crit)">unsupported: ${esc(j.unsupported_claims.join(" | "))}</span>`:""}</div>`}
function askQ(){const q=$("q").value.trim();if(!q)return;if(!LIVE){if(window.QA&&QA[q])showAnswer(QA[q]);else $("ans").textContent="Static page: start the lab (docker compose up) to ask questions.";return}
 $("ans").textContent="Retrieving today's top behaviours from the store and asking the LLM ...";
 fetch("/api/ask",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q})}).then(r=>r.json()).then(showAnswer).catch(e=>$("ans").textContent="error: "+e)}
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")askQ()});
function exportCSV(){const rows=[["case_id","host","label","reason","analyst"]];D.cases.forEach(c=>{if(labels[c.case_id])c.hosts.filter(h=>h.hunt_score>0||c.hosts.length==1).forEach(h=>rows.push([c.case_id,h.name,labels[c.case_id],"dashboard","analyst"]))});
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(r=>r.join(",")).join("\n")],{type:"text/csv"}));a.download="labels.csv";a.click()}
function sel(i){cur=i;curHost=0;const c=D.cases[i];
 $("cscore").className="score sev-"+c.severity;$("cscore").textContent=Math.round(c.score);$("cid").textContent=`${c.case_id} · ${c.severity.toUpperCase()} · ${c.hosts.length} hosts, ${c.touched_hosts.length} touched`;
 $("ctitle").textContent=c.title;
 const order=["Command and Control","Discovery","Credential Access","Lateral Movement"].filter(t=>c.tactics.includes(t));
 $("chain").innerHTML=order.map(t=>`<span class="chip" style="color:${COL[t]};border-color:${COL[t]}"><b style="color:${COL[t]}">${t}</b>&nbsp;${c.findings.filter(f=>f.tactic===t).length} hits</span>`).join('<span class="arrow">→</span>')+(c.kill_chain?'<span class="chip" style="margin-left:8px">C2 + lateral movement on the same hosts: <b>&nbsp;+5 score</b></span>':'');
 queue();graph(c);shapPanel(c);timeline(c);tri(c)}
sel(0);
</script></body></html>"""


def render(d, t, live=False, qa=None, metrics=None):
    """HTML for a scored day. live=True: the page talks to server.py (/api/ask, /api/label).
    metrics: optional {detection, llm_short, verdict} to fill the pipeline banner + results ribbon."""
    from hunts import HUNTS
    d["touched_total"] = len({t["ip"] for c in d.get("cases", []) for t in c.get("touched_hosts", [])})
    if not d.get("day"):
        day = d["cases"][0]["findings"][0]["first_ts"] if d["cases"] and d["cases"][0]["findings"] else 0
        d["day"] = dt.datetime.fromtimestamp(day, dt.timezone.utc).strftime("%Y-%m-%d") if day else ""
    for c in t.values():
        c.pop("zeek_rows", None)
    j = lambda o: json.dumps(o, default=float).replace("</", "<\\/")
    return (HTML.replace("__HUNTS__", j(HUNTS)).replace("__DATA__", j(d)).replace("__TRIAGE__", j(t))
            .replace("__LIVE__", "true" if live else "false").replace("__QA__", j(qa or {}))
            .replace("__METRICS__", j(metrics or {})))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="out/cases.json")
    ap.add_argument("--triage", default="out/triage.json")
    ap.add_argument("--out", default="out/dashboard.html")
    ap.add_argument("--png", default=None)
    ap.add_argument("--qa", default=None, help="results/metrics.json: show its answers in the static page")
    a = ap.parse_args()
    d = json.load(open(a.cases))
    t = json.load(open(a.triage))
    qa, met = {}, {}
    if a.qa:
        mj = json.load(open(a.qa))
        for q in mj["qa"]:
            r = q["llm"] or q["template"]
            qa[q["question"]] = {"answer": r["answer"], "model": r["model"], "judge": r["judge"], "latency_s": r.get("latency_s")}
        v = next((q["llm"]["judge"].get("verdict") for q in mj["qa"] if q.get("llm")), None)
        met = {"detection": mj.get("detection", {}),
               "llm_short": (mj["llm_model"].split(":")[0] if mj.get("llm_available") else "qwen3"),
               "verdict": v or "faithfulness"}
    open(a.out, "w").write(render(d, t, qa=qa, metrics=met))
    print("dashboard ->", a.out)
    if a.png:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1680, "height": 1050}, device_scale_factor=2)
            pg.goto("file://" + __import__("os").path.abspath(a.out))
            pg.wait_for_timeout(400)
            pg.click(".btn.tp")  # show a decided case in the picture
            pg.screenshot(path=a.png, full_page=True)
            b.close()
        print("screenshot ->", a.png)


if __name__ == "__main__":
    main()
