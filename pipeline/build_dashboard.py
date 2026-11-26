"""Build the analyst dashboard (one self-contained HTML file) and a PNG screenshot of it.

  python build_dashboard.py --cases out/cases.json --triage out/triage.json --out out/dashboard.html --png out/dashboard.png

The HTML works offline: click a case in the priority queue, switch tabs (Overview / Explainability /
Timeline / Attack path), press TP / FP, then "Export labels" downloads labels.csv for train_feedback.py.
When served by server.py (live=True) the Ask-the-network box and the TP/FP buttons call the API.
"""
import argparse
import datetime as dt
import json

HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSM Hunt Console</title>
<style>
:root{
 --bg:#0a0e15;--bg2:#0d1220;--surface:#111826;--surface2:#151d2e;--surface3:#1a2334;
 --line:#222c40;--line2:#2b374f;--txt:#e9eef8;--txt2:#c2ccde;--mut:#8491ab;--mut2:#5e6b85;
 --acc:#4f8cff;--acc2:#6ea0ff;
 --crit:#ff5c78;--high:#ff9d4d;--med:#ffce4d;--low:#33d19e;
 --c2:#b98bff;--lm:#4f8cff;--cred:#ff8a5c;--disc:#44d4e6;
 --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px -12px rgba(0,0,0,.5);
 --r:12px}
*{box-sizing:border-box}
html,body{margin:0}
body{background:radial-gradient(1200px 600px at 80% -10%,#101a2e 0,var(--bg) 60%) fixed,var(--bg);
 color:var(--txt);font:13.5px/1.5 "Inter","Segoe UI",system-ui,DejaVu Sans,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.mono{font-family:"JetBrains Mono","DejaVu Sans Mono",Consolas,monospace}
a{color:var(--acc2);text-decoration:none}
/* top bar */
header{display:flex;align-items:center;gap:14px;padding:13px 24px;border-bottom:1px solid var(--line);
 background:rgba(10,14,21,.75);backdrop-filter:blur(8px);position:sticky;top:0;z-index:20}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px;letter-spacing:.2px}
.brand .mk{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,var(--acc),#8a5bff);
 display:grid;place-items:center;font-size:14px;box-shadow:0 0 16px -4px var(--acc)}
.brand small{color:var(--mut);font-weight:600;font-size:11px;letter-spacing:.6px;text-transform:uppercase;margin-left:2px}
.spring{flex:1}
.chip{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border:1px solid var(--line2);border-radius:999px;color:var(--mut);font-size:11.5px;white-space:nowrap;background:var(--surface)}
.chip b{color:var(--txt2);font-weight:600}
.dot{width:7px;height:7px;border-radius:50%;background:var(--low);box-shadow:0 0 8px var(--low)}
/* pipeline strip */
.flow{display:flex;align-items:center;gap:0;overflow-x:auto;padding:12px 24px;border-bottom:1px solid var(--line);background:var(--bg2)}
.flow::-webkit-scrollbar{height:0}
.stg{flex:1 1 0;min-width:120px;padding:4px 2px}
.stg .sn{font-size:10px;color:var(--mut2);text-transform:uppercase;letter-spacing:.7px;font-weight:600}
.stg .sv{font-size:13.5px;font-weight:700;margin:2px 0 1px;color:var(--txt)}
.stg .sd{font-size:10.5px;color:var(--mut);line-height:1.25}
.stg.on .sv{color:var(--acc2)}.stg.ex .sv{color:var(--cred)}.stg.ai .sv{color:var(--c2)}
.far{color:var(--mut2);padding:0 2px;flex:0 0 auto;font-size:13px}
/* kpis */
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:16px 24px 4px}
.kpi{background:linear-gradient(180deg,var(--surface),var(--bg2));border:1px solid var(--line);border-radius:var(--r);padding:13px 15px;box-shadow:var(--shadow)}
.kpi .v{font-size:25px;font-weight:750;letter-spacing:-.5px;line-height:1.1}
.kpi .l{color:var(--mut);font-size:11.5px;margin-top:3px}
.kpi.crit .v{color:var(--crit)}
.ribbon{display:flex;flex-wrap:wrap;gap:8px;padding:12px 24px 2px}
.rb{display:inline-flex;align-items:center;gap:7px;background:var(--surface);border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:12px;color:var(--mut)}
.rb b{color:var(--txt2)}.rb.good b{color:var(--low)}.rb.crit b{color:var(--crit)}
/* layout */
main{display:grid;grid-template-columns:375px 1fr;gap:16px;padding:16px 24px 28px;align-items:start}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow)}
.pad{padding:16px 18px}
h3{margin:0 0 12px;font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:var(--mut);font-weight:700}
/* queue */
.seg{display:inline-flex;background:var(--bg2);border:1px solid var(--line);border-radius:9px;padding:3px;gap:2px;margin-bottom:12px}
.seg span{padding:5px 11px;border-radius:7px;color:var(--mut);cursor:pointer;font-size:12px;font-weight:600}
.seg span.on{background:var(--surface3);color:var(--txt)}
.case{display:flex;gap:12px;padding:12px;border:1px solid var(--line);border-radius:10px;margin-bottom:9px;cursor:pointer;background:var(--surface2);position:relative;transition:border-color .12s,transform .12s}
.case:hover{border-color:var(--line2)}
.case.on{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc) inset,0 0 22px -12px var(--acc)}
.ring{flex:0 0 44px;height:44px;border-radius:50%;display:grid;place-items:center;font-weight:800;font-size:15px;position:relative}
.ring::before{content:"";position:absolute;inset:0;border-radius:50%;border:3px solid currentColor;opacity:.9}
.case .t{font-weight:650;font-size:12.5px;letter-spacing:.1px}
.case .m{color:var(--mut);font-size:11.5px;margin-top:3px;line-height:1.35}
.tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.tag{font-size:10.5px;padding:2px 8px;border-radius:6px;background:var(--bg2);border:1px solid var(--line2);color:var(--mut)}
.lab{position:absolute;top:10px;right:10px;font-size:10px;font-weight:800;padding:2px 7px;border-radius:5px}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}
.muted{color:var(--mut);font-size:11.5px}
details.lib{margin-top:14px;border-top:1px solid var(--line);padding-top:12px}
details.lib summary{cursor:pointer;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.9px;font-weight:700;list-style:none}
details.lib summary::-webkit-details-marker{display:none}
details.lib summary::before{content:"▸ ";color:var(--mut2)}
details.lib[open] summary::before{content:"▾ "}
.librow{display:flex;gap:9px;align-items:center;margin:6px 0;font-size:11.5px}
.hid{font-weight:700;font-size:10.5px;padding:2px 7px;border-radius:5px;min-width:46px;text-align:center;color:#06101f}
/* right column */
.ask{display:flex;gap:9px;align-items:center}
.ask input{flex:1;background:var(--bg2);color:var(--txt);border:1px solid var(--line2);border-radius:10px;padding:12px 14px;font:inherit}
.ask input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.15)}
.btn{padding:11px 16px;border-radius:10px;border:1px solid var(--line2);background:var(--surface3);color:var(--txt);font-weight:650;cursor:pointer;font-size:13px}
.btn.pri{background:var(--acc);border-color:var(--acc);color:#061024}
.btn.pri:hover{background:var(--acc2)}
.presets{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.presets .tag{cursor:pointer}.presets .tag:hover{border-color:var(--acc);color:var(--txt2)}
.answer{margin-top:12px;font-size:13.5px;line-height:1.6;color:var(--txt2);white-space:pre-wrap}.answer:empty{display:none}
.jg{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
.ch2{display:flex;align-items:center;gap:14px;padding:16px 18px;border-bottom:1px solid var(--line)}
.ch2 .big{font-size:18px;font-weight:750;letter-spacing:-.2px}
.ch2 .id{color:var(--mut);font-size:11.5px;font-weight:600;margin-bottom:3px;letter-spacing:.3px}
.chain{display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid var(--line)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;padding:4px 10px;border-radius:999px;border:1px solid var(--line2)}
.arrow{color:var(--mut2)}
/* tabs */
.tabrow{display:flex;gap:4px;padding:10px 14px 0;border-bottom:1px solid var(--line)}
.tabrow span{padding:9px 14px;border-radius:9px 9px 0 0;color:var(--mut);cursor:pointer;font-size:12.5px;font-weight:650;border:1px solid transparent;border-bottom:none;margin-bottom:-1px}
.tabrow span.on{color:var(--txt);background:var(--surface2);border-color:var(--line)}
.tabc{padding:18px}
/* explainability bars */
.ht{display:inline-flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.ht span{padding:5px 10px;border-radius:8px;background:var(--bg2);border:1px solid var(--line2);color:var(--mut);cursor:pointer;font-size:12px;font-weight:600}
.ht span.on{background:var(--acc);border-color:var(--acc);color:#061024}
.bar{display:grid;grid-template-columns:230px 1fr 54px;align-items:center;gap:12px;margin:11px 0}
.bar .n{font-size:12.5px}.bar .n small{display:block;color:var(--mut);font-size:10.5px;margin-top:2px}
.track{height:12px;background:var(--bg2);border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.fill{height:100%;background:linear-gradient(90deg,#ff8a5c,#ff5c78);border-radius:6px}
.bar .val{color:var(--cred);font-size:11.5px;text-align:right;font-weight:650}
.note{color:var(--mut);font-size:11.5px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line);line-height:1.5}
/* timeline table */
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:var(--mut);text-align:left;font-weight:600;padding:8px 8px;border-bottom:1px solid var(--line);font-size:10.5px;text-transform:uppercase;letter-spacing:.6px}
td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
td.mono{color:#9fb3d9;font-size:11px}
/* triage overview */
.badge{display:inline-flex;padding:4px 11px;border-radius:7px;font-weight:750;font-size:11.5px;letter-spacing:.3px}
.hl{font-size:16px;font-weight:700;margin:14px 0 8px;line-height:1.35}
.tri p{margin:8px 0;color:var(--txt2)}
.sec{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.8px;margin:16px 0 6px;font-weight:700}
.tri ol,.tri ul{margin:4px 0 8px;padding-left:18px}.tri li{margin:4px 0}
.cite{color:var(--acc2);font-size:10.5px}
.foot{margin-top:14px;padding-top:11px;border-top:1px solid var(--line);color:var(--mut);font-size:11px;line-height:1.5}
.dec{display:flex;gap:10px;margin-top:10px}
.bd{flex:1;padding:11px;border-radius:10px;border:1px solid var(--line2);background:var(--surface3);color:var(--txt);font-weight:700;cursor:pointer;font-size:13px}
.bd.tp{border-color:var(--crit);color:var(--crit)}.bd.fp{border-color:var(--low);color:var(--low)}
.bd.on.tp{background:var(--crit);color:#fff}.bd.on.fp{background:var(--low);color:#06101f}
select{width:100%;margin-top:10px;background:var(--bg2);color:var(--txt);border:1px solid var(--line2);border-radius:9px;padding:9px;font:inherit}
svg text{fill:var(--txt)}
@media (max-width:1050px){main{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<header>
 <div class="brand"><span class="mk">◆</span>NSM Hunt Console<small>Network Detection &amp; Response</small></div>
 <span class="spring"></span>
 <span class="chip"><span class="dot"></span>Zeek sensor <b id="src">live</b></span>
 <span class="chip">ML <b id="model">Isolation Forest</b></span>
 <span class="chip">LLM <b id="llmname">Ollama</b> · self-hosted</span>
 <span class="chip">Hunt day <b id="day"></b></span>
</header>
<div class="flow" id="flow"></div>
<div class="kpis" id="kpis"></div>
<div class="ribbon" id="ribbon"></div>
<main>
 <section class="card pad">
  <h3>Priority queue</h3>
  <div class="seg" id="seg"><span class="on" data-f="all">All</span><span data-f="Lateral Movement">Lateral movement</span><span data-f="Command and Control">C2</span></div>
  <div id="queue"></div>
  <div class="muted" id="supp" style="margin-top:8px"></div>
  <details class="lib"><summary>Hunt coverage · hits today</summary><div id="lib" style="margin-top:10px"></div></details>
 </section>
 <section>
  <div class="card pad" style="margin-bottom:16px">
   <h3>Ask the network · answered from the stored ML + explainability + hunt output</h3>
   <div class="ask"><input id="q" placeholder="What abnormal behaviour happened on the network today?">
    <button class="btn pri" onclick="askQ()">Ask</button></div>
   <div class="presets" id="presets"></div>
   <div id="ans" class="answer"></div>
  </div>
  <div class="card">
   <div class="ch2"><div class="ring" id="cring"></div><div><div class="id" id="cid"></div><div class="big" id="ctitle"></div></div></div>
   <div class="chain" id="chain"></div>
   <div class="tabrow" id="tabrow">
     <span data-t="overview" class="on">Overview</span><span data-t="explain">Explainability</span>
     <span data-t="timeline">Timeline</span><span data-t="graph">Attack path</span></div>
   <div class="tabc" id="tabc"></div>
  </div>
 </section>
</main>
<script>
const D=__DATA__, T=__TRIAGE__, LIVE=__LIVE__, QA=__QA__, MET=__METRICS__;
const COL={"Lateral Movement":"var(--lm)","Command and Control":"var(--c2)","Credential Access":"var(--cred)","Discovery":"var(--disc)"};
const SHORT={"Lateral Movement":"Lateral movement","Command and Control":"C2","Credential Access":"Credential access","Discovery":"Discovery"};
const SEVC={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)"};
const labels={}; let cur=0, curHost=0, filt="all", tab="overview";
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const hhmm=ts=>{const h=((ts%86400)+86400)%86400/3600;return String(Math.floor(h)).padStart(2,"0")+":"+String(Math.floor(h%1*60)).padStart(2,"0")};
const fmt=v=>Math.abs(v)<10&&v%1?v.toFixed(2):Math.round(v).toLocaleString();
$("day").textContent=D.day; $("model").textContent=D.model; if(D.llm_model)$("llmname").textContent=String(D.llm_model).split(" (")[0]; if(D.source)$("src").textContent=D.source;

/* pipeline strip */
(function(){const S=[
 ["Zeek sensor","9 log types","packets → JSON","on"],
 ["Features","per host","conn/dns/ssl/kerberos",""],
 ["Isolation Forest",(D.hosts_scored!=null?D.hosts_scored+" hosts":"hosts"),"risk vs own baseline","on"],
 ["Explainability","top reasons","why the score is high","ex"],
 ["Store",(D.findings_total!=null?D.findings_total+" findings":"findings"),"LLM reads only this",""],
 ["Ask","question","plain language",""],
 ["LLM answer",(MET.llm_short||"qwen3"),"local · cites ids","ai"],
 ["LLM judge",(MET.verdict||"faithfulness"),"a 2nd model grades","ai"]];
 $("flow").innerHTML=S.map((s,i)=>`<div class="stg ${s[3]}"><div class="sn">${s[0]}</div><div class="sv">${s[1]}</div><div class="sd">${s[2]}</div></div>`+(i<S.length-1?'<div class="far">→</div>':'')).join("")})();

/* kpis */
const crit=D.cases.filter(c=>c.severity==="critical").length;
$("kpis").innerHTML=[[D.hosts_scored,"hosts scored"],[D.findings_total,"hunt hits (12 hunts)"],
 [D.cases.length,"open cases"],[crit,"critical",1],[D.findings_suppressed,"auto-suppressed"]]
 .map(([v,l,c])=>`<div class="kpi ${c?'crit':''}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join("");
const m=MET.detection||{},rb=[];
if(m.techniques_detected!=null)rb.push(["good",`<b>${m.techniques_detected}/${m.techniques_total}</b>&nbsp;attack techniques detected`]);
if(m.compromised_case_rank)rb.push(["crit",`compromised host ranked&nbsp;<b>#${m.compromised_case_rank}</b>`]);
if(m.host_precision!=null)rb.push(["good",`host precision / recall&nbsp;<b>${Math.round(m.host_precision*100)}% / ${Math.round(m.host_recall*100)}%</b>`]);
rb.push(["",`LLM + judge run&nbsp;<b>locally</b>&nbsp;(open-source)`]);
$("ribbon").innerHTML=rb.map(r=>`<span class="rb ${r[0]}">${r[1]}</span>`).join("");

/* hunt coverage */
const HUNTS=__HUNTS__;
(function(){const n={};D.cases.forEach(c=>c.findings.forEach(f=>n[f.hunt]=(n[f.hunt]||0)+1));
 $("lib").innerHTML=Object.entries(HUNTS).map(([id,h])=>`<div class="librow">
  <span class="hid" style="background:${COL[h[1]]}">${id}</span>
  <span style="flex:1;color:${n[id]?'var(--txt2)':'var(--mut2)'}">${h[0].split(" (")[0]}</span>
  <b style="color:${n[id]?'var(--crit)':'var(--mut2)'}">${n[id]||0}</b></div>`).join("")})();

/* queue */
function tacticTags(c){return c.tactics.map(t=>`<span class="tag" style="color:${COL[t]};border-color:${COL[t]}">${SHORT[t]}</span>`).join("")}
function queue(){$("queue").innerHTML=D.cases.map((c,i)=>({c,i})).filter(({c})=>filt==="all"||c.tactics.includes(filt)).map(({c,i})=>`
 <div class="case ${i==cur?'on':''}" onclick="sel(${i})">
  <div class="ring sev-${c.severity}">${Math.round(c.score)}</div>
  <div style="min-width:0"><div class="t">${c.case_id} · ${c.hosts[0].name}</div>
  <div class="m">${esc(c.title.split(": ").slice(1).join(": "))}</div>
  <div class="tags">${tacticTags(c)}${c.kill_chain?'<span class="tag" style="color:var(--crit);border-color:var(--crit)">kill chain</span>':''}</div></div>
  ${labels[c.case_id]?`<span class="lab" style="background:${labels[c.case_id]=='TP'?'var(--crit)':'var(--low)'};color:#06101f">${labels[c.case_id]}</span>`:''}</div>`).join("")}
$("seg").querySelectorAll("span").forEach(t=>t.onclick=()=>{$("seg").querySelectorAll("span").forEach(x=>x.classList.remove("on"));t.classList.add("on");filt=t.dataset.f;queue()});
$("supp").textContent=`${D.findings_suppressed} hits hidden — the deployment server creates remote services on most baseline days (learned by the baseline, not allow-listed by hand).`;

/* case header + tabs */
function sel(i){cur=i;curHost=0;const c=D.cases[i];
 $("cring").className="ring sev-"+c.severity;$("cring").style.color=SEVC[c.severity];$("cring").textContent=Math.round(c.score);
 $("cid").textContent=`${c.case_id} · ${c.severity.toUpperCase()} · ${c.hosts.length} host${c.hosts.length>1?'s':''}, ${c.touched_hosts.length} touched`;
 $("ctitle").textContent=c.title;
 const order=["Command and Control","Discovery","Credential Access","Lateral Movement"].filter(t=>c.tactics.includes(t));
 $("chain").innerHTML=order.map(t=>`<span class="pill" style="color:${COL[t]};border-color:${COL[t]}"><b>${SHORT[t]}</b> ${c.findings.filter(f=>f.tactic===t).length}</span>`).join('<span class="arrow">→</span>')
  +(c.kill_chain?'<span class="pill" style="margin-left:4px;color:var(--mut)">C2 + lateral movement on the same hosts <b style="color:var(--crit)">+5</b></span>':'');
 queue();renderTab()}
$("tabrow").querySelectorAll("span").forEach(s=>s.onclick=()=>{tab=s.dataset.t;$("tabrow").querySelectorAll("span").forEach(x=>x.classList.toggle("on",x==s));renderTab()});
function renderTab(){const c=D.cases[cur];({overview:tri,explain:explPanel,timeline:timeline,graph:graph}[tab]||tri)(c)}

/* overview = triage */
function tri(c){const t=T[c.case_id];
 if(!t){$("tabc").innerHTML='<div class="muted">No triage summary for this case.</div>';return}
 const col={likely_malicious:"var(--crit)",suspicious:"var(--high)",likely_benign:"var(--low)"}[t.assessment]||"var(--mut)";
 $("tabc").innerHTML=`<div class="tri">
  <span class="badge" style="background:${col};color:#06101f">${t.assessment.replace("_"," ").toUpperCase()}</span>
  <span class="chip" style="margin-left:6px">confidence <b>${t.confidence}</b></span>
  <div class="hl">${esc(t.headline)}</div><p>${esc(t.summary)}</p>
  ${t.attack_story&&t.attack_story.length?`<div class="sec">Attack story</div><ol>${t.attack_story.slice(0,9).map(s=>`<li>${esc(s)}</li>`).join("")}${t.attack_story.length>9?`<li class="muted">+${t.attack_story.length-9} more (see Timeline)</li>`:''}</ol>`:''}
  <div class="sec">Evidence (cited)</div><ul>${t.evidence.slice(0,4).map(e=>`<li>${esc(e.claim)} <span class="cite">[${esc(e.source)}]</span></li>`).join("")}</ul>
  ${t.benign_explanations&&t.benign_explanations.length?`<div class="sec">Could it be benign?</div><ul>${t.benign_explanations.map(s=>`<li>${esc(s)}</li>`).join("")}</ul>`:''}
  <div class="sec">Recommended next steps</div><ol>${t.next_steps.slice(0,5).map(s=>`<li>${esc(s)}</li>`).join("")}</ol>
  <div class="foot">Written by <b>${t.generated_by&&t.generated_by.startsWith("offline")?(D.llm_model||"Ollama")+" (configured)":esc(t.generated_by||"template")}</b> · self-hosted, no data leaves the network · evidence pulled from the store by Zeek uid${t.generated_by&&t.generated_by.startsWith("offline")?` · <i>demo text: no model pulled yet</i>`:''}</div>
  <div class="sec">Analyst decision</div>
  <div class="dec"><button class="bd tp ${labels[c.case_id]=='TP'?'on':''}" onclick="mark('TP')">✓ True positive</button><button class="bd fp ${labels[c.case_id]=='FP'?'on':''}" onclick="mark('FP')">✕ False positive</button></div>
  <select id="reason"><option>Reason: confirmed malicious (EDR / host evidence)</option><option>Known admin activity (change ticket)</option><option>Benign software / update agent</option><option>Needs more data</option></select>
  <div class="muted" style="margin-top:9px">Labels feed <span class="mono">train_feedback.py</span> → XGBoost re-ranks tomorrow's queue. <a href="#" onclick="exportCSV();return false">Export labels.csv</a></div></div>`}
function mark(l){const c=D.cases[cur];labels[c.case_id]=l;renderTab();queue();
 if(LIVE)fetch("/api/label",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({case_id:c.case_id,host:c.hosts[0].name,label:l,reason:($("reason")||{}).value||""})})}

/* explainability */
function explPanel(c){const hs=c.hosts.filter(h=>h.explanations&&h.explanations.length).slice(0,4);if(curHost>=hs.length)curHost=0;
 if(!hs.length){$("tabc").innerHTML='<div class="muted">No model explanation for this case (hunt-only).</div>';return}
 const h=hs[curHost],mx=Math.max(...h.explanations.map(r=>r.contribution))||1;
 $("tabc").innerHTML=`<div class="ht">${hs.map((x,i)=>`<span class="${i==curHost?'on':''}" onclick="curHost=${i};explPanel(D.cases[${cur}])">${x.name} · ${Math.round(x.ml_risk)}</span>`).join("")}</div>
  ${h.explanations.map(r=>`<div class="bar"><div class="n">${esc(r.text)}<small>today ${fmt(r.value)} · this host usually ${fmt(r.baseline_median)}</small></div>
   <div class="track"><div class="fill" style="width:${(100*r.contribution/mx).toFixed(0)}%"></div></div><div class="val">+${r.contribution.toFixed(2)}</div></div>`).join("")}
  <div class="note">ML risk <b style="color:var(--txt)">${h.ml_risk.toFixed(0)}/100</b> is how unusual today is <i>for ${h.name}</i> vs its own baseline — not vs other hosts. The explainability layer ranks the features that pushed the score up. Hunt score ${h.hunt_score.toFixed(0)}.</div>`}

/* timeline */
function timeline(c){$("tabc").innerHTML=`<table><thead><tr><th>Time</th><th>Hunt</th><th>Source → target</th><th>ATT&CK</th><th>What Zeek saw</th><th>Evidence</th></tr></thead><tbody>
 ${c.findings.map(f=>`<tr><td class="mono">${hhmm(f.first_ts)}</td>
  <td><span class="hid" style="background:${COL[f.tactic]}">${f.hunt}</span></td>
  <td><b>${esc(f.src_name)}</b> → ${esc(f.dst_name)}</td><td class="mono">${esc(f.attack.split(",")[0])}</td>
  <td>${esc(f.detail)}</td><td class="mono">${esc(f.evidence_uids[0]||'')}${f.evidence_uids.length>1?` +${f.evidence_uids.length-1}`:''}</td></tr>`).join("")}
 </tbody></table>`}

/* attack path */
function graph(c){$("tabc").innerHTML='<svg id="g" width="100%" height="380" viewBox="0 0 640 380"></svg>';
 const ext=[...new Set(c.findings.filter(f=>["C2-01","C2-02"].includes(f.hunt)).map(f=>f.dst_name))];
 const E=[];const pth={};
 c.attack_path.forEach(e=>{if(e.hunt==="LM-05"){(pth[e.src]=pth[e.src]||[]).push(e.dst)}else E.push(e)});
 Object.entries(pth).forEach(([s,d])=>E.push({src:s,dst:`${d.length} hosts`,hunt:"LM-05",cluster:true}));
 const inc={};E.forEach(e=>{if(["LM-01","LM-02","LM-03","LM-04"].includes(e.hunt))inc[e.dst]=1});
 const hosts=[...new Set(c.hosts.filter(h=>h.hunt_score>0).map(h=>h.name))];
 const roots=hosts.filter(h=>!inc[h]);const lvl={};roots.forEach(r=>lvl[r]=1);
 for(let k=0;k<4;k++)E.forEach(e=>{if(lvl[e.src]&&!(e.dst in lvl)&&!ext.includes(e.dst))lvl[e.dst]=lvl[e.src]+1});
 ext.forEach(x=>lvl[x]=0);hosts.forEach(h=>{if(!(h in lvl))lvl[h]=1});
 const cols={};Object.entries(lvl).forEach(([n,l])=>(cols[l]=cols[l]||[]).push(n));
 const maxL=Math.max(...Object.keys(cols).map(Number));const pos={};
 Object.entries(cols).forEach(([l,ns])=>ns.forEach((n,i)=>pos[n]={x:60+(l)*(520/Math.max(1,maxL)),y:(i+1)*380/(ns.length+1),crowd:ns.length>4}));
 const ec=h=>h.startsWith("C2")?"#b98bff":["LM-05","LM-06","LM-07"].includes(h)?"#ff8a5c":"#4f8cff";
 const lines=[...E.map(e=>({...e,c:ec(e.hunt)})),...ext.map(x=>({src:roots[0]||hosts[0],dst:x,hunt:(c.findings.find(f=>f.dst_name===x)||{}).hunt||"C2-01",c:"#b98bff"}))];
 let s=`<defs>${["#b98bff","#ff8a5c","#4f8cff"].map((k,i)=>`<marker id="a${i}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L10,5L0,10z" fill="${k}"/></marker>`).join("")}</defs>`;
 const mk={"#b98bff":0,"#ff8a5c":1,"#4f8cff":2};
 lines.forEach(e=>{const a=pos[e.src],b=pos[e.dst];if(!a||!b)return;const dx=b.x-a.x,dy=b.y-a.y,L=Math.hypot(dx,dy)||1,r=24;
  const x1=a.x+dx/L*r,y1=a.y+dy/L*r,x2=b.x-dx/L*r,y2=b.y-dy/L*r;
  s+=`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${e.c}" stroke-width="2" marker-end="url(#a${mk[e.c]})" opacity=".85"/>`;
  s+=`<text x="${(x1+x2)/2}" y="${(y1+y2)/2-5}" text-anchor="middle" style="font-size:10px;fill:${e.c};font-weight:700">${e.hunt}</text>`});
 Object.entries(pos).forEach(([n,p])=>{const h=c.hosts.find(x=>x.name===n);const isExt=ext.includes(n);const isCl=/hosts$/.test(n);
  const fill=isExt?"#241a3a":h&&h.hunt_score>0?"#2a1522":"#14203a";const st=isExt?"#b98bff":h&&h.hunt_score>0?"#ff5c78":"#4f8cff";
  s+=`<circle cx="${p.x}" cy="${p.y}" r="22" fill="${fill}" stroke="${st}" stroke-width="2" ${isCl?'stroke-dasharray="4 3"':''}/>`;
  s+=`<text x="${p.x}" y="${p.y+4}" text-anchor="middle" style="font-size:${isExt?9:10.5}px;font-weight:700">${isExt?'C2':isCl?n.split(' ')[0]:n}</text>`;
  s+=`<text x="${p.x}" y="${p.y+37}" text-anchor="middle" style="fill:#8491ab;font-size:10px">${isExt?n.replace(/^(.{16}).+$/,"$1…"):isCl?'NTLM targets':(h&&!p.crowd?h.role:'')}</text>`});
 if(!lines.length)s+=`<text x="320" y="190" text-anchor="middle" style="fill:#8491ab">Single-host case — no lateral-movement edges</text>`;
 $("g").innerHTML=s}

/* ask the network */
const PRESETS=["What abnormal behaviour happened on the network today?","Which hosts should I investigate first, and why did the model flag them?","Is there any sign of credential theft or lateral movement?"];
$("presets").innerHTML=PRESETS.map(p=>`<span class="tag" onclick="$('q').value=this.textContent;askQ()">${p}</span>`).join("");
function showAnswer(r){const j=r.judge||{};const vc=j.verdict==="pass"?"var(--low)":j.verdict==="fail"?"var(--crit)":"var(--mut)";
 $("ans").innerHTML=`<div>${esc(r.answer)}</div><div class="jg"><span class="chip">answered by <b>${esc(String(r.model||"-").split(" (")[0])}</b>${r.latency_s?` · ${r.latency_s}s`:""}</span>
 <span class="chip" style="border-color:${vc}">LLM judge <b style="color:${vc}">&nbsp;${esc(j.verdict||"n/a")}</b>${j.faithfulness?` · faith ${j.faithfulness}/5 · rel ${j.relevance}/5 · comp ${j.completeness}/5 · act ${j.actionability}/5`:""}</span>
 ${(j.unsupported_claims||[]).length?`<span class="chip" style="border-color:var(--crit)">unsupported: ${esc(j.unsupported_claims.join(" | "))}</span>`:""}</div>`}
function askQ(){const q=$("q").value.trim();if(!q)return;
 if(!LIVE){if(window.QA&&QA[q])showAnswer(QA[q]);else $("ans").textContent="Static page — start the lab (docker compose up) to ask free-form questions. The preset questions have stored answers.";return}
 $("ans").textContent="Retrieving today's top behaviours from the store and asking the LLM …";
 fetch("/api/ask",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q})}).then(r=>r.json()).then(showAnswer).catch(e=>$("ans").textContent="error: "+e)}
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")askQ()});
function exportCSV(){const rows=[["case_id","host","label","reason","analyst"]];D.cases.forEach(c=>{if(labels[c.case_id])c.hosts.filter(h=>h.hunt_score>0||c.hosts.length==1).forEach(h=>rows.push([c.case_id,h.name,labels[c.case_id],"dashboard","analyst"]))});
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(r=>r.join(",")).join("\n")],{type:"text/csv"}));a.download="labels.csv";a.click()}

sel(0);
</script></body></html>"""


def render(d, t, live=False, qa=None, metrics=None):
    """HTML for a scored day. live=True: the page talks to server.py (/api/ask, /api/label).
    metrics: optional {detection, llm_short, verdict} to fill the pipeline strip + results ribbon."""
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
    ap.add_argument("--qa", default=None, help="results/metrics.json: show its answers + detection metrics in the static page")
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
            pg = b.new_page(viewport={"width": 1600, "height": 1150}, device_scale_factor=2)
            pg.goto("file://" + __import__("os").path.abspath(a.out))
            pg.wait_for_timeout(400)
            pg.screenshot(path=a.png, full_page=True)
            b.close()
        print("screenshot ->", a.png)


if __name__ == "__main__":
    main()
