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
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;padding:16px 24px 4px}
.kpi .v{transition:color .3s}.kpi.bump{animation:bump .5s}
@keyframes bump{0%{transform:scale(1)}40%{transform:scale(1.06)}100%{transform:scale(1)}}
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
svg text{fill:var(--txt);pointer-events:none}
/* animated pipeline strip */
.stg{opacity:0;transform:translateY(6px);animation:rise .5s ease forwards}
@keyframes rise{to{opacity:1;transform:none}}
.stg.sweep{position:relative}
.stg.sweep::after{content:"";position:absolute;inset:-6px -3px;border-radius:9px;background:radial-gradient(60% 120% at 50% 50%,rgba(79,140,255,.18),transparent 70%);opacity:0;animation:sweep 1s ease}
@keyframes sweep{0%{opacity:0}30%{opacity:1}100%{opacity:0}}
.far{opacity:.5;animation:fadein .6s ease forwards}@keyframes fadein{to{opacity:.8}}
/* chat */
.chatlog{padding:6px 18px 2px;max-height:360px;overflow-y:auto;display:flex;flex-direction:column;gap:12px}
.chatlog:empty{display:none}
.msg{display:flex;gap:10px;max-width:92%}
.msg .av{flex:0 0 26px;height:26px;border-radius:7px;display:grid;place-items:center;font-size:12px;font-weight:700;margin-top:1px}
.msg.user{align-self:flex-end;flex-direction:row-reverse}
.msg.user .av{background:var(--surface3);color:var(--txt2)}
.msg.ai .av{background:linear-gradient(135deg,var(--acc),#8a5bff);color:#fff}
.bub{padding:10px 13px;border-radius:12px;font-size:13.5px;line-height:1.55;white-space:pre-wrap}
.msg.user .bub{background:var(--acc);color:#061024;border-bottom-right-radius:4px}
.msg.ai .bub{background:var(--surface2);border:1px solid var(--line);color:var(--txt2);border-bottom-left-radius:4px}
.cur::after{content:"▋";color:var(--acc);animation:blink 1s steps(1) infinite}@keyframes blink{50%{opacity:0}}
.starters{display:flex;flex-wrap:wrap;gap:6px;padding:10px 18px}
.starters .tag{cursor:pointer}.starters .tag:hover{border-color:var(--acc);color:var(--txt2)}
.askbar{display:flex;gap:9px;align-items:center;padding:12px 18px 16px;border-top:1px solid var(--line)}
.askbar input{flex:1;background:var(--bg2);color:var(--txt);border:1px solid var(--line2);border-radius:10px;padding:12px 14px;font:inherit}
.askbar input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.15)}
.mode{font-size:10px;font-weight:700;letter-spacing:.4px;padding:2px 8px;border-radius:999px;margin-left:8px;text-transform:uppercase}
.mode.live{color:var(--low);border:1px solid var(--low)}.mode.demo{color:var(--mut);border:1px solid var(--line2)}
circle[data-host]{cursor:pointer;transition:filter .15s}circle[data-host]:hover{filter:brightness(1.25)}
/* policy / threat tags + zone map */
.bpol{font-size:9.5px;font-weight:800;padding:1px 6px;border-radius:5px;background:var(--crit);color:#fff}
.bth{font-size:10px;padding:1px 7px;border-radius:5px;border:1px solid var(--c2);color:var(--c2)}
/* context button, toggle, modal, toast */
.ctxbtn{display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:9px;border:1px solid var(--acc);color:var(--acc2);background:rgba(79,140,255,.08);cursor:pointer;font-size:12px;font-weight:650}
.ctxbtn:hover{background:rgba(79,140,255,.16)}
.toggle{display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;color:var(--mut);user-select:none}
.sw{width:34px;height:19px;border-radius:999px;background:var(--surface3);border:1px solid var(--line2);position:relative;transition:background .15s;flex:0 0 auto}
.sw::after{content:"";position:absolute;top:1px;left:1px;width:15px;height:15px;border-radius:50%;background:var(--mut);transition:left .15s}
.sw.on{background:var(--acc)}.sw.on::after{left:16px;background:#fff}
.modal{position:fixed;inset:0;background:rgba(5,8,13,.72);backdrop-filter:blur(3px);display:none;place-items:center;z-index:50;padding:20px}
.modal.show{display:grid}
.sheet{width:min(560px,94vw);max-height:86vh;overflow:auto;background:var(--surface);border:1px solid var(--line2);border-radius:14px;box-shadow:0 24px 70px -24px #000}
.sheet .hd{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line);font-weight:700}
.sheet .bd2{padding:16px 18px}
.drop{border:1.5px dashed var(--line2);border-radius:12px;padding:22px;text-align:center;color:var(--mut);cursor:pointer;margin:12px 0}
.drop:hover{border-color:var(--acc);color:var(--txt2)}
.x{margin-left:auto;cursor:pointer;color:var(--mut);font-size:20px;line-height:1}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--surface3);border:1px solid var(--line2);border-radius:10px;padding:10px 16px;font-size:13px;z-index:60;opacity:0;transition:opacity .2s;pointer-events:none}
.toast.show{opacity:1}
.zlist{display:flex;flex-direction:column;gap:6px;margin:10px 0}
.zrow{display:flex;align-items:center;gap:10px;font-size:12.5px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--surface2)}
.crit{display:inline-flex;gap:2px}.crit i{width:6px;height:6px;border-radius:50%;background:var(--crit);display:inline-block}.crit i.off{background:var(--line2)}
@media (max-width:1050px){main{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<header>
 <div class="brand"><span class="mk">◆</span>NSM Hunt Console<small>Network Detection &amp; Response</small></div>
 <span class="spring"></span>
 <span class="chip"><span class="dot"></span>Zeek sensor <b id="src">live</b></span>
 <span class="chip">ML <b id="model">Isolation Forest</b></span>
 <span class="chip">LLM <b id="llmname">Ollama</b> · self-hosted</span>
 <span class="chip">Hunt day <b id="day"></b></span>
 <button class="ctxbtn" id="ctxbtn" onclick="openCtx()" title="Upload your network context (zones, policy, threat model)">◇ Network context</button>
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
  <div class="card" style="margin-bottom:16px">
   <div class="pad" style="padding-bottom:0"><h3 style="margin-bottom:4px">Ask the network<span class="mode" id="chatmode"></span></h3>
    <div class="muted">Answers come only from the stored ML + explainability + hunt output — never from raw logs.</div></div>
   <div class="chatlog" id="chatlog"></div>
   <div class="starters" id="presets"></div>
   <div class="askbar"><input id="q" placeholder="Ask about today's activity…" autocomplete="off">
    <button class="btn pri" id="sendb" onclick="askQ()">Send</button></div>
  </div>
  <div class="card">
   <div class="ch2"><div class="ring" id="cring"></div><div><div class="id" id="cid"></div><div class="big" id="ctitle"></div></div></div>
   <div class="chain" id="chain"></div>
   <div class="tabrow" id="tabrow">
     <span data-t="overview" class="on">Overview</span><span data-t="explain">Explainability</span>
     <span data-t="timeline">Timeline</span><span data-t="graph">Attack path</span><span data-t="zones" id="tab-zones">Zone map</span></div>
   <div class="tabc" id="tabc"></div>
  </div>
 </section>
</main>
<div class="modal" id="ctxmodal"><div class="sheet">
 <div class="hd">◇ Network context<span class="x" onclick="closeCtx()">×</span></div>
 <div class="bd2">
  <div class="muted" id="ctxsummary"></div>
  <div class="zlist" id="ctxzones"></div>
  <label class="toggle" style="margin:6px 0 2px"><span class="sw" id="ctxsw"></span> Score with this context (zones · policy · threat model)</label>
  <div class="drop" id="ctxdrop">Click to upload a <b>network_context.json</b><div class="muted" style="margin-top:5px">zones · allowed_flows · threat_model — see the README for the format. The pipeline reads YAML; the in-browser upload takes JSON.</div></div>
  <input type="file" id="ctxfile" accept=".json,application/json" style="display:none">
  <div class="muted" id="ctxmsg"></div>
 </div>
</div></div>
<div class="toast" id="toast"></div>
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
 $("flow").innerHTML=S.map((s,i)=>`<div class="stg ${s[3]}" style="animation-delay:${i*55}ms"><div class="sn">${s[0]}</div><div class="sv">${s[1]}</div><div class="sd">${s[2]}</div></div>`+(i<S.length-1?'<div class="far">→</div>':'')).join("");
 const st=[...document.querySelectorAll('.stg')];let si=0;   // a highlight that sweeps the pipeline, left to right
 setInterval(()=>{st.forEach(x=>x.classList.remove('sweep'));const x=st[si%st.length];if(x){void x.offsetWidth;x.classList.add('sweep')}si++},720)})();

/* kpis */
const crit=D.cases.filter(c=>c.severity==="critical").length;
$("kpis").innerHTML=[[D.hosts_scored,"hosts scored"],[D.findings_total,"hunt hits (12 hunts)"],
 [D.cases.length,"open cases"],[crit,"critical",1],[D.findings_suppressed,"auto-suppressed"],
 ['<span id="ntri">0</span>',"triaged today",0,"tri"]]
 .map(([v,l,c,k])=>`<div class="kpi ${c?'crit':''}" ${k?`id="kpi-${k}"`:''}><div class="v">${v}</div><div class="l">${l}</div></div>`).join("");
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
function renderTab(){const c=D.cases[cur];({overview:tri,explain:explPanel,timeline:timeline,graph:graph,zones:zonemap}[tab]||tri)(c)}

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
 const t=$("ntri");if(t){t.textContent=Object.keys(labels).length;const k=$("kpi-tri");if(k){k.classList.remove("bump");void k.offsetWidth;k.classList.add("bump")}}
 if(LIVE)fetch("/api/label",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({case_id:c.case_id,host:c.hosts[0].name,label:l,reason:($("reason")||{}).value||""})})}
function focusHost(name){const c=D.cases[cur];const hs=c.hosts.filter(h=>h.explanations&&h.explanations.length);const i=hs.findIndex(h=>h.name===name);if(i<0)return;
 tab='explain';curHost=i;$("tabrow").querySelectorAll("span").forEach(x=>x.classList.toggle("on",x.dataset.t=='explain'));renderTab()}

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
  <td><b>${esc(f.src_name)}</b> → ${esc(f.dst_name)}${f.zone_src?`<div class="muted" style="font-size:10px">${esc(f.zone_src)} → ${esc(f.zone_dst)}</div>`:''}</td><td class="mono">${esc(f.attack.split(",")[0])}</td>
  <td>${esc(f.detail)} ${f.policy=='violation'?'<span class="bpol">policy</span>':''} ${f.threat_name?`<span class="bth">${esc(f.threat_name)}</span>`:''}</td><td class="mono">${esc(f.evidence_uids[0]||'')}${f.evidence_uids.length>1?` +${f.evidence_uids.length-1}`:''}</td></tr>`).join("")}
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
  const click=(h&&h.explanations&&h.explanations.length)?`data-host="${esc(n)}" onclick="focusHost('${String(n).replace(/['\\]/g,'')}')"`:'';
  s+=`<circle cx="${p.x}" cy="${p.y}" r="22" fill="${fill}" stroke="${st}" stroke-width="2" ${isCl?'stroke-dasharray="4 3"':''} ${click}/>`;
  s+=`<text x="${p.x}" y="${p.y+4}" text-anchor="middle" style="font-size:${isExt?9:10.5}px;font-weight:700">${isExt?'C2':isCl?n.split(' ')[0]:n}</text>`;
  s+=`<text x="${p.x}" y="${p.y+37}" text-anchor="middle" style="fill:#8491ab;font-size:10px">${isExt?n.replace(/^(.{16}).+$/,"$1…"):isCl?'NTLM targets':(h&&!p.crowd?h.role:'')}</text>`});
 if(!lines.length)s+=`<text x="320" y="190" text-anchor="middle" style="fill:#8491ab">Single-host case — no lateral-movement edges</text>`;
 $("g").innerHTML=s}

/* ask the network — a multi-turn chat. Live: the LLM (Ollama) answers over the store. Static: the recorded answers play back. */
const PRESETS=["What abnormal behaviour happened on the network today?","Which hosts should I investigate first, and why did the model flag them?","Is there any sign of credential theft or lateral movement?"];
$("presets").innerHTML=PRESETS.map(p=>`<span class="tag" onclick="askQ(this.textContent)">${esc(p)}</span>`).join("");
$("chatmode").className="mode "+(LIVE?"live":"demo");
$("chatmode").textContent=LIVE?("live · "+String(D.llm_model||"qwen3").split(" (")[0]):"recorded demo";
const chat=[];let busy=false;
function scrollChat(){const l=$("chatlog");l.scrollTop=l.scrollHeight}
function bubble(role){const m=document.createElement("div");m.className="msg "+role;
 m.innerHTML=`<div class="av">${role=="user"?"You":"◆"}</div><div class="bub"></div>`;
 $("chatlog").appendChild(m);scrollChat();return m.querySelector(".bub")}
function typeOut(el,text,meta){el.classList.add("cur");let i=0;const step=Math.max(1,Math.round(text.length/90));
 (function go(){i+=step;el.textContent=text.slice(0,i);scrollChat();
  if(i<text.length)setTimeout(go,16);else{el.classList.remove("cur");el.textContent=text;if(meta)el.insertAdjacentHTML("beforeend",meta);busy=false;scrollChat()}})()}
function chips(r){const j=r.judge||{};if(!r.model&&!j.verdict)return"";
 const vc=j.verdict=="pass"?"var(--low)":j.verdict=="fail"?"var(--crit)":"var(--mut)";
 return `<div class="jg" style="margin-top:9px"><span class="chip">${esc(String(r.model||"qwen3").split(" (")[0])}${r.latency_s?` · ${r.latency_s}s`:""}</span>`+
  (j.verdict?`<span class="chip" style="border-color:${vc}">LLM judge <b style="color:${vc}">&nbsp;${esc(j.verdict)}</b>${j.faithfulness?` · faith ${j.faithfulness}/5`:""}</span>`:"")+
  ((j.unsupported_claims||[]).length?`<span class="chip" style="border-color:var(--crit)">unsupported: ${esc(j.unsupported_claims.join(" | "))}</span>`:"")+`</div>`}
function askQ(preset){if(busy)return;const q=String(preset||$("q").value).trim();if(!q)return;$("q").value="";
 bubble("user").textContent=q;chat.push({role:"user",content:q});busy=true;const ab=bubble("ai");ab.classList.add("cur");ab.textContent="…";
 if(LIVE){fetch("/api/ask",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q,history:chat.slice(0,-1)})})
   .then(r=>r.json()).then(r=>{chat.push({role:"assistant",content:r.answer});ab.classList.remove("cur");typeOut(ab,r.answer,chips(r))})
   .catch(e=>{ab.classList.remove("cur");ab.textContent="error: "+e;busy=false})}
 else{const r=QA[q];ab.classList.remove("cur");
  if(r){chat.push({role:"assistant",content:r.answer});typeOut(ab,r.answer,chips(r)+`<div class="muted" style="margin-top:6px">Recorded answer · run the lab for a live chat.</div>`)}
  else{const t="This is the static demo — I can replay the recorded answers above, so tap a suggested question. Run the lab locally (docker compose up) for a live chat that answers any question from today's stored results.";chat.push({role:"assistant",content:t});typeOut(ab,t)}}}
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")askQ()});
function exportCSV(){const rows=[["case_id","host","label","reason","analyst"]];D.cases.forEach(c=>{if(labels[c.case_id])c.hosts.filter(h=>h.hunt_score>0||c.hosts.length==1).forEach(h=>rows.push([c.case_id,h.name,labels[c.case_id],"dashboard","analyst"]))});
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(r=>r.join(",")).join("\n")],{type:"text/csv"}));a.download="labels.csv";a.click()}

/* ---- network context: zones, policy, threat model (scoring + zone map + upload) ---- */
let NC=D.netcontext||null, CTXON=!!NC;
function ipInt(ip){const p=String(ip).split('.');if(p.length!=4||p.some(x=>x===''||isNaN(x)))return null;return(((+p[0])*16777216)+((+p[1])*65536)+((+p[2])*256)+(+p[3]))>>>0}
function inCidr(ip,cidr){const [a,b]=cidr.split('/');const ii=ipInt(ip),ni=ipInt(a);if(ii==null||ni==null)return false;const m=(+b)==0?0:(0xffffffff*Math.pow(2,32-(+b)))>>>0&0xffffffff;const mask=(+b)==0?0:(~((1<<(32-(+b)))-1))>>>0;return((ii&mask)>>>0)===((ni&mask)>>>0)}
function zoneOf(ip,nc){if(ipInt(ip)==null)return 'external';let best=null,bl=-1;(nc.zones||[]).forEach(z=>(z.cidrs||[]).forEach(c=>{const pl=+(c.split('/')[1]);if(inCidr(ip,c)&&pl>bl){bl=pl;best=z.name}}));return best||'unknown'}
function zCrit(nc,zn){const z=(nc.zones||[]).find(z=>z.name==zn);return z?(z.criticality||1):1}
function critOf(ip,nc){const a=(nc.critical_assets||[]).find(a=>a.ip==ip);if(a)return a.criticality;return zCrit(nc,zoneOf(ip,nc))}
function threatOf(hunt,nc){return(nc.threat_model||[]).find(t=>(t.hunts||[]).includes(hunt))}
function annotate(nc){const vh=new Set(nc.violation_hunts||[]);const al=new Set((nc.allowed_flows||[]).map(f=>Array.isArray(f)?f[0]+'>'+f[1]:f.from+'>'+f.to));const BB={5:10,4:8,3:5,2:3,1:1,0:0};
 D.cases.forEach(c=>{let viols=[],threats=[],critz=new Set();
  c.findings.forEach(f=>{const zs=zoneOf(f.src,nc),zd=zoneOf(f.dst,nc);let pol=zd=='external'?'external':(al.has(zs+'>'+zd)||(zs==zd&&zs!='workstations')?'allowed':'violation');if(vh.has(f.hunt))pol='violation';
   f.zone_src=zs;f.zone_dst=zd;f.policy=pol;const t=threatOf(f.hunt,nc);f.threat_name=t?t.name:null;
   if(pol=='violation'){viols.push(f);if(critOf(f.dst,nc)>=3)critz.add(zd);if(t&&!threats.find(x=>x.id==t.id))threats.push({id:t.id,name:t.name,technique:t.technique})}});
  const maxc=Math.max(0,...viols.map(f=>critOf(f.dst,nc)));
  c._ctx={violations:viols.length,critical_zones_reached:[...critz],threats:threats,bonus:viols.length?Math.min(14,(BB[maxc]||0)+Math.min(4,threats.length)):0}})}
function rescore(){if(NC&&CTXON){annotate(NC);D.cases.forEach(c=>{const base=c.score_base!=null?c.score_base:c.score;c.score=Math.min(100,Math.round((base+c._ctx.bonus)*10)/10)})}
 else{D.cases.forEach(c=>{c.score=(c.score_base!=null?c.score_base:c.score);c._ctx=null;c.findings.forEach(f=>{f.policy=null;f.threat_name=null})})}
 D.cases.forEach(c=>c.severity=c.score>=90?'critical':c.score>=75?'high':c.score>=50?'medium':'low');
 D.cases.sort((a,b)=>b.score-a.score);cur=0;queue();sel(0)}
function zonemap(c){if(!NC){$("tabc").innerHTML='<div class="muted">No network context loaded. Click <b>◇ Network context</b> in the header to upload your zones, policy and threat model.</div>';return}
 const nc=NC,zs=[...nc.zones].sort((a,b)=>(b.criticality||1)-(a.criticality||1)),W=640,bh=58,top=10,H=top+zs.length*bh+16,yOf={};
 zs.forEach((z,i)=>yOf[z.name]=top+i*bh+bh/2);
 const ip={};c.hosts.forEach(h=>ip[h.name]=h.ip);c.findings.forEach(f=>{ip[f.src_name]=f.src;ip[f.dst_name]=f.dst});
 const names=new Set();c.attack_path.forEach(e=>{names.add(e.src);names.add(e.dst)});c.findings.filter(f=>f.hunt[0]=='C').forEach(f=>names.add(f.dst_name));if(!names.size)c.hosts.forEach(h=>names.add(h.name));
 const byZone={};[...names].forEach(n=>{const z=zoneOf(ip[n]||'',nc);(byZone[z]=byZone[z]||[]).push(n)});
 const pos={};Object.entries(byZone).forEach(([z,ns])=>ns.forEach((n,i)=>pos[n]={x:120+(i+1)*((W-150)/(ns.length+1)),y:yOf[z]!=null?yOf[z]:H-bh/2}));
 let s=`<defs>${[['v','#ff5c78'],['a','#4f8cff'],['e','#b98bff']].map(([k,col])=>`<marker id="z${k}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L10,5L0,10z" fill="${col}"/></marker>`).join("")}</defs>`;
 zs.forEach((z,i)=>{const y=top+i*bh,col=z.criticality>=5?'#ff5c78':z.criticality>=4?'#ff9d4d':z.criticality>=3?'#ffce4d':'#2b374f';
  s+=`<rect x="8" y="${y+4}" width="${W-16}" height="${bh-8}" rx="9" fill="${z.name=='external'?'#141019':'#111a2b'}" stroke="${col}" stroke-opacity=".45"/><text x="20" y="${y+bh/2-1}" style="font-size:12px;font-weight:700">${esc(z.name)}</text><text x="20" y="${y+bh/2+14}" style="font-size:9.5px;fill:#8491ab">crit ${z.criticality}</text>`});
 function edge(a,b,col,mk,lab){const dx=b.x-a.x,dy=b.y-a.y,L=Math.hypot(dx,dy)||1,r=18,x1=a.x+dx/L*r,y1=a.y+dy/L*r,x2=b.x-dx/L*r,y2=b.y-dy/L*r;s+=`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${col}" stroke-width="2" marker-end="url(#${mk})" opacity=".9"/><text x="${(x1+x2)/2}" y="${(y1+y2)/2-4}" text-anchor="middle" style="font-size:9px;font-weight:700;fill:${col}">${lab}</text>`}
 const seen={};c.attack_path.forEach(e=>{const k=e.src+'>'+e.dst;if(seen[k])return;seen[k]=1;const a=pos[e.src],b=pos[e.dst];if(!a||!b)return;const f=c.findings.find(x=>x.src_name==e.src&&x.dst_name==e.dst);const v=f&&f.policy=='violation';const ext=zoneOf(ip[e.dst]||'',nc)=='external';edge(a,b,v?'#ff5c78':'#4f8cff',v?'zv':'za',ext?'':e.hunt)});
 const c2seen={};c.findings.filter(f=>f.hunt=='C2-01'||f.hunt=='C2-02').forEach(f=>{const a=pos[f.src_name],b=pos[f.dst_name];if(a&&b&&!c2seen[f.dst_name]){c2seen[f.dst_name]=1;edge(a,b,'#b98bff','ze','')}});
 Object.entries(pos).forEach(([n,p])=>{const h=c.hosts.find(x=>x.name==n),ext=zoneOf(ip[n]||'',nc)=='external',fill=ext?'#241a3a':h&&h.hunt_score>0?'#2a1522':'#14203a',st=ext?'#b98bff':h&&h.hunt_score>0?'#ff5c78':'#4f8cff';
  s+=`<circle cx="${p.x}" cy="${p.y}" r="17" fill="${fill}" stroke="${st}" stroke-width="2"/><text x="${p.x}" y="${p.y+4}" text-anchor="middle" style="font-size:9.5px;font-weight:700">${esc(n.length>11?n.slice(0,10)+'…':n)}</text>`});
 s+=`<text x="${W-14}" y="${H-5}" text-anchor="end" style="font-size:9.5px;fill:#8491ab">red = breaks zone policy · blue = allowed · purple = external C2</text>`;
 $("tabc").innerHTML=`<svg width="100%" viewBox="0 0 ${W} ${H}">${s}</svg>`+(c._ctx?`<div class="note">Context: <b>${c._ctx.violations}</b> policy violation(s)${c._ctx.critical_zones_reached.length?`, reaching <b style="color:var(--crit)">${c._ctx.critical_zones_reached.join(', ')}</b>`:''}${c._ctx.threats.length?` · matches ${c._ctx.threats.map(t=>esc(t.name)+(t.technique?' ('+esc(t.technique)+')':'')).join(', ')}`:''} → <b>+${c._ctx.bonus}</b> score.</div>`:'')}
function openCtx(){const nc=NC,su=$("ctxsummary"),zl=$("ctxzones");
 if(!nc){su.innerHTML="No network context loaded yet. Upload one to score by zone, policy and your threat model.";zl.innerHTML=""}
 else{su.innerHTML=`<b>${esc(nc.name||'network')}</b> · ${nc.zones.length} zones · ${(nc.threat_model||[]).length} threat-model scenarios · ${(nc.allowed_flows||[]).length} allowed flows`;
  zl.innerHTML=nc.zones.map(z=>`<div class="zrow"><span style="flex:1"><b>${esc(z.name)}</b> <span class="muted">${(z.cidrs||[]).join(', ')}</span></span><span class="crit">${[1,2,3,4,5].map(i=>`<i class="${i<=(z.criticality||1)?'':'off'}"></i>`).join("")}</span></div>`).join("")}
 $("ctxsw").classList.toggle("on",CTXON);$("ctxmsg").textContent="";$("ctxmodal").classList.add("show")}
function closeCtx(){$("ctxmodal").classList.remove("show")}
function toast(t){const e=$("toast");e.textContent=t;e.classList.add("show");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("show"),2600)}
$("ctxsw").onclick=()=>{if(!NC){toast("Upload a context first");return}CTXON=!CTXON;$("ctxsw").classList.toggle("on",CTXON);rescore();if(tab=='zones')zonemap(D.cases[cur]);toast(CTXON?"Context ON — scored by zone, policy & threat model":"Context OFF — base ML + hunt score")};
$("ctxdrop").onclick=()=>$("ctxfile").click();
$("ctxfile").onchange=e=>{const f=e.target.files[0];if(!f)return;const rd=new FileReader();
 rd.onload=()=>{try{const j=JSON.parse(rd.result);if(!j.zones||!j.zones.length)throw new Error("missing zones[]");
   NC=j;CTXON=true;$("tab-zones").style.display="";$("ctxbtn").style.opacity=1;rescore();openCtx();
   $("ctxmsg").innerHTML=`<span style="color:var(--low)">Loaded ${esc(j.name||f.name)} — queue re-scored.</span>`;toast("Network context applied");
   if(LIVE)fetch("/api/netcontext",{method:"POST",headers:{"Content-Type":"application/json"},body:rd.result}).catch(()=>{})}
  catch(err){$("ctxmsg").innerHTML=`<span style="color:var(--crit)">Invalid JSON context: ${esc(err.message)}</span>`}};
 rd.readAsText(f)};
if(NC){annotate(NC)}else{$("ctxbtn").style.opacity=.75;$("tab-zones").style.display="none"}
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
