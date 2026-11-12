'use strict';
const $ = id => document.getElementById(id);
const esc = x => String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const jprint = obj => JSON.stringify(obj,null,2);
const safeNum = x => Number.isFinite(Number(x)) ? Number(x) : 0;
const utc = t => t ? new Date(Number(t)*1000).toISOString().slice(0,19).replace('T',' ') + ' UTC' : '—';
const pageName = location.pathname.startsWith('/tool/') ? location.pathname.split('/').pop() : 'overview';
const names = {overview:'Overview',crowdsec:'CrowdSec & IP Enforcement',waf:'Coraza WAF',suricata:'Suricata IDS',clamav:'ClamAV Antivirus',k6:'k6 Load Testing',iperf3:'iperf3 Network Throughput',prometheus:'Prometheus Metrics',grafana:'Grafana Monitoring',store:'Protected Demo Store',guide:'Student Practical Guide',remoteecs:'Remote ECS2 Telemetry'};
async function api(path,options={}){
  let opt={...options};if(opt.body && !(opt.body instanceof FormData))opt.headers={'Content-Type':'application/json',...(opt.headers||{})};
  let r=await fetch(path,opt);let data;try{data=await r.json()}catch{throw Error(`Non-JSON HTTP ${r.status} (check Coraza logs / app health)`)}
  if(!r.ok)throw Error(typeof data.detail==='string'?data.detail:typeof data.error==='string'?data.error:typeof data.message==='string'?data.message:`HTTP ${r.status}`);
  return data;
}
const post=(path,data={})=>api(path,{method:'POST',body:JSON.stringify(data)});
const del=path=>api(path,{method:'DELETE'});
let toastTimeout;
function toast(msg,bad=false){const n=$('toast');n.textContent=msg;n.className='toast'+(bad?' bad':'');clearTimeout(toastTimeout);toastTimeout=setTimeout(()=>n.className='toast hidden',7000)}
function result(id,obj){const n=$(id);if(n)n.textContent=typeof obj==='string'?obj:jprint(obj)}
async function perform(button,fn){if(button)button.disabled=true;try{await fn()}catch(e){toast(e.message,true)}finally{if(button)button.disabled=false}}
function intro(tag,title,desc){return `<div class="eyebrow">${tag}</div><h1 class="page-title">${title}</h1><p class="page-subtitle">${desc}</p>`}
function panel(title,body,extra=''){return `<section class="panel"><div class="heading-row"><h2>${title}</h2>${extra}</div>${body}</section>`}
function proof(text){return `<div class="notice">${text}</div>`}
function step(n,title,body){return `<div class="step"><div class="step-num">${n}</div><div><b>${title}</b><p>${body}</p></div></div>`}
function stats(items){return `<div class="stats">${items.map(([label,value,note])=>`<div class="stat"><span>${label}</span><b>${esc(value)}</b><small>${note}</small></div>`).join('')}</div>`}
const toolCards=[
 ['crowdsec','⊘','CrowdSec & IP bans','Ban a real test client and confirm HTTP 429; inspect CrowdSec decisions.'],
 ['waf','⬡','Coraza WAF','Send safe, controlled requests through the genuine firewall.'],
 ['suricata','◎','Suricata IDS','Start and stop actual live packet monitoring, investigate real alerts, and inspect PCAP evidence.'],
 ['clamav','◈','ClamAV','Test an antivirus scan using a harmless EICAR signature.'],
 ['k6','↗','k6 Load Testing','Generate actual traffic to the protected shopping application.'],
 ['iperf3','⇄','iperf3','Measure actual TCP transfer speed between lab containers.'],
 ['prometheus','◷','Prometheus','Run real PromQL queries and inspect live scrape targets.'],
 ['grafana','▥','Grafana','Explore 8 preserved dashboards and 3 new real-metrics dashboards.'],
 ['store','▣','KooLab Demo Store','Use the actual sample workload: catalog, cart, API, downloads.'],['remoteecs','▦','ECS2 Target Telemetry','Monitor real measurements from optional second ECS.']
];
function overview(){
 $('page').innerHTML=intro('MISSION CONTROL','CloudShield operations','Dedicated real-world labs. Each button calls a real security or testing engine; no fake enable/disable switches.')+
 stats([['Active bans','…','Application-layer'],['Events / hour','…','Audit records'],['Load test','…','Real k6 process'],['Available engines','…','Real service checks']])+
 panel('Engine availability','<div id="engineGrid" class="engine-grid">Checking containers and services…</div>')+
 '<h2 style="margin:23px 0 14px">Choose a practical tool</h2><div class="gridtools">'+toolCards.map(([slug,icon,title,desc])=>`<a class="tile" href="/tool/${slug}"><span class="icon">${icon}</span><h3>${title}</h3><p>${desc}</p><span class="go">Open dedicated lab →</span></a>`).join('')+'</div>'+
 proof('Test results are measured from actual HTTP calls, active processes, files or instrumented metrics. A tool without a running engine will show an error or “unavailable,” not a successful simulation.');
 Promise.all([api('/api/status'),api('/api/tools/runtime')]).then(([s,eng])=>{
  let els=document.querySelectorAll('.stat b');els[0].textContent=s.bans;els[1].textContent=s.events_last_hour;els[2].textContent=s.running?'RUNNING':'IDLE';els[3].textContent=Object.values(eng).filter(x=>x.ok).length+' / '+Object.keys(eng).length;
  $('engineGrid').innerHTML=Object.entries(eng).map(([key,v])=>`<div class="engine-item"><span><span class="dot ${v.ok?'on':'off'}"></span>${esc(key)}</span><span class="${v.ok?'good':'dim'}">${v.ok?'Reachable':'Unavailable'}</span></div>`).join('');
 }).catch(e=>toast('Service status: '+e.message,true));
}
function crowdsec(){
 $('page').innerHTML=intro('SECURITY PRACTICAL 01','CrowdSec & independent IP clients','Three separate Docker containers generate actual requests. Block one client, keep the others reachable, and learn the difference between a CloudShield ban and CrowdSec LAPI decisions.')+
 panel('Step 1 · See real client IP addresses',proof('Clients A, B and C have their own Docker IP addresses. The IMPORTANT field is <b>IP actually seen by the protected app</b>. If it differs from the expected IP, enforcement needs fixing before a lab can pass.')+
 '<div class="actions"><button id="refreshClients" class="btn primary">Test all three clients now</button><button id="resetClients" class="btn warn">Emergency reset A/B/C bans</button></div><div class="table-wrap"><table><thead><tr><th>Client</th><th>Docker IP</th><th>IP observed by app</th><th>HTTP result</th><th>Time blocked</th><th>Actions</th></tr></thead><tbody id="clientRows"><tr><td colspan="6">Loading genuine HTTP probes…</td></tr></tbody></table></div><div class="result" id="clientInfo">IP proof comes from a live request; this is not a fake dashboard switch.</div>')+
 panel('Step 2 · Understand the ban and expiry','<div class="input-row"><label class="field">Time limit<select id="banMinutes"><option value="1">1 minute — classroom test</option><option value="5">5 minutes</option><option value="60">1 hour</option><option value="240">4 hours</option></select></label></div>'+step('1','Test all three','Before the ban, each client should receive HTTP 200 and identify itself with its own IP.')+step('2','Ban Client B','Only Client B should be denied. Clients A and C must continue working.')+step('3','Unban with a real button','Click Unban B or wait for expiry; check that its HTTP status returns to 200.')+proof('The per-client buttons control <b>CloudShield application-guard enforcement (429)</b>. These are not automatically CrowdSec bans. CrowdSec LAPI decisions are reported in the separate panel below.'))+
 panel('Exercise B · Generate actual suspicious login behavior','<p>Choose one independent client, then send five genuine wrong-password HTTP requests. The application guard may ban it. Check the separate CrowdSec decisions panel to find out whether CrowdSec itself issued a ban.</p><div class="input-row"><label class="field">Traffic source<select id="loginClient"><option value="B">Client B</option><option value="A">Client A</option><option value="C">Client C</option></select></label><button id="badLogins" class="btn warn">Send five actual failed logins</button></div><div id="loginOutput" class="result">No failed logins sent.</div>')+
 panel('Actual CrowdSec LAPI evidence','<p class="muted">If CrowdSec has a genuine ban decision its LAPI will show it. Empty results mean there is no CrowdSec decision; we do not relabel application bans as CrowdSec bans.</p><div class="actions"><button class="btn" id="crowdDecisions">Fetch real CrowdSec decisions</button></div><div class="result" id="crowdResult">Not queried yet.</div>');
 const refresh=async()=>{
   const data=await api('/api/v3/clients'); const rows=$('clientRows');
   rows.innerHTML=data.clients.map(c=>{const obs=c.body?.observed_client_ip??c.body?.ip??'—';const status=c.http_status??'ERROR';const valid=c.source_ip_verified?'✓':'⚠';return `<tr><td><b>${esc(c.client)}</b></td><td class="mono">${esc(c.expected_ip)}</td><td class="mono">${valid} ${esc(obs)}</td><td>${esc(status)}</td><td>${c.seconds_left||0}s</td><td><button class="btn slim warn" data-ban="${esc(c.client)}">Ban</button> <button class="btn slim safe" data-unban="${esc(c.client)}">Unban</button></td></tr>`}).join('');
   rows.querySelectorAll('[data-ban]').forEach(b=>b.onclick=e=>perform(b,async()=>{let out=await post('/api/v3/clients/ban',{client:b.dataset.ban,minutes:Number($('banMinutes').value)});result('clientInfo',out);await refresh()}));
   rows.querySelectorAll('[data-unban]').forEach(b=>b.onclick=e=>perform(b,async()=>{let out=await post('/api/v3/clients/unban',{client:b.dataset.unban});result('clientInfo',out);await refresh()}));
   const wrong=data.clients.filter(c=>!c.source_ip_verified); if(wrong.length)result('clientInfo','SOURCE-IP VERIFICATION WARNING: '+wrong.map(x=>x.client+': expected '+x.expected_ip+' but observed '+(x.body?.observed_client_ip||'none')).join('; ')+'\nDo not claim independent ban tests pass until real source IPs match.');
 };
 $('refreshClients').onclick=e=>perform(e.target,refresh);
 $('resetClients').onclick=e=>perform(e.target,async()=>{result('clientInfo',await post('/api/v3/clients/reset'));await refresh()});
 $('badLogins').onclick=e=>perform(e.target,async()=>{result('loginOutput',await post('/api/v3/clients/login-abuse',{client:$('loginClient').value,minutes:1}));await refresh()});
 $('crowdDecisions').onclick=e=>perform(e.target,async()=>result('crowdResult',await api('/api/tools/crowdsec/decisions')));
 refresh().catch(e=>result('clientInfo',e.message));
}
function waf(){
 const cases=[['normal','Ordinary visit','A visitor sends a normal message. No blocking threshold should be reached.'],['sqli','Database trick-like text','The request contains harmless text that looks like someone trying to confuse a database.'],['xss','Script-like text','The request contains harmless script-shaped text. It is never executed by the sample app.'],['traversal','File path trick-like text','The request contains harmless text resembling navigation outside the expected folder.']];
 $('page').innerHTML=intro('SECURITY PRACTICAL 02','Coraza — The website gatekeeper','A request enters the security gate before reaching our store. Watch the actual HTTP response, and learn what the firewall saw and why it may block.')+
 panel('The three simple stages', '<div class="gridtools"><div class="probe-profile"><h3>① Visitor sends data</h3><p>Normal product search or suspicious-looking text travels toward the website.</p></div><div class="probe-profile"><h3>② Coraza checks rules</h3><p>A security rule looks for known risky patterns and may add an anomaly score.</p></div><div class="probe-profile"><h3>③ Allow or block</h3><p>Below the blocking score = usually allowed. At the threshold = denied. A 403 alone is not enough to identify who blocked it.</p></div></div>')+
 panel('Choose a genuine request',proof('Each button sends a real request through the running Coraza + OWASP CRS reverse proxy. We display the <b>exact harmless text</b>, observed HTTP status, and actual matching rule IDs if audit data is available.')+
 '<div class="gridtools">'+cases.map(([id,name,desc])=>`<div class="probe-profile"><span class="tag">${esc(id)}</span><h3>${esc(name)}</h3><p>${esc(desc)}</p><button class="btn primary" data-waf="${id}">Send request to firewall</button></div>`).join('')+'</div><div class="result" id="wafOut">Choose any test to read real evidence.</div><div id="wafExplain" class="notice">HTTP 200 = the website answered normally. HTTP 403 = denied, but confirm rule evidence before attributing the decision to Coraza.</div>')+
 panel('Why does one pass and another fail?',step('A','The request text differs','A normal product search usually has no suspicious markers; a script-shaped phrase can match security rules.')+step('B','Rules have scores','Some rules only raise a warning. Several scores may accumulate past the configured blocking threshold.')+step('C','Check real evidence','If audit rules are absent, the page should explicitly say “rule evidence unavailable” instead of inventing a reason.')+'<div class="notice warn">False positives are possible. A legitimate request can be denied. Coraza is a web-request filter, not antivirus and not a universal malware detector.</div>');
 document.querySelectorAll('[data-waf]').forEach(b=>b.onclick=e=>perform(b,async()=>{
   const x=await post('/api/tools/waf/check',{profile:b.dataset.waf});
   result('wafOut',x);
   $('wafExplain').textContent=`Request: ${x.request_text}\nActual HTTP: ${x.http_status}\nResult: ${x.verdict}\nWhy: ${x.why}\nRule IDs from real audit: ${x.rules?.length?x.rules.map(r=>r.rule_id||'(ID unavailable)').join(', '):'Not available / no rule evidence'}`;
   toast(`Observed HTTP ${x.http_status} — ${x.verdict}`);
 }));
}
function suricata(){
 $('page').innerHTML=intro('SECURITY PRACTICAL 03','Suricata — Network Security Camera','Suricata inspects network packets and raises alerts when rules match. The live sensor starts with CloudShield; turn it off when the ECS needs CPU resources.')+
 panel('Live monitoring controls',proof('<b>IDS = detects and alerts.</b> <b>IPS = actively drops traffic.</b> This v3 mode is a real live IDS monitoring the isolated toolbox network namespace; it does <b>not</b> claim to see the entire Huawei VPC or perform inline IPS drops.')+
 '<div class="actions"><button class="btn primary" id="idsStart">▶ Start sensor</button><button class="btn warn" id="idsStop">■ Stop sensor (save CPU)</button><button class="btn" id="idsRefresh">↻ Refresh live alerts</button><button class="btn safe" id="idsTrigger">Send harmless suspicious test message</button></div><div id="idsState" class="notice">Checking engine…</div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Sending IP</th><th>Rule triggered</th><th>Action</th></tr></thead><tbody id="idsRows"><tr><td colspan="4">No live alert yet.</td></tr></tbody></table></div><div class="result" id="idsOut">Live IDS reports only actual Suricata engine events.</div>')+
 panel('Advanced lab · Actual inline IPS (optional)',proof('This is a separate NFQUEUE security experiment confined to toolbox TCP port 8096. It never changes the host firewall, ECS SSH or the main dashboard. If Huawei ECS kernel NFQUEUE support is missing, the page reports the real error and leaves IPS disabled.')+
 '<div class="actions"><button id="ipsStart" class="btn primary">Start isolated IPS</button><button id="ipsNormal" class="btn">Send normal request</button><button id="ipsAttack" class="btn warn">Send harmless blocked-pattern request</button><button id="ipsStop" class="btn safe">Stop IPS</button></div><div class="result" id="ipsOut">IPS is off by default; first click Start isolated IPS.</div>')+
 panel('Historical packet capture lab',step('1','Look at a stored capture','A PCAP is like a recording of old network traffic.')+step('2','Run Suricata against it','The real engine reads the file and searches for a harmless signature.')+'<div class="actions"><button class="btn" id="runPcap">Inspect saved PCAP</button></div><div class="result" id="pcapOut">No offline scan run.</div>')+
 panel('Before moving to IPS',proof('True inline IPS needs an explicit forwarding path, suitable kernel privileges and verified packet drops. The live sensor here is **IDS only**. The application WAF and IP-guard demonstrate actual blocking elsewhere in this lab.'));
 const refresh=async()=>{let r=await api('/api/v3/ids/status');$('idsState').textContent=r.running?'🟢 Live monitoring ON — toolbox eth0':'🔴 Monitoring OFF — traffic is not being inspected. '+(r.last_error||'');let arr=r.alerts||[];$('idsRows').innerHTML=arr.length?arr.slice(-25).reverse().map(a=>`<tr><td>${esc(a.timestamp)}</td><td class="mono">${esc(a.src_ip)}</td><td>${esc(a.signature)} (SID ${esc(a.sid)})</td><td>${esc(a.action||'alert')}</td></tr>`).join(''):'<tr><td colspan="4">No live Suricata events matching lab rules yet.</td></tr>';return r};
 $('idsStart').onclick=e=>perform(e.target,async()=>{result('idsOut',await post('/api/v3/ids/start'));await refresh()});
 $('idsStop').onclick=e=>perform(e.target,async()=>{result('idsOut',await post('/api/v3/ids/stop'));await refresh()});
 $('idsRefresh').onclick=e=>perform(e.target,refresh);
 $('idsTrigger').onclick=e=>perform(e.target,async()=>{let r=await post('/api/v3/ids/generate');result('idsOut',r);await refresh()});
 $('runPcap').onclick=e=>perform(e.target,async()=>result('pcapOut',await post('/api/tools/suricata/run')));
 $('ipsStart').onclick=e=>perform(e.target,async()=>result('ipsOut',await post('/api/v3/ips/start')));
 $('ipsStop').onclick=e=>perform(e.target,async()=>result('ipsOut',await post('/api/v3/ips/stop')));
 $('ipsNormal').onclick=e=>perform(e.target,async()=>result('ipsOut',await api('/api/v3/ips/probe?attack=0')));
 $('ipsAttack').onclick=e=>perform(e.target,async()=>result('ipsOut',await api('/api/v3/ips/probe?attack=1')));
 refresh().catch(e=>result('idsOut',e.message));
}
function clamav(){
 $('page').innerHTML=intro('SECURITY PRACTICAL 04','ClamAV Antivirus','Upload a harmless file or run a harmless antivirus test signature. The verdict comes from the real ClamAV daemon.')+
 panel('Check antivirus engine', '<div class="actions"><button id="clamPing" class="btn">Check ClamAV daemon</button><button id="clamEicar" class="btn primary">Scan harmless EICAR test string</button></div><div class="result" id="clamOut">Check daemon health, then test its detection.</div>')+
 panel('Scan your own safe file','<p>Choose a harmless text file, PDF or image (maximum 1 MiB). CloudShield sends it to ClamAV using the real scanning protocol.</p><div class="input-row"><label class="field">Select file<input type="file" id="clamFile"></label><button id="scanUpload" class="btn primary">Scan uploaded file</button></div><div class="result" id="uploadOut">No file submitted.</div>')+
 panel('Easy practical sequence',step('1','Check readiness','ClamAV downloads a signature database on first startup. It may need several minutes.')+step('2','Scan safe file','Expect a clean verdict from the daemon.')+step('3','Run EICAR','The EICAR string is harmless and deliberately matches antivirus signatures. Expect FOUND, not a fake warning.')+
 '<div class="notice warn">If daemon says not ready, inspect <code>sudo docker compose logs clamav</code>. The lab never fabricates a positive result. Use only instructor-approved harmless test files.</div>');
 $('clamPing').onclick=e=>perform(e.target,async()=>result('clamOut',await api('/api/tools/clamav/health')));
 $('clamEicar').onclick=e=>perform(e.target,async()=>{let r=await post('/api/tools/clamav/eicar');result('clamOut',r);toast(r.detected?'Real ClamAV EICAR detection confirmed':'EICAR not detected: inspect signatures',!r.detected)});
 $('scanUpload').onclick=e=>perform(e.target,async()=>{let f=$('clamFile').files[0];if(!f)throw Error('Select a file');if(f.size>1048576)throw Error('Max 1 MiB');const d=new FormData();d.append('file',f);let resp=await fetch('/target/upload',{method:'POST',body:d});let obj=await resp.json();result('uploadOut',obj);if(resp.status!==200&&resp.status!==422)throw Error(obj.detail||'Scan failed');toast('Real scan result: '+obj.scan)});
}
function k6(){
 $('page').innerHTML=intro('PERFORMANCE PRACTICAL 05','Distributed k6 Load Testing','Pick an authorized website, choose real load-generating containers, set virtual users and duration, and watch actual request performance.')+
 panel('Step 1 · Choose destination',proof('Local mode uses Demo Store 1 on ECS1 and needs no ECS2. Remote mode sends requests to a private IPv4 target such as Demo Store 2 on ECS2. The destination must be yours to test.')+
 '<div class="input-row"><label class="field">Target<select id="kMode"><option value="store">Demo Store 1 — same ECS</option><option value="remote">Other ECS — private IP</option></select></label><label class="field">Target private IPv4<input id="kIp" placeholder="192.168.1.25" value=""></label><label class="field">Port<input id="kPort" type="number" value="8081"></label><label class="field">Path<input id="kPath" value="/health"></label></div><div class="actions"><button id="kCheck" class="btn">Check remote ECS connection</button><button id="kSave" class="btn">Save remote target</button></div><div class="result" id="kTargetOut">You can test ECS1 without a remote IP.</div>')+
 panel('Step 2 · Configure safe traffic', '<div class="input-row"><label class="field">Total virtual users<input id="kUsers" type="number" value="6" min="1" max="100"></label><label class="field">Independent load containers<input id="kAgents" type="number" value="3" min="1" max="3"></label><label class="field">Duration in seconds<input id="kSeconds" type="number" value="20" min="5" max="120"></label><label class="field">Global request-rate cap (req/s)<input id="kRps" type="number" value="20" min="1" max="150"></label></div>'+proof('Example: 60 virtual users on 3 agents means 20 VUs per agent. They have distinct local container IPs; a remote ECS may see a shared NAT IP. Real Kubernetes Pods are available in the optional K3s deployment, not under ordinary Docker Compose.')+
 '<div class="actions"><button class="btn primary" id="kStart">Start genuine distributed test</button><button class="btn warn" id="kStop">Emergency stop all agents</button><button class="btn" id="kRefresh">Refresh real results</button></div><div class="result" id="kOut">No distributed job started.</div>')+
 panel('Classic one-ECS scenarios — still available','<p>These original real k6 scripts are preserved for the practical: normal traffic, shopping journey, controlled spike, repeated wrong logins, file downloads and WAF patterns.</p><div class="input-row"><label class="field">Built-in scenario<select id="classicProfile"><option value="normal">Normal API traffic</option><option value="store">Demo Store journey</option><option value="spike">Controlled traffic spike</option><option value="auth">Repeated failed demo logins</option><option value="transfer">File download traffic</option><option value="waf">WAF signature requests</option></select></label><label class="field">Virtual users (1–30)<input type="number" id="classicVus" value="3" min="1" max="30"></label><label class="field">Duration seconds (5–120)<input id="classicSeconds" type="number" value="10" min="5" max="120"></label></div><div class="actions"><button id="classicStart" class="btn primary">Run classic test</button><button id="classicStop" class="btn warn">Stop classic test</button><button id="classicStatus" class="btn">Read result</button></div><div class="result" id="classicResult">No classic load test run.</div>')+
 panel('Step 3 · Inspect agent evidence','<div class="table-wrap"><table><thead><tr><th>Worker</th><th>Execution</th><th>HTTP requests</th><th>p95 delay (ms)</th><th>Failure rate</th></tr></thead><tbody id="kAgentRows"><tr><td colspan="5">No measured results.</td></tr></tbody></table></div><p class="muted small">On the same ECS: workers have distinct container addresses. For a remote ECS: verify the IP seen by ECS2; standard NAT may show only the ECS1 node IP.</p>');
 const target=()=>({ip:$('kIp').value.trim(),port:Number($('kPort').value),path:$('kPath').value,protocol:'http'});
 $('kCheck').onclick=e=>perform(e.target,async()=>{if($('kMode').value!=='remote')throw Error('Select remote mode first');result('kTargetOut',await post('/api/v3/targets/check',target()))});
 $('kSave').onclick=e=>perform(e.target,async()=>{if($('kMode').value!=='remote')throw Error('Select remote mode first');result('kTargetOut',await post('/api/v3/targets',target()))});
 $('kStart').onclick=e=>perform(e.target,async()=>{let out=await post('/api/v3/load/start',{...target(),mode:$('kMode').value,vus:Number($('kUsers').value),agents:Number($('kAgents').value),seconds:Number($('kSeconds').value),max_rps:Number($('kRps').value)});result('kOut',out);toast('Real worker processes started');await refreshAgents()});
 $('kStop').onclick=e=>perform(e.target,async()=>{result('kOut',await post('/api/v3/load/stop'));await refreshAgents()});
 $('kRefresh').onclick=e=>perform(e.target,refreshAgents);
 $('classicStart').onclick=e=>perform(e.target,async()=>{result('classicResult',await post('/api/runs',{profile:$('classicProfile').value,vus:Number($('classicVus').value),seconds:Number($('classicSeconds').value)}))});
 $('classicStop').onclick=e=>perform(e.target,async()=>result('classicResult',await post('/api/runs/stop')));
 $('classicStatus').onclick=e=>perform(e.target,async()=>{const all=await api('/api/runs');result('classicResult',all.length?await api('/api/runs/'+all[0].id):'No classic tests yet')});

 async function refreshAgents(){let x=await api('/api/v3/load/status');if(x.run){$('kAgentRows').innerHTML=x.agents.map(a=>{let m=a.summary?.metrics||{};let d=m.http_req_duration?.values||{};return `<tr><td>${esc(a.agent)}</td><td>${esc(a.state||a.error)}</td><td>${esc(m.http_reqs?.values?.count??'—')}</td><td>${esc(d['p(95)']?.toFixed?.(1)??'—')}</td><td>${esc(m.http_req_failed?.values?.rate!==undefined?(100*m.http_req_failed.values.rate).toFixed(1)+'%':'—')}</td></tr>`}).join('');result('kOut',{run:x.run,agents:x.agents.map(a=>({agent:a.agent,state:a.state,metrics:a.summary?.metrics?Object.keys(a.summary.metrics):[]}))})}}
 refreshAgents().catch(()=>{});setInterval(()=>{if($('kAgentRows'))refreshAgents().catch(()=>{})},5000);
}
async function refreshK6(){const arr=await api('/api/runs');if(!$('kRows'))return;$('kRows').innerHTML=arr.length?arr.map(r=>`<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.profile)}</td><td>${r.vus}</td><td>${esc(r.status)}</td><td>${utc(r.started)}</td></tr>`).join(''):'<tr><td colspan="5">No runs yet</td></tr>';
 if(arr.length){let last=await api('/api/runs/'+arr[0].id);let m=last.summary?.metrics||{}; $('kReq').textContent=m.http_reqs?.values?.count??'—';$('kP95').textContent=m.http_req_duration?.values?.['p(95)']?.toFixed?.(1)??'—';$('kErr').textContent=m.http_req_failed?.values?.rate!==undefined?(100*m.http_req_failed.values.rate).toFixed(1)+'%':'—';result('kOut',last.status==='running'?`Actual job ${last.id} running. Refresh for final measurements.`:`Run ${last.id} — ${last.status}\nExit code: ${last.exit_code}\n`+JSON.stringify(m,null,2).slice(0,4600));}}
function iperf3(){
 $('page').innerHTML=intro('NETWORK PRACTICAL 06','iperf3 Real Network Speed','Test the local Docker bridge or measure TCP/UDP throughput to a genuine iperf3 receiver on another ECS. The remote ECS must have iperf3 server running on its selected port.')+
 panel('Choose a network destination',proof('Local Docker-to-Docker traffic is NOT Huawei VPC throughput. For cross-ECS speed choose Remote and install the included ECS2 target package; open port 5201 TCP/UDP in its security group only to ECS1.')+
 '<div class="input-row"><label class="field">Destination<select id="iperfMode"><option value="local">Local test server (ECS1)</option><option value="remote">Remote ECS2 private IP</option></select></label><label class="field">Remote IPv4<input id="iperfIp" placeholder="192.168.1.25"></label><label class="field">iperf3 port<input id="iperfPort" type="number" value="5201"></label></div>')+
 panel('Configure the measurement','<div class="input-row"><label class="field">Protocol<select id="iperfProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label class="field">Direction<select id="iperfDirection"><option value="upload">ECS1 → Receiver</option><option value="download">Receiver → ECS1</option><option value="both">Both directions</option></select></label><label class="field">Seconds<input id="iperfDuration" type="number" min="2" max="30" value="5"></label><label class="field">Parallel streams<input id="iperfStreams" type="number" min="1" max="4" value="1"></label><label class="field">UDP bitrate cap (Mbps)<input id="iperfMbps" type="number" min="1" max="100" value="10"></label></div><div class="actions"><button class="btn primary" id="iperfStart">Run real iperf3 transfer</button></div><div class="metric-list"><div class="metric"><b id="iperfSpeed">—</b><small>Measured receiver speed (Mbps)</small></div><div class="metric"><b id="iperfBytes">—</b><small>Measured bytes sent</small></div><div class="metric"><b id="iperfRetrans">—</b><small>TCP retransmissions</small></div></div><div class="result" id="iperfOut">No measured throughput yet.</div>')+
 panel('How students interpret results',step('1','TCP vs UDP','TCP reports throughput and possible retransmissions. UDP can report jitter and packet loss.')+step('2','Local vs remote','Same-ECS Docker bridge speed may be very different from ECS1 ↔ ECS2 private VPC speed.')+step('3','Verify the remote receiver','An HTTP server on port 8081 is NOT an iperf3 server. The iperf receiver runs on TCP/UDP 5201.'));
 $('iperfStart').onclick=e=>perform(e.target,async()=>{
   const remote=$('iperfMode').value==='remote'; const payload={ip:remote?$('iperfIp').value.trim():'',port:Number($('iperfPort').value),seconds:Number($('iperfDuration').value),protocol:$('iperfProtocol').value,direction:$('iperfDirection').value,streams:Number($('iperfStreams').value),mbps:Number($('iperfMbps').value)};
   result('iperfOut','Actual iperf3 is running. No simulated results are displayed.');
   const data=remote?await post('/api/v3/iperf3',payload):await post('/api/v3/iperf3',{...payload,ip:''});
   $('iperfSpeed').textContent=data.receiver_mbps??'—';$('iperfBytes').textContent=data.bytes_sent??'—';$('iperfRetrans').textContent=data.retransmits??'—';result('iperfOut',data);toast('Real measurement complete');
 });
}
function prometheus(){
 const opts=[
 ['sum(rate(cloudshield_requests_total[1m]))','Live HTTP requests per second'],
 ['cloudshield_active_bans','Active application-layer IP bans'],
 ['sum(rate(cloudshield_blocks_total[5m]))','Live HTTP blocking rate'],
 ['cloudshield_k6_last_requests_per_second','Last actual k6 requests per second'],
 ['100-100*avg(rate(node_cpu_seconds_total{mode="idle"}[2m]))','ECS CPU usage percent'],
 ['node_memory_MemAvailable_bytes','ECS memory available bytes'],
 ['up','Are scrape targets working? (1 = yes)']
 ];
 $('page').innerHTML=intro('OBSERVABILITY PRACTICAL 07','Prometheus Metrics','Run actual PromQL queries against the time-series database and inspect whether real services are being scraped.')+
 panel('Inspect live scrape targets','<p class="muted">A working Prometheus collector periodically asks CloudShield and node-exporter for real metrics. Look for <b>UP</b> targets and investigate any DOWN result.</p><div class="actions"><button class="btn primary" id="promTargets">Query real scrape targets</button></div><div class="result" id="promTargetOut">Not queried yet.</div>')+
 panel('Run real PromQL', '<div class="input-row"><label class="field" style="flex:1;min-width:230px">Choose a sample query<select id="promSamples"><option value="">Select sample query</option>'+opts.map(([q,title])=>`<option value="${esc(q)}">${title}</option>`).join('')+'</select></label></div><label class="field" style="width:100%">PromQL expression (editable)<input id="promExpr" maxlength="180" placeholder="cloudshield_active_bans" value="cloudshield_active_bans"></label><div class="actions"><button class="btn primary" id="promRun">Execute actual Prometheus query</button><a class="btn" href="/tool/grafana">Open Grafana charts →</a></div><div class="result" id="promOut">Choose or edit PromQL, then execute. Empty result is valid if no matching samples exist.</div>')+
 panel('Student practical',step('1','Check scrape status','Read labels, last scrape and any errors from the real Prometheus targets API.')+step('2','Run a simple metric','Query cloudshield_active_bans, then ban the real toolbox IP and run it again.')+step('3','Run a rate expression','Generate k6 traffic and query a per-second HTTP request rate.')+step('4','Explain empty results','Not every metric exists before the first operation or first scrape; No data is not zero.'));
 $('promSamples').onchange=()=>{if($('promSamples').value)$('promExpr').value=$('promSamples').value};
 $('promTargets').onclick=e=>perform(e.target,async()=>result('promTargetOut',await api('/api/tools/prometheus/targets')));
 $('promRun').onclick=e=>perform(e.target,async()=>result('promOut',await post('/api/tools/prometheus/query',{query:$('promExpr').value.trim()})));
}
const dashboards=[['01-overview','Mission Control','HTTP activity, blocks, active labs, CPU'],['02-crowdsec','IP Enforcement','Real guard counters and CrowdSec-enforced request outcomes'],['03-coraza','Coraza WAF','Preset request results and live backend activity'],['04-suricata','Suricata IDS','Actual offline IDS alert counts and related network metrics'],['05-clamav','ClamAV Antivirus','Live scan outcomes and host resource use'],['06-k6','k6 Load Testing','Measured virtual users, latency, error rate and traffic'],['07-iperf3','iperf3 Throughput','Docker bridge throughput and host packet rates'],['08-infrastructure','ECS Infrastructure','Host CPU, memory, disks, network, load and uptime'],['09-distributed','Distributed k6 Agents','Three independent load workers and real traffic'],['10-vpc','Cross-ECS Monitoring','ECS2 CPU, RAM, network and iperf throughput'],['11-soc','Live Security SOC','IDS, banned IPs and WAF activity']];
function grafana(){
 $('page').innerHTML=intro('OBSERVABILITY PRACTICAL 07','Prometheus + Grafana','Eight original Grafana dashboards preserved, plus three dedicated v3 dashboards. Run a tool, then watch the graphs change.')+
 panel('Open dedicated Grafana dashboards',proof('All graphs query actual Prometheus samples; “No data” means nothing has been measured yet. Grafana is bound to <code>127.0.0.1:3000</code> on ECS—use the SSH tunnel shown in the student guide.')+
 '<div class="dashlinks">'+dashboards.map(([uid,label,desc])=>`<a class="dashlink" target="_blank" rel="noopener" href="http://localhost:3000/d/cs2-${uid}/cloudshield"><span>${label}<small class="muted" style="display:block;font-weight:400">${desc}</small></span>↗</a>`).join('')+'</div>')+
 panel('What is collected?', '<div class="two"><div>'+step('1','Prometheus collects','It requests real metric counters from CloudShield and the ECS node exporter every five seconds.')+step('2','Grafana displays','It turns those measurements into charts and lets you inspect time ranges.')+'</div><div>'+step('3','Use paired tests','Run a k6 traffic spike, then open the k6 dashboard and the ECS infrastructure dashboard.')+step('4','Identify bottlenecks','Compare real request delays, CPU, memory and network usage.')+'</div></div>')+
 panel('Prometheus debugging commands','<div class="result">sudo docker compose ps prometheus grafana node-exporter\nsudo docker compose logs --tail 60 prometheus grafana\ncurl -s http://127.0.0.1:9090/api/v1/targets</div>');
}
function store(){
 $('page').innerHTML=intro('PROTECTED APPLICATION','KooLab Demo Store','An actual working practice web app. The store sits behind Coraza and the application-layer ban checker.')+
 panel('Open protected store','<p>Browse six demo products, search by name, add products to your cart, place a dummy order, trigger bounded delays, request APIs and download sample files.</p><div class="actions"><a class="btn primary" href="/target/store" target="_blank" rel="noopener">Open KooLab Demo Store ↗</a><a class="btn" href="/target/store/api/products" target="_blank" rel="noopener">Open products API ↗</a><a class="btn" href="/tool/k6">Run a shopping journey test →</a></div>')+
 panel('Classroom experiment',step('1','Browse products','Open the store and check the catalog returns real JSON data.')+step('2','Generate load','Use k6 store journey with 5 virtual users and inspect latency, request rate and status codes.')+step('3','Test protection','Visit CrowdSec & IP Bans and temporarily block the separate test client, then use the live HTTP probe.')+step('4','Check Grafana','Watch network, CPU, memory and app metrics before and after traffic.'));
}
function guide(){
 $('page').innerHTML=intro('STUDENT HANDBOOK','Hands-on security and cloud performance exercises','Each tool has a separate page, a real executable operation and a verifiable outcome. Record observed status codes and raw data—not what you expected to see.')+
 panel('How to access',proof('After <code>sudo bash install.sh</code> on ECS, open an SSH tunnel from your workstation: <code>ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@ECS_PUBLIC_IP</code>. Then visit <code>http://localhost:8080</code>. No web password; never publish the control interface to the public internet.'))+
 panel('Suggested teaching sequence',[
 ['A','CrowdSec / IP Ban','Check unblocked response → ban test client → recheck HTTP 429 → release → recheck 200.'],
 ['B','Coraza WAF','Send normal and SQL-style probes and record real status codes.'],
 ['C','Suricata','Start or stop the real live sensor, create safe test traffic and check recorded alerts.'],
 ['D','ClamAV','Scan a safe file and then EICAR; record real daemon verdicts.'],
 ['E','k6','Use 1, 5, 10 VUs, then compare request p95, error ratios and CPU use.'],
 ['F','iperf3','Run 4-second real transfer and report Mbps plus retransmissions.'],
 ['G','Grafana','Inspect the original eight plus three new dashboards and explain any empty graphs.']].map(([n,t,d])=>step(n,t,d)).join(''))+
 panel('Evidence students should submit','<p>A screenshot of the specific tool page, the raw HTTP/engine result, a Grafana chart from the matching time period, and a 3-sentence conclusion explaining what was actually measured.</p><div class="actions"><a class="btn" href="/target/store" target="_blank">Open Demo Store ↗</a><a class="btn" href="/tool/overview">Return to all tools →</a></div>')+
 '<div class="notice warn">This is a controlled practical, not an unrestricted attack platform. Students cannot enter arbitrary target URLs; heavy load is bounded, and active packet sniffing is not enabled.</div>';
}

function remoteecs(){
 $('page').innerHTML=intro('REMOTE TARGET','ECS2 Live Telemetry','The optional target ECS sends real CPU, memory and network measurements to ECS1. No fabricated numbers and no remote agent required for local ECS1 labs.')+
 panel('Connected agent evidence','<div class="actions"><button id="telemetryRefresh" class="btn primary">Refresh genuine measurements</button></div><div class="result" id="telemetryOut">Awaiting real agent data.</div>')+
 panel('Deploy target server',step('1','Upload separate ECS2 ZIP','Install Demo Store 2, its iperf3 server and the outbound metrics agent on the second Ubuntu ECS.')+step('2','Connect by private VPC IP','Use the telemetry token shown by the ECS1 instructor-only command. Allow ECS2 access to ECS1 port 9108 only.')+step('3','Test remotely','Open k6 or iperf3 pages on ECS1, enter the ECS2 private IP and perform a bounded test.')+proof('No agent status means there is no confirmed telemetry yet. ECS2 data requires correct token and Huawei security-group rules.'));
 const refresh=async()=>result('telemetryOut',await api('/api/v3/telemetry'));
 $('telemetryRefresh').onclick=e=>perform(e.target,refresh);refresh().catch(()=>{});
}

const pages={overview,crowdsec,waf,suricata,clamav,k6,iperf3,prometheus,grafana,store,guide,remoteecs};
const current=pages[pageName]||overview;
$('topTitle').textContent=names[pageName]||'CloudShield Operations';
document.querySelectorAll('[data-page]').forEach(a=>{if(a.dataset.page===pageName)a.classList.add('active')});
$('reloadBtn').onclick=()=>location.reload();
current();
async function healthTop(){try{let r=await api('/healthz');$('topStatus').textContent='Core API online · v'+r.version;$('topPulse').className='status-pulse ok'}catch(e){$('topStatus').textContent='Core API unreachable';$('topPulse').className='status-pulse';}}
healthTop();setInterval(healthTop,15000);
