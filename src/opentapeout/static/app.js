'use strict';
const $ = id => document.getElementById(id);
let state = null, selected = null, token = '', currentView = 'overview';
const seedNode = $('offline-data');
const offline = seedNode ? JSON.parse(seedNode.textContent) : null;
const text = (id, value) => { $(id).textContent = String(value); };
const elem = (tag, content, className) => { const node = document.createElement(tag); if (content !== undefined) node.textContent = String(content); if (className) node.className = className; return node; };
const short = value => value ? value.slice(0, 12) + '…' : '—';
const clear = id => { $(id).replaceChildren(); return $(id); };
async function api(path) {
  if (offline) {
    if (Object.hasOwn(offline, path)) return structuredClone(offline[path]);
    throw new Error('This offline review does not contain ' + path);
  }
  const response = await fetch(path, {headers: token ? {Authorization:'Bearer ' + token} : {}, cache:'no-store'});
  if (response.status === 401) { $('auth').classList.remove('hidden'); throw new Error('Enter your API token to view this workspace.'); }
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function failure(error) { text('error', error.message); $('error').classList.remove('hidden'); }
function pill(status) { return elem('span', status.toUpperCase(), 'pill ' + status); }
function table(headers, rows) {
  const wrap = elem('div', undefined, 'table-wrap'), t = elem('table'), head = elem('thead'), hr = elem('tr'), body = elem('tbody');
  headers.forEach(h => hr.append(elem('th', h))); head.append(hr);
  rows.forEach(row => { const tr = elem('tr'); row.cells.forEach(c => { const td = elem('td'); td.append(c instanceof Node ? c : document.createTextNode(String(c))); tr.append(td); }); if(row.click){tr.className='clickable';tr.tabIndex=0;tr.addEventListener('click',row.click);tr.addEventListener('keydown', e=>{if(e.key==='Enter')row.click();});} body.append(tr); });
  t.append(head,body);wrap.append(t);return wrap;
}
function candidate() { return state.candidates.find(c => c.name === selected) || state.candidates.at(-1); }
function render() {
  const c = candidate();
  if (!c) { text('gate-heading','No candidates yet'); text('gate-description','Create a candidate with the CLI to start release review.'); return; }
  selected = c.name;
  const g = c.gate;
  text('project-name',state.project.name); text('project-label',state.project.name.replace(' • SYNTHETIC DEMO',''));
  $('demo-pill').classList.toggle('hidden', !state.synthetic);
  text('digest-short', short(c.sha256));
  const sel = clear('candidate-select'); state.candidates.forEach(x => {const o = elem('option', x.name);o.value=x.name;sel.append(o);});sel.value=selected;
  $('gate-banner').classList.toggle('blocked', !g.ready);text('gate-symbol', g.ready ? '✓' : '!');
  text('gate-heading',g.ready ? 'This candidate satisfies the configured release gate.' : 'Release blocked. Evidence no longer matches the design.');
  text('gate-description',g.ready ? 'Input fingerprints, required checks, artifact integrity and reviewer signatures are valid.' : `${g.blockers.length} blocking condition${g.blockers.length === 1 ? '' : 's'}. Rebuild affected evidence before approving a new candidate.`);
  const badge = $('gate-badge');badge.className='pill '+(g.ready?'pass':'blocked');badge.textContent=g.ready?'READY TO SEAL':'REVIEW REQUIRED';
  const passed=g.checks.filter(x=>x.status==='pass').length;
  text('metric-checks',`${passed} / ${g.checks.length}`);text('metric-resources',state.resources.length);
  text('metric-approvals',Object.keys(g.approval_assignment).length);text('metric-events',state.checkpoint.seq);
  text('nav-count',state.runs.length);text('checks-pill',`${g.checks.length} REQUIRED`);
  clear('checks-table').append(table(['Check / corner','Evidence','State'],g.checks.map(check=>({cells:[check.check,short(check.run_id),pill(check.status)],click:()=>{show('evidence');showRun(check.run_id);}}))));
  const contract=clear('contract');
  [['Candidate owner',c.created_by],['Delivery files',c.deliveries.map(d=>d.name).join(', ')||'No delivery bound'],['Approval assignment',Object.entries(g.approval_assignment).map(([r,p])=>`${r}: ${p}`).join(' · ')||'Not yet satisfied'],['Release notes',c.notes]].forEach(([label,value])=>{const row=elem('div',undefined,'contract-row');row.append(elem('label',label),elem('p',value));contract.append(row);});
  const blockers=clear('blockers');
  if(!g.blockers.length){text('blocker-title','All release gates satisfied');blockers.append(elem('div','✓ No blockers detected. This is a ledger policy decision, not proof of physical signoff or foundry acceptance.','success-note'));}
  else {text('blocker-title',`Release blockers (${g.blockers.length})`);g.blockers.forEach(b=>{const row=elem('div',undefined,'blocker-row'),content=elem('div');content.append(elem('strong',`${b.code} · ${b.scope}`),elem('p',b.message));row.append(elem('span','!','blocker-dot'),content);blockers.append(row);});}
  renderEvidence();renderResources();renderApprovals();text('ledger-head',short(state.checkpoint.hash));
  text('last-updated',offline?'Offline synthetic review snapshot':'Updated '+new Date().toLocaleTimeString());
}
function renderEvidence() {
 const q=$('search').value.toLowerCase();const rows=state.runs.filter(r=>[r.kind,r.corner,r.id,r.tool_spec.name].join(' ').toLowerCase().includes(q)).reverse();
 clear('evidence-list').append(table(['Check','Corner','Tool / version','Captured result','Run'],rows.map(r=>({cells:[r.kind,r.corner,r.tool_spec.name+' '+r.tool_spec.version,pill(r.result?.status||'incomplete'),short(r.id)],click:()=>showRun(r.id)}))));
}
function showRun(id){const r=state.runs.find(x=>x.id===id);text('run-detail',r?JSON.stringify(r,null,2):'No run is available for this check.');$('run-detail').classList.remove('hidden');}
function renderResources(){clear('resource-table').append(table(['Resource','Kind','Dependencies','Content SHA-256','State'],state.resources.map(r=>({cells:[r.id,r.kind,r.depends_on.join(', ')||'—',short(r.sha256),pill(r.workspace_drift?'drift':r.stale_reasons.length?'stale':'fresh')],click:()=>showImpact(r.id)}))));}
async function showImpact(id){try{const data=await api('/api/impact/'+encodeURIComponent(id));const box=clear('impact-detail');box.classList.remove('hidden');const heading=elem('div',undefined,'card-heading');heading.append(elem('h2','Downstream impact of '+id));box.append(heading);if(!data.downstream.length)box.append(elem('p','No derived resources depend on this node.','empty'));data.downstream.forEach(d=>box.append(elem('div',d.path.join(' → '),'impact-path')));box.append(elem('div',data.affected_runs.length+' evidence runs bind this resource or its dependents.','success-note'));}catch(e){failure(e);}}
function renderApprovals(){const c=candidate(), approvals=clear('approval-list');state.approvals.forEach(a=>{const row=elem('div',undefined,'identity');row.append(elem('strong',a.payload.role+' reviewer'),pill(a.payload.candidate_sha256===c.sha256?'signed':'old-scope'),elem('span','key '+short(a.key_id),'mono'),elem('p','Candidate '+short(a.payload.candidate_sha256)));approvals.append(row);});if(!state.approvals.length)approvals.append(elem('p','No signed approvals yet.','empty'));const waivers=clear('waiver-list');state.waivers.forEach(w=>{const row=elem('div',undefined,'identity');row.append(elem('strong',w.payload.owner),elem('p',w.payload.rationale),elem('span','Expires '+w.payload.expires_at,'mono'));waivers.append(row);});if(!state.waivers.length)waivers.append(elem('p','No waivers recorded. No violations are silently excluded.','empty'));}
const titles={overview:['Release overview','Every result. The right revision.'],evidence:['Signoff evidence','Evidence you can trace.'],dependencies:['Dependencies','Know what a change invalidates.'],approvals:['Approvals & waivers','Accountability, bound to content.'],audit:['Audit ledger','A verifiable history of decisions.']};
async function show(view){currentView=view;document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!==view));document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===view));text('breadcrumb',titles[view][0]);text('view-title',titles[view][1]);if(view==='audit'){try{const data=await api('/api/audit');clear('audit-list').append(table(['Sequence','Event','Actor','Time','Event hash'],data.events.slice().reverse().map(e=>({cells:[e.seq,e.type,e.actor,e.at.replace('T',' ').slice(0,19),short(e.hash)]}))));}catch(e){failure(e);}}}
async function load(){try{state=await api('/api/summary');$('error').classList.add('hidden');$('auth').classList.add('hidden');render();if(currentView==='audit')await show('audit');}catch(e){failure(e);}}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>show(n.dataset.view)));
$('candidate-select').addEventListener('change',e=>{selected=e.target.value;render();});$('search').addEventListener('input',()=>state&&renderEvidence());$('refresh').addEventListener('click',load);$('connect').addEventListener('click',()=>{token=$('token').value;$('token').value='';load();});
$('export-json').addEventListener('click',()=>{if(!state)return;const url=URL.createObjectURL(new Blob([JSON.stringify(state,null,2)],{type:'application/json'}));const a=elem('a');a.href=url;a.download='opentapeout-review.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
load();
