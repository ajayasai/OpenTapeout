'use strict';
function populateControls(){
  for(const id of ['plan-change','compare-before','compare-after']){
    const select=$(id),previous=select.value;select.replaceChildren();
    if(id==='plan-change'){const none=elem('option','Observed changes only');none.value='';select.append(none);state.resources.forEach(r=>{const o=elem('option','What if '+r.id+' changes?');o.value=r.id;select.append(o);});}
    else state.candidates.forEach(c=>{const o=elem('option',c.name);o.value=c.name;select.append(o);});
    if([...select.options].some(o=>o.value===previous))select.value=previous;
    else if(id==='compare-after' && candidate())select.value=candidate().name;
  }
}
async function renderPlan(){
  try{
    const params=new URLSearchParams();if(candidate())params.set('name',candidate().name);params.set('changed',$('plan-change').value);
    const data=await api('/api/plan?'+params.toString());
    text('plan-summary',`${data.summary.reusable_checks} of ${data.summary.required_checks} checks have reusable evidence. ${data.summary.resource_tasks} resource tasks. This plan does not authorize release.`);
    clear('plan-resources').append(table(['Wave','Resource','Action','Reason path'],data.resource_tasks.map(t=>({cells:[t.wave,t.resource,t.action.replaceAll('_',' '),t.reason_path.join(' → ')]}))));
    if(!data.resource_tasks.length)$('plan-resources').append(elem('p','No resource rebuilds identified from declared dependencies. Check evidence freshness and approvals separately.','empty'));
    clear('plan-checks').append(table(['Check / corner','Recommended action','Affected inputs','Other blockers'],data.checks.map(c=>({cells:[c.check,c.action.replaceAll('_',' '),c.affected_inputs.join(', ')||'—',c.blockers.map(b=>b.code).join(', ')||'—']}))));
  }catch(e){failure(e);}
}
async function renderComparison(){
  try{
    const a=$('compare-before').value,b=$('compare-after').value;if(!a||!b)return;
    const data=await api('/api/compare/'+encodeURIComponent(a)+'/'+encodeURIComponent(b));
    text('comparison-summary',`${data.resources.length} changed resources. Policy ${data.policy_changed?'changed':'unchanged'}. Numeric deltas require unit and threshold interpretation.`);
    clear('comparison-metrics').append(table(['Check / corner','Metric','Before','After','Delta'],data.metric_deltas.map(m=>({cells:[m.check,m.metric,m.before??'—',m.after??'—',m.delta??'—']}))));
  }catch(e){failure(e);}
}
function renderLifecycle(){
  const hash=candidate()?.sha256;
  const deliveries=(state.delivery_capsules||[]).filter(d=>d.candidate_sha256===hash);
  const receipts=state.signed_receipts||[];
  clear('delivery-list').append(table(['Delivery','Designated recipient','Archive SHA-256','Acknowledgment'],deliveries.map(d=>({cells:[d.id,d.recipient,short(d.archive_sha256),receipts.some(r=>r.payload.delivery_id===d.id)?'Recipient signed':'Not recorded']}))));
  if(!deliveries.length)$('delivery-list').append(elem('p','No minimal delivery capsules for this candidate. Use the disclosure and deliver CLI commands after sealing.','empty'));
  const withdrawals=(state.withdrawals||[]).filter(w=>w.payload.candidate_sha256===hash);
  text('withdrawal-state',withdrawals.length?'WITHDRAWN — '+withdrawals.map(w=>w.payload.reason).join('; '):'No withdrawal recorded for this candidate in this workspace. Offline status snapshots have explicit expiry.');
}
$('plan-run').addEventListener('click',renderPlan);
$('compare-run').addEventListener('click',renderComparison);
