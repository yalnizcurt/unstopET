"""Trusted run correlation. Outcomes are observations, never model assertions."""
from datetime import datetime, timezone
import secrets

class RunEvents:
    def __init__(self, run_id, integration_id, agent_id):
        self.run_id=run_id; self.integration_id=integration_id; self.agent_id=agent_id; self.events=[]
    def record(self, stage, operation, decision, **details):
        event=dict(details,event_id=secrets.token_hex(16),run_id=self.run_id,integration_id=self.integration_id,
            agent_id=self.agent_id,stage=stage,operation=operation,decision=decision,result=decision,
            policy_version=2,created_at=datetime.now(timezone.utc).isoformat(),sequence=len(self.events)+1)
        self.events.append(event)
        return event
    def broker(self,event):
        stages={'model.generate':'MODEL_RESPONSE','tools.collect':'TOOL_COLLECTION','tools.invoke':'TOOL_RESULT',
                'email.prepare':'ACTION_AUTHORIZATION','email.dispatch':'ACTION_EXECUTION','finalize':'OUTPUT_RELEASE','runtime.stop':'RUNTIME_STOP'}
        details={key:value for key,value in event.items() if key not in
                 ('event_id','principal','task','time','budget','stage','operation','result','policy_version','created_at')}
        if 'reason' in details: details['reason_code']=details['reason']
        return self.record(stages.get(event['operation'],event['stage']),event['operation'],event['result'],**details)


def security_summary(run):
    timeline=run.get('timeline',[])
    return dict(run_id=run['id'],integration_id=run.get('integration_id',run.get('agent_id')),
        status=run['status'],output_released=run['status']=='COMPLETED',
        legitimate_task_success=None,utility_note='Output release is recorded; business correctness requires independent evaluation',
        inspected_artifacts=len(run.get('artifacts',[])),
        threat_fragments=sum(bool(f['signals']) for a in run.get('artifacts',[]) for f in a['fragments']),
        incomplete_artifacts=sum(a['inspection_status']!='COMPLETE' for a in run.get('artifacts',[])),
        model_requests=sum(e['stage']=='MODEL_REQUEST' for e in timeline),
        tool_requests=sum(e['stage']=='TOOL_REQUEST' for e in timeline),
        denied_actions=[e for e in timeline if e['stage']=='ACTION_AUTHORIZATION' and e['decision']=='DENY'],
        mock_emails_executed=run.get('emails_executed',0),
        containment_probe=run.get('containment_probe'),memory='DISABLED',
        retention='24-hour temporary demo records; absent/expired IDs are denied')
