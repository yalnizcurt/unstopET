"""Versioned security platform API. All agent execution uses the existing sealed Linux path."""
import base64
from contextlib import asynccontextmanager
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from agents import PROFILES, REPOSITORY
from firewall import Binding, Denied, Firewall, text, redact_known_secrets
from gate1 import run_runtime, verify_linux_boundary
from groq_ai import GroqProvider
from inspection import MANIFEST, inspect
from network import fetch_public
from parsing import parse_file
from semantic import PromptGuard
from storage import Store
from integrations import catalog, registration, describe, verification
from runtime_events import RunEvents, security_summary
from runtime_tools import PROFILE_TOOLS, TOOLS, TURN_INSTRUCTIONS, score_suppliers

class Strict(BaseModel): model_config=ConfigDict(extra='forbid',strict=True)
class Upload(Strict):
    filename: str = Field(min_length=1,max_length=180)
    data: str = Field(min_length=1,max_length=1_400_000)
class Task(Strict):
    agent_id: Literal['procurement','research','developer']
    intent: str = Field(min_length=1,max_length=8000)
    evidence: list[str] = Field(default_factory=list,max_length=8)
    artifact_ids: list[str] = Field(default_factory=list,max_length=8)
    urls: list[str] = Field(default_factory=list,max_length=2)
    use_demo_repository: bool = False
    session_id: str | None = None
    integration_id: str | None = Field(default=None,max_length=60)
    containment_probe: bool = False
class LegacyTask(Strict):
    intent: str = Field(min_length=1,max_length=8000)
    evidence: list[str] = Field(min_length=1,max_length=8)
class Attack(Strict):
    agent_id: Literal['procurement','research','developer']='procurement'
    scenario: str = Field(max_length=60)
    surface: Literal['text','html','pdf','docx','xlsx','zip']='text'


def create_app(access_token, provider_factory, origins, store=None, parser=parse_file, runner=run_runtime,
               verify=True, semantic_enabled=False):
    if store is None:
        store=Store(os.environ.get('ATF_DB_PATH','/tmp/atf-history.sqlite3'))
        archive=Path(__file__).with_name('cloud-evaluation-report.json')
        if archive.is_file():
            measured=json.loads(archive.read_text())
            for record in measured.get('results',[]):
                if record.get('results') and record.get('id') and not store.get(record['id'],'evaluation'):
                    store.put('evaluation',dict(record,origin='ARCHIVED_MEASURED_RUN',
                        scope=record['scope']+' Archived measurement from '+str(measured.get('backend_commit'))+'.'),record_id=record['id'])
    work=threading.Lock(); attempts=[]
    @asynccontextmanager
    async def lifespan(app):
        if verify: verify_linux_boundary()
        yield
    app=FastAPI(title='Agent Trust Firewall',version='1.0.0',lifespan=lifespan,docs_url='/api/docs',redoc_url=None,openapi_url='/api/openapi.json')
    app.state.store=store
    @app.middleware('http')
    async def boundary(request: Request, call_next):
        origin=request.headers.get('origin')
        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
        if origin in origins:
            headers.update({'Access-Control-Allow-Origin':origin,'Vary':'Origin'})
        if origin and origin not in origins: return JSONResponse({'error':'ORIGIN_DENIED'},403)
        if request.method=='OPTIONS':
            headers.update({'Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type'})
            return JSONResponse({},200,headers=headers)
        if request.url.path not in ('/api/health','/api/v1/health','/api/docs','/api/openapi.json'):
            if not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+access_token).encode()):
                return JSONResponse({'error':'AUTHENTICATION_REQUIRED'},401,headers=headers)
            if request.method=='POST':
                try: length=int(request.headers.get('content-length','0'))
                except ValueError: length=0
                if not 1<=length<=1_500_000 or request.headers.get('content-type','').split(';')[0]!='application/json':
                    return JSONResponse({'error':'INVALID_REQUEST_BODY'},413,headers=headers)
        try: result=await call_next(request)
        except Exception: result=JSONResponse({'error':'REQUEST_UNAVAILABLE'},503)
        result.headers.update(headers); return result
    @app.exception_handler(Denied)
    async def deny(request, error): return JSONResponse({'error':error.code},422)
    from fastapi.exceptions import RequestValidationError
    @app.exception_handler(RequestValidationError)
    async def invalid(request,error): return JSONResponse({'error':'INVALID_FIELDS_OR_LIMITS'},422)

    def enter():
        if not work.acquire(blocking=False): raise Denied('BUSY_TRY_AGAIN')
        now=time.monotonic(); attempts[:]=[t for t in attempts if now-t<60]
        if len(attempts)>=15: work.release(); raise Denied('REQUEST_BUDGET_EXHAUSTED')
        attempts.append(now)
    def guard(provider): return PromptGuard(provider) if semantic_enabled and provider else None
    def inspection(name,raw,classifier,source_kind="USER_SUPPLIED_UNTRUSTED_CONTENT",trace=None,tool_request_id=None):
        result=inspect(parser(name,raw),classifier)
        result["source_kind"]=source_kind
        saved=store.put('artifact',result)
        if trace:
            trace.record('ARTIFACT_INSPECTION','input.inspect',saved['decision'],source_artifact_id=saved['id'],
                source_fragment_ids=[f['id'] for f in saved['fragments']],inspection_status=saved['inspection_status'],
                uninspected_channels=saved['uninspected_channels'],tool_request_id=tool_request_id)
            flagged=[f for f in saved['fragments'] if f['signals'] or f['disposition']=='REQUIRE_REVIEW']
            for fragment in flagged:
                trace.record('THREAT_DETECTION','fragment.inspect',fragment['disposition'],source_artifact_id=saved['id'],
                    source_fragment_ids=[fragment['id']],location=fragment['location'],signals=fragment['signals'],
                    reason_code='INSPECTION_POLICY',tool_request_id=tool_request_id)
        for fragment in saved['fragments']:
            if not trace and (fragment['signals'] or fragment['disposition']=='REQUIRE_REVIEW'):
                store.put('event',dict(operation='input.inspect',result=fragment['disposition'],artifact_id=saved['id'],
                    location=fragment['location'],signals=fragment['signals'],reason='INSPECTION_POLICY',policy_version=2))
        return saved
    def add_evidence(firewall,binding,artifact,trace=None,tool_request_id=None):
        if artifact['inspection_status']=='UNSUPPORTED': raise Denied('UNSUPPORTED_ARTIFACT')
        released=[f for f in artifact['fragments'] if f['disposition'] in ('ALLOW','SANITIZE')]
        if not released: raise Denied('NO_RELEASED_FRAGMENTS')
        content='\n'.join(f"[{f.get('released_location',f['location'])}] {f['text']}" for f in released)
        evidence=firewall.import_text(binding,text(content),kind=artifact.get('source_kind','USER_SUPPLIED_UNTRUSTED_CONTENT'),inspected=True)
        firewall.grant_read(binding,evidence.id)
        artifact["context_source_id"]=evidence.id
        if trace:
            trace.record('EVIDENCE_RELEASE','context.release','ALLOW',source_artifact_id=artifact['id'],
                source_fragment_ids=[f['id'] for f in released],context_source_id=evidence.id,
                release_scope=artifact['release_scope'],tool_request_id=tool_request_id)
    def execute(body,provider,classifier,trace,state):
        started=time.monotonic()
        profile=PROFILES[body.agent_id]; inspected=state['artifacts']; tool_activity=state['tool_activity']
        if isinstance(provider,GroqProvider): provider.runtime_profile=body.agent_id
        integration=registration(body.integration_id or body.agent_id)
        if integration['agent_profile_id']!=body.agent_id: raise Denied('INTEGRATION_PROFILE_MISMATCH')
        if body.urls and body.agent_id!='research': raise Denied('TOOL_NOT_AUTHORIZED')
        if body.use_demo_repository and body.agent_id!='developer': raise Denied('TOOL_NOT_AUTHORIZED')
        if body.intent!=redact_known_secrets(body.intent) or any(url!=redact_known_secrets(url) for url in body.urls): raise Denied('SECRET_DISCLOSURE_DENIED')
        if body.session_id and not store.get(body.session_id,'session'): raise Denied('SESSION_ACCESS_DENIED')
        for i,value in enumerate(body.evidence): inspected.append(inspection(f'pasted-{i+1}.txt',text(value).encode(),classifier,trace=trace))
        for identity in body.artifact_ids:
            artifact=store.get(identity,'artifact')
            if not artifact: raise Denied('ARTIFACT_ACCESS_DENIED')
            trace.record('EVIDENCE_RECEIVED','artifact.reuse',artifact['decision'],source_artifact_id=artifact['id'],
                inspection_status=artifact['inspection_status'],inspection_created_at=artifact['created_at'])
            inspected.append(artifact)
        def collect(firewall,binding):
            for url in body.urls:
                trace.record('TOOL_REQUEST','public_https_read','PROPOSED',destination=url,origin='AUTHENTICATED_SOURCE_PLAN')
                raw,name=fetch_public(url)
                trace.record('ACTION_AUTHORIZATION','public_https_read','ALLOW',destination=url,reason_code='USER_SELECTED_PUBLIC_HTTPS')
                trace.record('TOOL_EXECUTION','public_https_read','ALLOW',destination=url,observed_execution=True)
                artifact=inspection(name,raw,classifier,'EXTERNAL_RETRIEVED_EVIDENCE',trace=trace)
                for f in artifact['fragments']:
                    f['released_location']=url+' '+f.get('released_location',f['location'])
                    f['location']=url+' '+f['location']
                add_evidence(firewall,binding,artifact,trace); inspected.append(artifact)
                tool_activity.append(dict(tool='public_https_read',destination=url,result='RELEASED_INSPECTED_FRAGMENTS',
                    inspection_status=artifact['inspection_status'],artifact_id=artifact['id']))
            if body.use_demo_repository:
                for name,value in REPOSITORY.items():
                    trace.record('ACTION_AUTHORIZATION','synthetic_repo_read','ALLOW',resource=name,reason_code='FIXED_SYNTHETIC_REPOSITORY')
                    trace.record('TOOL_EXECUTION','synthetic_repo_read','ALLOW',resource=name,observed_execution=True)
                    artifact=inspection(name,value.encode(),classifier,'EXTERNAL_RETRIEVED_EVIDENCE',trace=trace)
                    add_evidence(firewall,binding,artifact,trace); inspected.append(artifact)
                    tool_activity.append(dict(tool='synthetic_repo_read',resource=name,result='RELEASED_INSPECTED_FRAGMENTS',artifact_id=artifact['id']))
        def tool_catalog(firewall,binding,snapshot):
            return dict(agent_profile_id=body.agent_id,tools=[dict(name=name,arguments=TOOLS[name]) for name in PROFILE_TOOLS[body.agent_id]],
                released_artifacts=[dict(artifact_id=a['id'],filename=a['filename'] if all(f['disposition']=='ALLOW' for f in a['fragments'] if f['channel']=='filename') else 'Inspected artifact '+a['id'][:8],context_source_id=a.get('context_source_id')) for a in inspected if a.get('context_source_id') in {ref[0] for ref in snapshot.refs}],
                approved_sources=[dict(source_id='public-source-'+str(i+1),url=url) for i,url in enumerate(body.urls)],
                repository_files=list(REPOSITORY) if body.use_demo_repository else [],max_model_turns=3,max_tool_requests=2)
        def invoke(firewall,binding,snapshot,tool,arguments,request_id):
            source=None; resource=None
            if tool in ('read_released_evidence','extract_released_page_facts'):
                source=next((a for a in inspected if a['id']==arguments['artifact_id'] and a.get('context_source_id') in {r[0] for r in snapshot.refs}),None)
                if source is None or (tool=='extract_released_page_facts' and not any(t.get('artifact_id')==source['id'] and t['tool']=='public_https_read' for t in tool_activity)):
                    raise Denied('RESOURCE_SCOPE_DENIED')
                resource=source['id']
            elif tool=='read_approved_public_url':
                keys={'public-source-'+str(i+1):url for i,url in enumerate(body.urls)}
                url=keys.get(arguments['source_id'])
                if url is None: raise Denied('RESOURCE_SCOPE_DENIED')
                activity=next((t for t in tool_activity if t.get('destination')==url),None)
                source=next((a for a in inspected if activity and a['id']==activity['artifact_id']),None)
                if source is None: raise Denied('EVIDENCE_NOT_RELEASED')
                resource=url
            elif tool in ('read_approved_repository_file','propose_patch'):
                if not body.use_demo_repository or arguments['path'] not in REPOSITORY: raise Denied('RESOURCE_SCOPE_DENIED')
                source=next((a for a in inspected if a['filename']==arguments['path'] and a['source_kind']=='EXTERNAL_RETRIEVED_EVIDENCE'),None)
                if source is None: raise Denied('EVIDENCE_NOT_RELEASED')
                resource=arguments['path']
            elif tool=='prepare_mock_email':
                # The existing exact-envelope/DLP path is the only side-effect authority.
                result=firewall.prepare_email(binding,dict(snapshot_id=snapshot.id,**arguments))
                value=json.dumps(result)
            if source:
                if source.get('context_source_id') not in {ref[0] for ref in snapshot.refs}: raise Denied('EVIDENCE_NOT_RELEASED')
                value='\n'.join(f['text'] for f in source['fragments'] if f['disposition'] in ('ALLOW','SANITIZE'))
                if tool=='propose_patch': value=json.dumps(dict(path=resource,patch=arguments['patch'],execution='INERT_PROPOSAL_ONLY',tests_executed=False))
            elif tool=='score_suppliers':
                candidates=[a for a in inspected if a.get('context_source_id') in {r[0] for r in snapshot.refs} and a.get('runtime_tool_result') is not True]
                value=json.dumps(score_suppliers(candidates))
            firewall._snapshot(binding,snapshot.id)
            firewall._dlp(binding,text(value).encode(),snapshot)
            trace.record('ACTION_AUTHORIZATION',tool,'ALLOW',tool_request_id=request_id,snapshot_id=snapshot.id,
                resource=resource,reason_code='PROFILE_RESOURCE_AND_CURRENT_SNAPSHOT')
            trace.record('TOOL_EXECUTION',tool,'ALLOW',tool_request_id=request_id,resource=resource,
                observed_execution=True,execution_scope='INERT_TEXT_ONLY' if tool=='propose_patch' else 'RELEASED_EVIDENCE_COMPUTATION_OR_READ')
            result_artifact=inspection('tool-result.txt',value.encode(),classifier,'EXTERNAL_RETRIEVED_EVIDENCE',trace,request_id)
            result_artifact['runtime_tool_result']=True
            if source: result_artifact['derived_from_artifact_ids']=[source['id']]
            elif tool=='score_suppliers': result_artifact['derived_from_artifact_ids']=[a['id'] for a in candidates]
            inspected.append(result_artifact)
            if not any(f['channel']!='filename' and f['disposition'] in ('ALLOW','SANITIZE') for f in result_artifact['fragments']):
                raise Denied('TOOL_RESULT_WITHHELD')
            add_evidence(firewall,binding,result_artifact,trace,request_id)
            next_snapshot=firewall.issue_snapshot(binding,snapshot.intent)
            tool_activity.append(dict(tool=tool,resource=resource,result='RELEASED_INSPECTED_FRAGMENTS',
                artifact_id=result_artifact['id'],tool_request_id=request_id))
            return dict(snapshot_id=next_snapshot,artifact_id=result_artifact['id'])
        firewall=Firewall(provider=provider,instructions=profile['instructions']+'\n'+TURN_INSTRUCTIONS,
                          collect=collect if body.urls or body.use_demo_repository else None,
                          tools=invoke,tool_catalog=tool_catalog,event_sink=trace.broker)
        firewall.policy_version=2
        binding=Binding('demo-owner',body.session_id or trace.run_id,trace.run_id)
        state['firewall']=firewall
        snapshot=firewall.start_task(binding,body.intent)
        state['authorized_intent']=firewall.snapshots[snapshot].intent
        for artifact in inspected: add_evidence(firewall,binding,artifact,trace)
        snapshot=firewall.issue_snapshot(binding,firewall.snapshots[snapshot].intent)
        if not inspected and not firewall.collect: raise Denied('EVIDENCE_REQUIRED')
        try: result=runner(firewall,binding,'agent',snapshot,*(['collect'] if firewall.collect else []))
        except RuntimeError: raise Denied('RUNTIME_UNAVAILABLE_OR_DEADLINE') from None
        if result!=dict(completed=True) or not firewall.final_outputs:
            reason=next((e.get('reason') for e in reversed(firewall.audit) if e['result']=='DENY'),None)
            raise Denied(reason or 'AGENT_TASK_FAILED')
        if body.containment_probe:
            latest=next(s for s in reversed(list(firewall.snapshots.values())) if s.binding==binding)
            firewall.audit_origin='FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT'
            decision=firewall.handle(binding,dict(op='email.prepare',args=dict(snapshot_id=latest.id,
                recipient='attacker@example.com',body='Public synthetic independent containment probe.')))
            firewall.audit_origin=None
            state['containment_probe']=dict(origin='FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT',operation='email.prepare',
                decision=decision,emails_executed=len(firewall.mock_sink))
        record=dict(agent_id=body.agent_id,intent=redact_known_secrets(body.intent),
            integration_id=integration['id'],
            output=firewall.final_outputs[-1],status='COMPLETED',provider='GROQ' if provider else 'TEST_FIXTURE',
            model=getattr(provider,'model',None),usage=getattr(provider,'usage',{}),
            provider_metrics=dict(attempts=getattr(provider,'attempts',0),retries=getattr(provider,'retries',0),failure_codes=getattr(provider,'failure_codes',[])),
            classifier=dict(calls=classifier.calls,seconds=round(classifier.seconds,3),tokens=classifier.tokens) if classifier else None,
            seconds=round(time.monotonic()-started,3),artifacts=inspected,tool_activity=tool_activity,
            decisions=[dict(operation=e['operation'],result=e['result'],reason=e.get('reason')) for e in firewall.audit],
            emails_executed=len(firewall.mock_sink),runtime='VERIFIED_LINUX' if verify else 'TEST_FIXTURE',memory='DISABLED',task_id=binding.task)
        return record

    @app.get('/api/health')
    @app.get('/api/v1/health')
    def health(): return dict(status='READY',isolation='VERIFIED_LINUX' if verify else 'TEST_FIXTURE',storage='TEMPORARY_SQLITE',semantic_detector='PROMPT_GUARD_2_ROUTED' if semantic_enabled else 'DISABLED_PENDING_EVALUATION')
    @app.get('/api/v1/agents')
    def agents(): return [dict(profile,model=os.environ.get('GROQ_MODEL','openai/gpt-oss-20b'),
        profile_version=1,security_policy_version=2,outbound_policy='BROKER_AND_DLP',
        authorized_resources='RELEASED_ARTIFACTS_AND_FIXED_SYNTHETIC_REPO' if profile['id']=='developer' else
        'RELEASED_ARTIFACTS_AND_USER_SELECTED_PUBLIC_HTTPS' if profile['id']=='research' else 'RELEASED_ARTIFACTS') for profile in PROFILES.values()]
    @app.get('/api/v1/agents/{agent_id}')
    def agent(agent_id: str):
        if agent_id not in PROFILES: raise Denied('UNKNOWN_AGENT')
        return next(a for a in agents() if a['id']==agent_id)
    @app.get('/api/v1/coverage')
    def coverage(): return dict(formats=MANIFEST,memory='DISABLED',universal_protection=False)
    @app.get('/api/v1/integrations')
    def integrations(): return [describe(key,store.list('session'),verify) for key in catalog()]
    @app.get('/api/v1/integrations/{identity}')
    def integration(identity: str): return describe(identity,store.list('session'),verify)
    @app.get('/api/v1/integrations/{identity}/capabilities')
    def capabilities(identity: str):
        record=integration(identity)
        return {key:record[key] for key in ('integration_type','agent_profile_id','available_tools','supported_inputs','required_security_boundaries','limitations')}
    @app.get('/api/v1/integrations/{identity}/verification')
    def integration_verification(identity: str): return verification(identity,verify)
    @app.get('/api/v1/integrations/{identity}/runs')
    def integration_runs(identity: str):
        registration(identity)
        return [r for r in store.list('session') if r.get('integration_id',r.get('agent_id'))==identity]
    @app.get('/api/v1/policies')
    def policies(): return dict(version=2,authority=['SERVER_POLICY','AUTHORIZED_TASK_INTENT','UNTRUSTED_EVIDENCE'],
        disposition=['ALLOW','SANITIZE','QUARANTINE','BLOCK','REQUIRE_REVIEW','UNKNOWN'],
        external_email='MOCK_ONLY_REQUIRES_SERVER_AUTHORIZATION',memory='DISABLED',
        budgets=dict(file_bytes=1048576,expanded_bytes=2097152,archive_depth=2,archive_files=32,classifier_calls=16,model_calls=3,tool_requests=2,task_seconds=60),
        unsupported='WITHHELD',partial_release='INSPECTED_FRAGMENTS_ONLY',editing='SERVER_CONFIGURATION_ONLY')
    @app.get('/api/v1/settings')
    def settings(): return dict(provider='Groq',model=os.environ.get('GROQ_MODEL','openai/gpt-oss-20b'),
        semantic_enabled=semantic_enabled,storage='Temporary SQLite; cleared by redeploy / 24-hour retention',
        provider_retry='One retry with 250ms backoff for HTTP 429/503 only; other failures stay explicit',
        authentication='Shared demo access code, single principal',cost='Not calculated; provider billing is authoritative',
        raw_upload_retention='Discarded after extraction',isolated_runtime='Linux Landlock + seccomp')
    @app.get('/api/v1/overview')
    def overview():
        artifacts=store.list('artifact'); sessions=store.list('session'); events=store.list('event'); evaluations=store.list('evaluation')
        return dict(inputs=len(artifacts),sessions=len(sessions),completed=sum(s['status']=='COMPLETED' for s in sessions),
            protected_agents=len(PROFILES),integrations=len(catalog()),
            verified_integrations=sum(verification(key,verify)['status']=='PROTECTION_VERIFIED' for key in catalog()),
            unverified_integrations=sum(verification(key,verify)['status']!='PROTECTION_VERIFIED' for key in catalog()),
            threats=sum(bool(f['signals']) for a in artifacts for f in a['fragments']),
            sanitized=sum(f['disposition']=='SANITIZE' for a in artifacts for f in a['fragments']),
            unsupported=sum(a['inspection_status']=='UNSUPPORTED' for a in artifacts),
            partial=sum(a['inspection_status']=='PARTIAL' for a in artifacts),
            blocked_actions=sum(e['result']=='DENY' and (e['operation'].startswith('email') or e.get('stage')=='ACTION_AUTHORIZATION') for e in events),
            total_tokens=sum(s['usage'].get('total_tokens',0) for s in sessions),
            avg_seconds=round(sum(s['seconds'] for s in sessions)/len(sessions),3) if sessions else None,
            events=events[:12],category_counts={c:sum(sig['category']==c for a in artifacts for f in a['fragments'] for sig in f['signals'])
                for c in sorted({sig['category'] for a in artifacts for f in a['fragments'] for sig in f['signals']})},
            evaluation_runs=len(evaluations),retention='Last 100 records per kind, maximum 300 total, 24 hours; temporary deployment storage')
    @app.post('/api/v1/artifacts')
    def upload(body: Upload):
        enter()
        try:
            try: raw=base64.b64decode(body.data,validate=True)
            except ValueError: raise Denied('INVALID_BASE64_FILE') from None
            if body.filename!=redact_known_secrets(body.filename): raise Denied('SENSITIVE_FILENAME_DENIED')
            provider=provider_factory(); return inspection(body.filename,raw,guard(provider))
        finally: work.release()
    @app.get('/api/v1/artifacts')
    def artifacts(): return store.list('artifact')
    @app.get('/api/v1/artifacts/{identity}')
    def artifact(identity: str):
        record=store.get(identity,'artifact')
        if not record: raise Denied('ARTIFACT_ACCESS_DENIED')
        return record
    @app.get('/api/v1/artifacts/{identity}/coverage')
    def artifact_coverage(identity: str):
        record=artifact(identity)
        return {k:record[k] for k in ('inspection_status','inspected_channels','uninspected_channels','release_scope','safe_claim')}
    @app.post('/api/v1/tasks')
    def task(body: Task):
        enter()
        started=time.monotonic();provider=None; identity=secrets.token_hex(16)
        trace=RunEvents(identity,body.integration_id or body.agent_id,body.agent_id)
        trace.record('USER_TASK_ACCEPTED','task.accept','ALLOW',reason_code='AUTHENTICATED_DEMO_REQUEST')
        state=dict(artifacts=[],tool_activity=[]); error_code=None
        try:
            provider=provider_factory(); record=execute(body,provider,guard(provider),trace,state)
            trace.record('TASK_COMPLETED','task.complete','ALLOW',output_released=True)
        except Denied as error:
            error_code=error.code
            trace.record('TASK_FAILED','task.execute','DENY',reason=error.code,reason_code=error.code,output_released=False)
            record=dict(agent_id=body.agent_id,intent=redact_known_secrets(body.intent),status='REQUIRES_REVIEW' if error.code=='REQUIRES_REVIEW' else 'FAILED',
                output='',error=error.code,provider='GROQ' if provider else 'UNAVAILABLE',model=getattr(provider,'model',None),
                usage=getattr(provider,'usage',{}),seconds=round(time.monotonic()-started,3),artifacts=state['artifacts'],tool_activity=state['tool_activity'],
                decisions=[dict(operation=e['operation'],result=e['result'],reason=e.get('reason')) for e in state['firewall'].audit] if state.get('firewall') else [],
                emails_executed=len(state['firewall'].mock_sink) if state.get('firewall') else 0,
                runtime='VERIFIED_LINUX' if verify else 'TEST_FIXTURE',memory='DISABLED')
        except Exception:
            error_code='TASK_UNAVAILABLE'
            trace.record('TASK_FAILED','task.execute','DENY',reason_code=error_code,output_released=False)
            record=dict(agent_id=body.agent_id,intent=redact_known_secrets(body.intent),status='FAILED',output='',error=error_code,
                usage=getattr(provider,'usage',{}),seconds=round(time.monotonic()-started,3),artifacts=state['artifacts'],
                tool_activity=state['tool_activity'],
                decisions=[dict(operation=e['operation'],result=e['result'],reason=e.get('reason')) for e in state['firewall'].audit] if state.get('firewall') else [],
                emails_executed=len(state['firewall'].mock_sink) if state.get('firewall') else 0,
                runtime='VERIFIED_LINUX' if verify else 'TEST_FIXTURE',memory='DISABLED')
        finally: work.release()
        record.update(integration_id=trace.integration_id,timeline=trace.events,containment_probe=state.get('containment_probe'),
            authorized_intent=state.get('authorized_intent'))
        saved=store.put('session',record,record_id=identity)
        for event in trace.events: store.put('event',event,record_id=event['event_id'])
        if error_code: return JSONResponse(dict(error=error_code,run_id=identity),422)
        return saved
    @app.post('/api/analyze')
    def legacy(body: LegacyTask):
        record=task(Task(agent_id='procurement',intent=body.intent,evidence=body.evidence))
        if isinstance(record,JSONResponse): return record
        record['evidence']=[dict(source_id=a['id'],released_text='\n'.join(f['text'] for f in a['fragments']),
            inspection_status=a['inspection_status'],inspection_profile=a['parser_version'],may_issue_instructions=False) for a in record['artifacts']]
        record.update(supported_formats=[f['format'] for f in MANIFEST],semantic_detector='ROUTED_PROMPT_GUARD_2' if semantic_enabled else 'DISABLED')
        return record
    @app.get('/api/v1/sessions')
    def sessions(): return store.list('session')
    def lab_runs():
        return [dict(id=row['run_id'],agent_id=e['agent_id'],integration_id=e['agent_id'],
            intent='Contained matched procurement outcome fixture: '+e['scenario'],authorized_intent='Compare synthetic quoted prices',
            status=row['status'],output=row.get('output') or '',error=row.get('error'),timeline=row['timeline'],
            artifacts=[row['inspection']] if row.get('inspection') else [],tool_activity=[],decisions=row['decisions'],
            usage=row.get('usage',{}),seconds=row.get('seconds'),emails_executed=row.get('unauthorized_simulated_tool_executions',0),
            containment_probe=row.get('containment_probe'),evaluation_id=e['id'],created_at=row['created_at'],
            configuration=row['configuration'],origin='CONTAINED_ATTACK_LAB',task_success=row.get('task_success'),
            runtime='CONTAINED_BASELINE' if row['configuration']=='A' else 'VERIFIED_LINUX' if verify else 'TEST_FIXTURE')
            for e in store.list('evaluation') for row in e['results'] if row.get('run_id')]
    @app.get('/api/v1/runs')
    def runs(): return sorted(store.list('session')+lab_runs(),key=lambda r:r['created_at'],reverse=True)
    @app.get('/api/v1/sessions/{identity}')
    def session(identity: str):
        record=store.get(identity,'session')
        if not record: raise Denied('SESSION_ACCESS_DENIED')
        return record
    @app.get('/api/v1/runs/{identity}')
    def run(identity: str):
        record=store.get(identity,'session') or next((r for r in lab_runs() if r['id']==identity),None)
        if not record: raise Denied('RUN_ACCESS_DENIED')
        return record
    @app.get('/api/v1/runs/{identity}/timeline')
    def run_timeline(identity: str):
        record=run(identity)
        return dict(run_id=identity,status=record['status'],events=record.get('timeline',[]),
            origin='TRUSTED_RUNTIME_EVENTS' if 'timeline' in record else 'LEGACY_RUN_NO_DETAILED_TIMELINE')
    @app.get('/api/v1/runs/{identity}/security-summary')
    def run_security_summary(identity: str): return security_summary(run(identity))
    @app.get('/api/v1/incidents')
    def incidents():
        return [dict(e,observed_attacker_objective=None) for e in store.list('event') if e['result']=='DENY' or e.get('signals')]
    @app.get('/api/v1/incidents/{identity}')
    def incident(identity: str):
        event=store.get(identity,'event')
        if event is None:
            event=next((e for r in store.list('session') for e in r.get('timeline',[]) if e['event_id']==identity),None)
        if not event or (event['result']!='DENY' and not event.get('signals')): raise Denied('INCIDENT_ACCESS_DENIED')
        linked_run=next((r for r in runs() if r['id']==event.get('run_id')),None)
        artifact=next((a for a in (linked_run or {}).get('artifacts',[]) if a['id']==event.get('source_artifact_id',event.get('artifact_id'))),None)
        if not artifact: artifact=store.get(event.get('source_artifact_id',event.get('artifact_id','')),'artifact')
        return dict(event=event,artifact=artifact,run=linked_run,observed_attacker_objective=None,
            outcome_note='Detection, proposal denial and released output are distinct observations; no attacker success inferred')
    @app.get('/api/v1/events')
    def events(): return store.list('event')
    @app.get('/api/v1/evaluations')
    def evaluations(): return store.list('evaluation')
    @app.get('/api/v1/attacks')
    def attacks():
        from evaluation import SCENARIOS
        return dict(scenarios=[dict(id=k,category=v['category'],description=v['description']) for k,v in SCENARIOS.items()],
            surfaces=['text','html','pdf','docx','xlsx','zip'],contained=True,semantic_enabled=semantic_enabled)
    @app.post('/api/v1/attacks/run')
    def attack(body: Attack):
        from evaluation import run_attack
        enter()
        try:
            report=run_attack(body.agent_id,body.scenario,body.surface,provider_factory,parser,runner,semantic_enabled)
            saved=store.put('evaluation',report)
            for row in report['results']:
                for event in row.get('timeline',[]): store.put('event',dict(event,evaluation_id=saved['id']),record_id=event['event_id'])
                store.put('event',dict(operation='attack_lab.'+row['configuration'],result='OBSERVED',
                    reason='SYNTHETIC_CONTAINED_TEST',evaluation_id=saved['id'],agent_id=body.agent_id,
                    attacker_objective=row.get('attacker_objective_observed'),prevented=row.get('prevented')))
                probe=row.get('containment_probe')
                if probe and not row.get('timeline'):
                    decision=probe['decision']
                    store.put('event',dict(operation=probe['operation'],result='ALLOW' if decision['ok'] else 'DENY',
                        reason=decision.get('error'),origin=probe['origin'],evaluation_id=saved['id'],
                        agent_id=body.agent_id,policy_version=2))
            return saved
        finally: work.release()
    original_openapi=app.openapi
    def documented_schema():
        schema=original_openapi()
        schema.setdefault('components',{}).setdefault('securitySchemes',{})['DemoAccessCode']={
            'type':'http','scheme':'bearer','description':'Render APP_ACCESS_TOKEN; never the Groq credential'}
        for path,operations in schema['paths'].items():
            if path not in ('/api/health','/api/v1/health'):
                for operation in operations.values(): operation['security']=[{'DemoAccessCode':[]}]
        return schema
    app.openapi=documented_schema
    return app

if __name__=='__main__':
    import uvicorn
    access=os.environ.get('APP_ACCESS_TOKEN',''); key=os.environ.get('GROQ_API_KEY','')
    if len(access)<20 or not key: raise SystemExit('Server access and provider secrets are required')
    app=create_app(access,lambda:GroqProvider(key,os.environ.get('GROQ_MODEL','openai/gpt-oss-20b')),
        set(os.environ.get('ALLOWED_ORIGINS','https://agent-trust-firewall.vercel.app').split(',')),
        semantic_enabled=os.environ.get('SEMANTIC_ENABLED')=='1')
    uvicorn.run(app,host='0.0.0.0',port=int(os.environ.get('PORT','10000')),log_level='warning',access_log=False)
