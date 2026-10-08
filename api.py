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
from firewall import Binding, Denied, Firewall, SECRET, text
from gate1 import run_runtime, verify_linux_boundary
from groq_ai import GroqProvider
from inspection import MANIFEST, inspect
from network import fetch_public
from parsing import parse_file
from semantic import PromptGuard
from storage import Store

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
class LegacyTask(Strict):
    intent: str = Field(min_length=1,max_length=8000)
    evidence: list[str] = Field(min_length=1,max_length=8)
class Attack(Strict):
    agent_id: Literal['procurement','research','developer']='procurement'
    scenario: str = Field(max_length=60)
    surface: Literal['text','html','pdf','docx','xlsx','zip']='text'


def create_app(access_token, provider_factory, origins, store=None, parser=parse_file, runner=run_runtime,
               verify=True, semantic_enabled=False):
    store=store or Store(os.environ.get('ATF_DB_PATH','/tmp/atf-history.sqlite3'))
    work=threading.Lock(); attempts=[]
    @asynccontextmanager
    async def lifespan(app):
        if verify: verify_linux_boundary()
        yield
    app=FastAPI(title='Agent Trust Firewall',version='1.0.0',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
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
        if request.url.path not in ('/api/health','/api/v1/health'):
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
    def inspection(name,raw,classifier):
        result=inspect(parser(name,raw),classifier)
        saved=store.put('artifact',result)
        for fragment in saved['fragments']:
            if fragment['signals'] or fragment['disposition']=='REQUIRE_REVIEW':
                store.put('event',dict(operation='input.inspect',result=fragment['disposition'],artifact_id=saved['id'],
                    location=fragment['location'],signals=fragment['signals'],reason='INSPECTION_POLICY',policy_version=2))
        return saved
    def add_evidence(firewall,binding,artifact):
        if artifact['inspection_status']=='UNSUPPORTED': raise Denied('UNSUPPORTED_ARTIFACT')
        released=[f for f in artifact['fragments'] if f['disposition'] in ('ALLOW','SANITIZE')]
        if not released: raise Denied('NO_RELEASED_FRAGMENTS')
        content='\n'.join(f"[{f['location']}] {f['text']}" for f in released)
        evidence=firewall.import_text(binding,text(content),kind='EXTERNAL_RETRIEVED_EVIDENCE')
        firewall.grant_read(binding,evidence.id)
        artifact["context_source_id"]=evidence.id
    def execute(body,provider,classifier):
        profile=PROFILES[body.agent_id]; inspected=[]; tool_activity=[]
        if body.urls and body.agent_id!='research': raise Denied('TOOL_NOT_AUTHORIZED')
        if body.use_demo_repository and body.agent_id!='developer': raise Denied('TOOL_NOT_AUTHORIZED')
        if SECRET.search(body.intent) or any(SECRET.search(url) for url in body.urls): raise Denied('SECRET_DISCLOSURE_DENIED')
        if body.session_id and not store.get(body.session_id,'session'): raise Denied('SESSION_ACCESS_DENIED')
        for i,value in enumerate(body.evidence): inspected.append(inspection(f'pasted-{i+1}.txt',text(value).encode(),classifier))
        for identity in body.artifact_ids:
            artifact=store.get(identity,'artifact')
            if not artifact: raise Denied('ARTIFACT_ACCESS_DENIED')
            inspected.append(artifact)
        def collect(firewall,binding):
            for url in body.urls:
                raw,name=fetch_public(url)
                artifact=inspection(name,raw,classifier)
                for f in artifact['fragments']: f['location']=url+' '+f['location']
                add_evidence(firewall,binding,artifact); inspected.append(artifact)
                tool_activity.append(dict(tool='public_https_read',destination=url,result='RELEASED_INSPECTED_FRAGMENTS',
                    inspection_status=artifact['inspection_status'],artifact_id=artifact['id']))
            if body.use_demo_repository:
                for name,value in REPOSITORY.items():
                    artifact=inspection(name,value.encode(),classifier)
                    add_evidence(firewall,binding,artifact); inspected.append(artifact)
                    tool_activity.append(dict(tool='synthetic_repo_read',resource=name,result='RELEASED_INSPECTED_FRAGMENTS',artifact_id=artifact['id']))
        firewall=Firewall(provider=provider,instructions=profile['instructions'],
                          collect=collect if body.urls or body.use_demo_repository else None)
        binding=Binding('demo-owner',body.session_id or secrets.token_hex(16),secrets.token_hex(16))
        snapshot=firewall.start_task(binding,body.intent)
        for artifact in inspected: add_evidence(firewall,binding,artifact)
        snapshot=firewall.issue_snapshot(binding,firewall.snapshots[snapshot].intent)
        if not inspected and not firewall.collect: raise Denied('EVIDENCE_REQUIRED')
        started=time.monotonic()
        result=runner(firewall,binding,'demo',snapshot,*(['collect'] if firewall.collect else []))
        for event in firewall.audit:
            store.put('event',dict(operation=event['operation'],result=event['result'],reason=event.get('reason'),
                task_id=binding.task,agent_id=body.agent_id,policy_version=event['policy_version']))
        if result!=dict(completed=True) or not firewall.final_outputs:
            reason=next((e.get('reason') for e in reversed(firewall.audit) if e['result']=='DENY'),None)
            raise Denied(reason or 'AGENT_TASK_FAILED')
        record=store.put('session',dict(agent_id=body.agent_id,intent=body.intent,
            output=firewall.final_outputs[-1],status='COMPLETED',provider='GROQ' if provider else 'TEST_FIXTURE',
            model=getattr(provider,'model',None),usage=getattr(provider,'usage',{}),
            provider_metrics=dict(attempts=getattr(provider,'attempts',0),retries=getattr(provider,'retries',0),failure_codes=getattr(provider,'failure_codes',[])),
            classifier=dict(calls=classifier.calls,seconds=round(classifier.seconds,3),tokens=classifier.tokens) if classifier else None,
            seconds=round(time.monotonic()-started,3),artifacts=inspected,tool_activity=tool_activity,
            decisions=[dict(operation=e['operation'],result=e['result'],reason=e.get('reason')) for e in firewall.audit],
            emails_executed=len(firewall.mock_sink),runtime='VERIFIED_LINUX',memory='DISABLED',task_id=binding.task))
        return record

    @app.get('/api/health')
    @app.get('/api/v1/health')
    def health(): return dict(status='READY',isolation='VERIFIED_LINUX' if verify else 'TEST_FIXTURE',storage='TEMPORARY_SQLITE',semantic_detector='PROMPT_GUARD_2_ROUTED' if semantic_enabled else 'DISABLED_PENDING_EVALUATION')
    @app.get('/api/v1/agents')
    def agents(): return list(PROFILES.values())
    @app.get('/api/v1/agents/{agent_id}')
    def agent(agent_id: str):
        if agent_id not in PROFILES: raise Denied('UNKNOWN_AGENT')
        return PROFILES[agent_id]
    @app.get('/api/v1/coverage')
    def coverage(): return dict(formats=MANIFEST,memory='DISABLED',universal_protection=False)
    @app.get('/api/v1/policies')
    def policies(): return dict(version=2,authority=['SERVER_POLICY','AUTHORIZED_TASK_INTENT','UNTRUSTED_EVIDENCE'],
        disposition=['ALLOW','SANITIZE','QUARANTINE','BLOCK','REQUIRE_REVIEW','UNKNOWN'],
        external_email='MOCK_ONLY_REQUIRES_SERVER_AUTHORIZATION',memory='DISABLED',
        budgets=dict(file_bytes=1048576,expanded_bytes=2097152,archive_depth=2,archive_files=32,classifier_calls=16,model_calls=4),
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
            threats=sum(bool(f['signals']) for a in artifacts for f in a['fragments']),
            sanitized=sum(f['disposition']=='SANITIZE' for a in artifacts for f in a['fragments']),
            unsupported=sum(a['inspection_status']=='UNSUPPORTED' for a in artifacts),
            partial=sum(a['inspection_status']=='PARTIAL' for a in artifacts),
            blocked_actions=sum(e['result']=='DENY' and e['operation'].startswith('email') for e in events),
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
            if SECRET.search(body.filename): raise Denied('SENSITIVE_FILENAME_DENIED')
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
        started=time.monotonic();provider=None
        try:
            provider=provider_factory(); return execute(body,provider,guard(provider))
        except Denied as error:
            store.put('event',dict(operation='task.execute',result='DENY',reason=error.code,agent_id=body.agent_id))
            store.put('session',dict(agent_id=body.agent_id,intent=SECRET.sub('[REDACTED]',body.intent),status='FAILED',
                output='',error=error.code,provider='GROQ' if provider else 'UNAVAILABLE',model=getattr(provider,'model',None),
                usage=getattr(provider,'usage',{}),seconds=round(time.monotonic()-started,3),artifacts=[],tool_activity=[],
                decisions=[],emails_executed=0,runtime='VERIFIED_LINUX',memory='DISABLED'))
            raise
        finally: work.release()
    @app.post('/api/analyze')
    def legacy(body: LegacyTask):
        record=task(Task(agent_id='procurement',intent=body.intent,evidence=body.evidence))
        record['evidence']=[dict(source_id=a['id'],released_text='\n'.join(f['text'] for f in a['fragments']),
            inspection_status=a['inspection_status'],inspection_profile=a['parser_version'],may_issue_instructions=False) for a in record['artifacts']]
        record.update(supported_formats=[f['format'] for f in MANIFEST],semantic_detector='ROUTED_PROMPT_GUARD_2' if semantic_enabled else 'DISABLED')
        return record
    @app.get('/api/v1/sessions')
    def sessions(): return store.list('session')
    @app.get('/api/v1/sessions/{identity}')
    def session(identity: str):
        record=store.get(identity,'session')
        if not record: raise Denied('SESSION_ACCESS_DENIED')
        return record
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
                store.put('event',dict(operation='attack_lab.'+row['configuration'],result='OBSERVED',
                    reason='SYNTHETIC_CONTAINED_TEST',evaluation_id=saved['id'],agent_id=body.agent_id,
                    attacker_objective=row.get('attacker_objective_observed'),prevented=row.get('prevented')))
            return saved
        finally: work.release()
    return app

if __name__=='__main__':
    import uvicorn
    access=os.environ.get('APP_ACCESS_TOKEN',''); key=os.environ.get('GROQ_API_KEY','')
    if len(access)<20 or not key: raise SystemExit('Server access and provider secrets are required')
    app=create_app(access,lambda:GroqProvider(key,os.environ.get('GROQ_MODEL','openai/gpt-oss-20b')),
        set(os.environ.get('ALLOWED_ORIGINS','https://agent-trust-firewall.vercel.app').split(',')),
        semantic_enabled=os.environ.get('SEMANTIC_ENABLED')=='1')
    uvicorn.run(app,host='0.0.0.0',port=int(os.environ.get('PORT','10000')),log_level='warning',access_log=False)
