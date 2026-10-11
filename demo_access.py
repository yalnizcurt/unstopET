"""Server-issued anonymous visitors and bounded public-demo operations; no user profiles."""
import hashlib
import hmac
import os
import re
import secrets
import time

from firewall import Denied

COOKIE='__Host-atf-demo'
SESSION_SECONDS=86400
DEFAULTS=dict(session_requests_per_minute=120,ip_requests_per_minute=300,
    session_writes_per_hour=20,ip_writes_per_hour=100,session_creates_per_hour=20,
    daily_operations=100,sessions_max=256,inference_enabled=True)
ENV_NAMES={key:'DEMO_'+key.upper() for key in DEFAULTS}

# New administrative or internal routes never inherit public access by default.
PUBLIC_GET={'/api/health','/api/v1/health','/api/docs','/api/openapi.json'}
GET_ROUTES=re.compile(r'/api/v1/(?:agents(?:/(?:procurement|research|developer))?|integrations(?:/(?:procurement|research|developer|python-sdk-procurement|inspection-api)(?:/(?:capabilities|verification|runs))?)?|artifacts(?:/[a-f0-9]{32}(?:/coverage)?)?|sessions(?:/[a-f0-9]{32})?|runs(?:/[a-f0-9]{32}(?:/(?:timeline|security-summary))?)?|incidents(?:/[a-f0-9]{32})?|policies|coverage|settings|overview|events|evaluations|attacks)')
POST_ROUTES={'/api/v1/demo/session','/api/v1/artifacts','/api/v1/tasks','/api/v1/attacks/run','/api/analyze'}

def permitted_route(path,method):
    return (method=='GET' and (path in PUBLIC_GET or GET_ROUTES.fullmatch(path) is not None) or
            method=='POST' and path in POST_ROUTES)

class DemoDenied(Denied):
    def __init__(self,code,status=429,retry_after=60):
        super().__init__(code);self.status=status;self.retry_after=retry_after

class DemoAccess:
    def __init__(self,store,limits=None,now=time.time):
        self.store=store;self.now=now;self._ip_salt=secrets.token_bytes(32)
        self.limits=dict(DEFAULTS)
        for key,name in ENV_NAMES.items():
            if name in os.environ:
                self.limits[key]=os.environ[name]=='1' if key=='inference_enabled' else int(os.environ[name])
        if limits is not None:
            if set(limits)-set(DEFAULTS):raise ValueError('UNKNOWN_DEMO_LIMIT')
            self.limits.update(limits)
        if (type(self.limits['inference_enabled']) is not bool or
            any(type(v) is not int or not 1<=v<=100000 for k,v in self.limits.items() if k!='inference_enabled')):
            raise ValueError('INVALID_DEMO_LIMIT')
        with store.lock,store.db:
            store.db.execute('CREATE TABLE IF NOT EXISTS demo_visitors (id TEXT PRIMARY KEY, created REAL)')
            store.db.execute('CREATE TABLE IF NOT EXISTS demo_counters (key TEXT PRIMARY KEY, start REAL, count INTEGER)')

    def peer(self,request):
        # Forwarded headers are attacker-controlled unless a separately verified proxy rewrites them.
        return hmac.new(self._ip_salt,(request.client.host if request.client else 'unknown-peer').encode(),hashlib.sha256).hexdigest()

    def _prune(self,now):
        db=self.store.db
        db.execute('DELETE FROM records WHERE principal IN (SELECT id FROM demo_visitors WHERE created<=?)',(now-SESSION_SECONDS,))
        db.execute('DELETE FROM demo_visitors WHERE created<=?',(now-SESSION_SECONDS,))
        db.execute('DELETE FROM demo_counters WHERE start<?',(now-SESSION_SECONDS,))

    def _charge(self,entries):
        now=self.now()
        with self.store.lock,self.store.db:
            db=self.store.db;db.execute('BEGIN IMMEDIATE');self._prune(now)
            for label,period,maximum in entries:
                start=int(now//period)*period;key=label+':'+str(start)
                row=db.execute('SELECT count FROM demo_counters WHERE key=?',(key,)).fetchone()
                if row and row[0]>=maximum:raise DemoDenied('DEMO_RATE_LIMITED',retry_after=max(1,int(start+period-now)))
            if db.execute('SELECT COUNT(*) FROM demo_counters').fetchone()[0]>=10000:
                raise DemoDenied('DEMO_RATE_LIMITED')
            for label,period,maximum in entries:
                start=int(now//period)*period
                db.execute('INSERT INTO demo_counters VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',(label+':'+str(start),start))

    def request_limit(self,peer,owner=None,write=False):
        entries=[('peer-read:'+peer,60,self.limits['ip_requests_per_minute'])]
        if owner:entries.append(('visitor-read:'+owner,60,self.limits['session_requests_per_minute']))
        if write:
            entries.append(('peer-write:'+peer,3600,self.limits['ip_writes_per_hour']))
            if owner:entries.append(('visitor-write:'+owner,3600,self.limits['session_writes_per_hour']))
        self._charge(entries)

    def owner(self,cookie):
        if not isinstance(cookie,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',cookie):return None
        identity='visitor:'+hashlib.sha256(cookie.encode()).hexdigest()
        with self.store.lock,self.store.db:
            self._prune(self.now())
            return identity if self.store.db.execute('SELECT 1 FROM demo_visitors WHERE id=?',(identity,)).fetchone() else None

    def bootstrap(self,cookie,peer):
        if self.owner(cookie):return cookie,False
        self._charge([('peer-create:'+peer,3600,self.limits['session_creates_per_hour'])])
        cookie=secrets.token_urlsafe(32);identity='visitor:'+hashlib.sha256(cookie.encode()).hexdigest()
        with self.store.lock,self.store.db:
            self.store.db.execute('BEGIN IMMEDIATE');self._prune(self.now())
            if self.store.db.execute('SELECT COUNT(*) FROM demo_visitors').fetchone()[0]>=self.limits['sessions_max']:
                raise DemoDenied('SESSION_CAPACITY_EXHAUSTED')
            self.store.db.execute('INSERT INTO demo_visitors VALUES (?,?)',(identity,self.now()))
        return cookie,True

    def admit_operation(self):
        if not self.limits['inference_enabled']:raise DemoDenied('DEMO_INFERENCE_DISABLED',retry_after=3600)
        now=self.now();start=int(now//86400)*86400
        with self.store.lock,self.store.db:
            db=self.store.db;db.execute('BEGIN IMMEDIATE');self._prune(now)
            row=db.execute('SELECT count FROM demo_counters WHERE key=?',('global-operations:'+str(start),)).fetchone()
            if row and row[0]>=self.limits['daily_operations']:
                raise DemoDenied('DEMO_DAILY_BUDGET_EXHAUSTED',retry_after=max(1,int(start+86400-now)))
            db.execute('INSERT INTO demo_counters VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',('global-operations:'+str(start),start))

    def policy(self):
        return dict(self.limits,operation_scope='Admitted artifact inspections, tasks and evaluations; not a token or dollar budget',
            daily_reset='UTC midnight; counters also reset if free deployment storage is lost',
            ip_signal='Hashed observed peer; forwarded headers do not establish identity and shared proxies can aggregate visitors',
            concurrent_operations=1,session_seconds=SESSION_SECONDS)
