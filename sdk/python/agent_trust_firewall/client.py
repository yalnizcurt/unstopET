"""Small HTTPS client. Hosted execution enforces policy; inspection-only callers must obey release guidance."""
import base64
import json
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, quote
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler, HTTPRedirectHandler

class ATFError(Exception):
    def __init__(self, code, status=None, run_id=None):
        self.code=code; self.status=status; self.run_id=run_id
        super().__init__(code)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args): raise ATFError('REDIRECT_DENIED')

class ATFClient:
    def __init__(self, base_url, api_key):
        try: parsed=urlsplit(base_url); port=parsed.port
        except ValueError: raise ATFError('INVALID_SERVICE_URL') from None
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/') or port not in (None,443):
            raise ATFError('INVALID_SERVICE_URL')
        if not isinstance(api_key,str) or not api_key or '\n' in api_key or '\r' in api_key:
            raise ATFError('INVALID_ACCESS_CODE')
        self.base_url=base_url.rstrip('/'); self._api_key=api_key
        context=ssl.create_default_context()
        try:
            import certifi
        except ImportError: pass
        else: context.load_verify_locations(certifi.where())
        self._opener=build_opener(ProxyHandler({}),NoRedirect(),HTTPSHandler(context=context))

    def _request(self, path, body=None):
        request=Request(self.base_url+'/api/v1/'+path,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization':'Bearer '+self._api_key,'Content-Type':'application/json','User-Agent':'ATF-Python-Client/1.0'})
        try:
            with self._opener.open(request,timeout=90) as response:
                raw=response.read(2_000_001)
            if len(raw)>2_000_000: raise ATFError('RESPONSE_LIMIT_EXCEEDED')
            return json.loads(raw)
        except HTTPError as error:
            status=error.code
            try:
                failure=json.loads(error.read(4096)); code=failure.get('error','API_REQUEST_FAILED')
                run_id=failure.get('run_id')
            except (ValueError, AttributeError): code='API_REQUEST_FAILED'; run_id=None
            finally: error.close()
            if not isinstance(code,str) or not re.fullmatch('[A-Z0-9_]{1,100}',code): code='API_REQUEST_FAILED'
            if not isinstance(run_id,str) or not re.fullmatch('[a-f0-9]{32}',run_id): run_id=None
            raise ATFError(code,status,run_id) from None
        except (URLError,TimeoutError,OSError): raise ATFError('SERVICE_UNAVAILABLE') from None
        except (ValueError,UnicodeError): raise ATFError('INVALID_SERVICE_RESPONSE') from None

    def inspect_file(self, filename, data):
        if not isinstance(data,bytes) or not 1<=len(data)<=1_048_576: raise ATFError('INVALID_FILE')
        return self._request('artifacts',dict(filename=filename,data=base64.b64encode(data).decode()))

    def run_protected_agent(self, agent_id, task, artifact_ids=(), evidence=(), urls=(), use_demo_repository=False, containment_probe=False):
        return self._request('tasks',dict(agent_id=agent_id,intent=task,artifact_ids=list(artifact_ids),
            evidence=list(evidence),urls=list(urls),use_demo_repository=use_demo_repository,
            integration_id='python-sdk-procurement' if agent_id=='procurement' else agent_id,
            containment_probe=containment_probe))

    def get_artifact(self, identity): return self._request('artifacts/'+quote(identity,safe=''))
    def get_coverage(self, identity): return self._request('artifacts/'+quote(identity,safe='')+'/coverage')
    def get_integrations(self): return self._request('integrations')
    def get_verification(self, identity): return self._request('integrations/'+quote(identity,safe='')+'/verification')
    def get_events(self): return self._request('events')
    def get_runs(self): return self._request('runs')
    def get_run(self, identity): return self._request('runs/'+quote(identity,safe=''))
    def get_timeline(self, identity): return self._request('runs/'+quote(identity,safe='')+'/timeline')
    def get_security_summary(self, identity): return self._request('runs/'+quote(identity,safe='')+'/security-summary')
    def compare_attack(self, scenario='override', surface='xlsx', agent_id='procurement'):
        return self._request('attacks/run',dict(agent_id=agent_id,scenario=scenario,surface=surface))
