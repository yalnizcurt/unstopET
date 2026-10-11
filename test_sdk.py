import io
import json
from email.message import Message
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError
from urllib.request import BaseHandler
from urllib.response import addinfourl
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent/'sdk/python'))
from agent_trust_firewall import ATFClient, ATFError


class DemoTransport(BaseHandler):
    """Synthetic HTTPS transport; the real urllib cookie processor handles both directions."""
    handler_order=400

    def __init__(self, cookie='visitor-one', attributes='Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400'):
        self.cookie=cookie
        self.attributes=attributes
        self.requests=[]
        self.failure=None
        self.raw=None

    def https_open(self, request):
        self.requests.append(request)
        bootstrap=request.full_url.endswith('/api/v1/demo/session')
        if self.failure and not bootstrap:
            status,raw=self.failure
            raise HTTPError(request.full_url,status,'private provider diagnostics',{},io.BytesIO(raw))
        headers=Message()
        if bootstrap:
            headers['Set-Cookie']='__Host-atf-demo='+self.cookie+'; '+self.attributes
            value={'access':'ANONYMOUS_PUBLIC_DEMO','expires_in':86400,'session_created':True}
        else: value={'id':'synthetic-response'}
        raw=self.raw if self.raw is not None and not bootstrap else json.dumps(value).encode()
        response=addinfourl(io.BytesIO(raw),headers,request.full_url,200)
        response.msg='OK'
        return response


def client_with_transport(cookie='visitor-one',attributes=None,legacy=None):
    client=ATFClient('https://example.com',legacy)
    transport=DemoTransport(cookie,attributes) if attributes is not None else DemoTransport(cookie)
    client._opener.add_handler(transport)
    return client,transport


class SDKTests(unittest.TestCase):
    def test_https_only_and_no_redirects(self):
        for url in ('http://example.com','https://user:password@example.com','https://example.com?token=x','https://example.com:bad'):
            with self.assertRaises(ATFError): ATFClient(url)
        from agent_trust_firewall.client import NoRedirect
        with self.assertRaises(ATFError): NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_lazy_cookie_bootstrap_without_any_bearer(self):
        client,transport=client_with_transport(legacy='legacy-secret-never-send')
        self.assertEqual(transport.requests,[])
        client.get_runs(); client.get_events()
        self.assertEqual(len(transport.requests),3)
        bootstrap,first,second=transport.requests
        self.assertEqual(bootstrap.full_url,'https://example.com/api/v1/demo/session')
        self.assertEqual(bootstrap.get_method(),'POST')
        self.assertEqual(json.loads(bootstrap.data),{})
        self.assertEqual(bootstrap.get_header('X-atf-demo'),'1')
        self.assertEqual(first.get_header('Cookie'),'__Host-atf-demo=visitor-one')
        self.assertEqual(second.get_header('Cookie'),first.get_header('Cookie'))
        self.assertTrue(all(request.get_header('Authorization') is None for request in transport.requests))
        self.assertNotIn('legacy-secret-never-send',repr(client.__dict__))
        self.assertIsNone(first.get_header('X-atf-demo'))

    def test_each_instance_has_a_distinct_visitor_cookie_jar(self):
        first,one=client_with_transport('visitor-one')
        second,two=client_with_transport('visitor-two')
        first.get_runs(); second.get_runs(); first.get_events()
        self.assertIsNot(first._cookies,second._cookies)
        self.assertEqual(one.requests[-1].get_header('Cookie'),'__Host-atf-demo=visitor-one')
        self.assertEqual(two.requests[-1].get_header('Cookie'),'__Host-atf-demo=visitor-two')

    def test_cookie_attributes_accept_server_lowercase_spelling(self):
        client,transport=client_with_transport(attributes='Secure; httponly; samesite=strict; Path=/; Max-Age=86400')
        client.get_runs()
        self.assertEqual(transport.requests[-1].get_header('Cookie'),'__Host-atf-demo=visitor-one')

    def test_mutations_keep_session_and_custom_csrf_header(self):
        client,transport=client_with_transport()
        client.inspect_file('supplier.txt',b'Public synthetic quote')
        client.run_protected_agent('procurement','Compare',artifact_ids=['artifact-1'])
        client.compare_attack()
        self.assertEqual(len(transport.requests),4)
        for request in transport.requests:
            self.assertEqual(request.get_method(),'POST')
            self.assertEqual(request.get_header('X-atf-demo'),'1')
            self.assertIsNone(request.get_header('Authorization'))
        for request in transport.requests[1:]:
            self.assertEqual(request.get_header('Cookie'),'__Host-atf-demo=visitor-one')

    def test_bootstrap_requires_host_only_secure_http_only_strict_cookie(self):
        invalid=('HttpOnly; SameSite=Strict; Path=/', 'Secure; SameSite=Strict; Path=/',
            'Secure; HttpOnly; SameSite=Lax; Path=/',
            'Secure; HttpOnly; SameSite=Strict; Path=/api',
            'Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com',
            'Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        for attributes in invalid:
            with self.subTest(attributes=attributes):
                client,transport=client_with_transport(attributes=attributes)
                with self.assertRaises(ATFError) as failure: client.get_runs()
                self.assertEqual(failure.exception.code,'DEMO_SESSION_REQUIRED')
                self.assertEqual(len(transport.requests),1)
                self.assertFalse(client._session_ready)

    def test_session_expiry_is_explicit_and_not_silently_replaced(self):
        client,transport=client_with_transport()
        client.get_runs()
        transport.failure=(401,b'{"error":"DEMO_SESSION_REQUIRED"}')
        with self.assertRaises(ATFError) as failure: client.get_runs()
        self.assertEqual(failure.exception.code,'DEMO_SESSION_REQUIRED')
        self.assertEqual(failure.exception.status,401)
        self.assertEqual(len(transport.requests),3)
        self.assertEqual(sum(request.full_url.endswith('/demo/session') for request in transport.requests),1)

    def test_public_quota_errors_are_explicit_and_not_retried(self):
        for code in ('DEMO_RATE_LIMITED','DEMO_DAILY_BUDGET_EXHAUSTED','DEMO_INFERENCE_DISABLED'):
            with self.subTest(code=code):
                client,transport=client_with_transport()
                transport.failure=(429,json.dumps({'error':code}).encode())
                with self.assertRaises(ATFError) as failure: client.get_runs()
                self.assertEqual(failure.exception.code,code)
                self.assertEqual(failure.exception.status,429)
                self.assertEqual(len(transport.requests),2)

    def test_api_errors_never_echo_raw_service_or_provider_diagnostics(self):
        client,transport=client_with_transport()
        for raw,expected in [(b'{"error":"DEMO_SESSION_REQUIRED"}','DEMO_SESSION_REQUIRED'),
                             (b'{"error":"provider secret: confidential"}','API_REQUEST_FAILED'),
                             (b'private diagnostics','API_REQUEST_FAILED')]:
            transport.failure=(401,raw)
            with self.assertRaises(ATFError) as failure: client.get_runs()
            self.assertEqual(str(failure.exception),expected)
            self.assertEqual(failure.exception.status,401)

    def test_safe_failed_run_identifier_remains_investigable(self):
        client,transport=client_with_transport()
        run_id='a'*32
        transport.failure=(422,json.dumps({'error':'TASK_FAILED','run_id':run_id}).encode())
        with self.assertRaises(ATFError) as failure: client.get_runs()
        self.assertEqual(failure.exception.run_id,run_id)
        transport.failure=(422,b'{"error":"TASK_FAILED","run_id":"private credential"}')
        with self.assertRaises(ATFError) as failure: client.get_runs()
        self.assertIsNone(failure.exception.run_id)

    def test_bounded_responses_and_invalid_json(self):
        for raw,code in [(b'x'*2_000_001,'RESPONSE_LIMIT_EXCEEDED'),(b'not json','INVALID_SERVICE_RESPONSE')]:
            client,transport=client_with_transport(); transport.raw=raw
            with self.assertRaises(ATFError) as failure: client.get_runs()
            self.assertEqual(failure.exception.code,code)

    def test_separate_intent_evidence_and_hosted_integration(self):
        client=ATFClient('https://example.com')
        with patch.object(client,'_request',return_value={'id':'run-1'}) as request:
            client.run_protected_agent('procurement','Compare supplier prices',artifact_ids=['artifact-1'],evidence=['quoted command'])
        path,body=request.call_args.args
        self.assertEqual(path,'tasks'); self.assertEqual(body['integration_id'],'python-sdk-procurement')
        self.assertEqual(body['evidence'],['quoted command'])
        self.assertNotIn('messages',body); self.assertNotIn('user_authorized',body)

    def test_upload_limit_and_identity_path_escaping(self):
        client,transport=client_with_transport()
        with self.assertRaises(ATFError): client.inspect_file('large.txt',b'x'*1_048_577)
        self.assertEqual(transport.requests,[])
        client.get_artifact('foreign/id?query')
        self.assertTrue(transport.requests[-1].full_url.endswith('/artifacts/foreign%2Fid%3Fquery'))
