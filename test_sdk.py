import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
sys.path.insert(0,str(Path(__file__).parent/'sdk/python'))
from agent_trust_firewall import ATFClient, ATFError

class SDKTests(unittest.TestCase):
    def test_https_only_and_no_credential_redirect(self):
        for url in ('http://example.com','https://user:password@example.com','https://example.com?token=x','https://example.com:bad'):
            with self.assertRaises(ATFError): ATFClient(url,'synthetic-access')
        from agent_trust_firewall.client import NoRedirect
        with self.assertRaises(ATFError): NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_separate_intent_evidence_and_hosted_integration(self):
        client=ATFClient('https://example.com','synthetic-access')
        with patch.object(client,'_request',return_value={'id':'run-1'}) as request:
            client.run_protected_agent('procurement','Compare supplier prices',artifact_ids=['artifact-1'],evidence=['quoted command'])
        path,body=request.call_args.args
        self.assertEqual(path,'tasks'); self.assertEqual(body['integration_id'],'python-sdk-procurement')
        self.assertEqual(body['evidence'],['quoted command'])
        self.assertNotIn('messages',body); self.assertNotIn('user_authorized',body)
        self.assertNotIn('synthetic-access',json.dumps(body))
    def test_api_errors_are_bounded_and_never_echo_provider_body(self):
        client=ATFClient('https://example.com','synthetic-access')
        for raw,expected in [(b'{"error":"AUTHENTICATION_REQUIRED"}','AUTHENTICATION_REQUIRED'),
                             (b'{"error":"provider secret: confidential"}','API_REQUEST_FAILED')]:
            error=HTTPError('https://example.com',401,'credentials in raw message',{},io.BytesIO(raw))
            with patch.object(client._opener,'open',side_effect=error):
                with self.assertRaises(ATFError) as failure: client.get_runs()
                self.assertEqual(str(failure.exception),expected)
                self.assertEqual(failure.exception.status,401)
    def test_inspection_is_real_request_not_a_success_fixture(self):
        client=ATFClient('https://example.com','synthetic-access')
        with patch.object(client,'_request',return_value={'id':'artifact-1'}) as request:
            client.inspect_file('supplier.txt',b'Public synthetic quote')
        self.assertEqual(request.call_args.args[0],'artifacts')
        with self.assertRaises(ATFError): client.inspect_file('large.txt',b'x'*1_048_577)
