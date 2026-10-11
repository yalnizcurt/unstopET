import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from integrations import catalog, registration, verification
from firewall import Denied

class IntegrationTests(unittest.TestCase):
    def test_profiles_are_server_owned_and_sdk_is_hosted(self):
        entries=catalog()
        self.assertEqual({entries[k]['agent_profile_id'] for k in ('procurement','research','developer')},
                         {'procurement','research','developer'})
        self.assertEqual(entries['python-sdk-procurement']['agent_profile_id'],'procurement')
        self.assertEqual(entries['inspection-api']['required_security_boundaries'],['input_inspection'])
        with self.assertRaises(Denied): registration('external-mcp')
    def test_health_or_missing_evidence_cannot_verify_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            proof=verification('procurement',True,Path(tmp)/'missing.json')
            self.assertEqual(proof['status'],'CONNECTED')
            self.assertFalse(proof['verified_security_boundaries'])
            self.assertEqual(verification('procurement',False)['status'],'UNKNOWN')
            report=json.loads(Path('platform-linux-acceptance-report.json').read_text())
            report['source_sha256']={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in report['source_sha256']}
            evidence=Path(tmp)/'matching.json';evidence.write_text(json.dumps(report))
            self.assertEqual(verification('procurement',True,evidence)['status'],'PROTECTION_VERIFIED')
            report['source_sha256']['api.py']='0'*64;evidence.write_text(json.dumps(report))
            changed=verification('procurement',True,evidence)
            self.assertEqual(changed['status'],'CONNECTED');self.assertFalse(changed['source_matches'])
            self.assertFalse(changed['verified_security_boundaries'])
    def test_api_rejects_forged_integration_permissions_and_keeps_agents(self):
        from api import create_app
        from extractors import extract
        from storage import Store
        from fastapi.testclient import TestClient
        app=create_app('synthetic-integration-test-code',lambda:None,set(),Store(),parser=extract,verify=False)
        client=TestClient(app); auth={'Authorization':'Bearer synthetic-integration-test-code'}
        self.assertEqual(len(client.get('/api/v1/agents',headers=auth).json()),3)
        entries=client.get('/api/v1/integrations',headers=auth).json()
        self.assertEqual(len(entries),5)
        self.assertTrue(all(e['lifecycle_status']=='UNKNOWN' for e in entries))
        for identity in ('inspection-api','research','forged'):
            r=client.post('/api/v1/tasks',headers=auth,json=dict(agent_id='procurement',intent='Compare',
                evidence=['public'],integration_id=identity))
            self.assertEqual(r.status_code,422)
        self.assertEqual(client.post('/api/v1/integrations',headers=auth,json={'tools':['shell']}).status_code,405)
