"""Server-owned integration catalog. Connectivity never establishes security verification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from agents import PROFILES
from firewall import Denied

BOUNDARIES = ['input_inspection', 'context_authority', 'model_gateway', 'tool_authorization',
              'tool_output_inspection', 'output_dlp', 'linux_isolation']

def catalog():
    entries = {key: dict(id=key, agent_profile_id=key, name=profile['name'],
        description=profile['description'], integration_type='HOSTED_PROTECTED_RUNTIME',
        required_security_boundaries=BOUNDARIES) for key, profile in PROFILES.items()}
    entries['python-sdk-procurement'] = dict(id='python-sdk-procurement', agent_profile_id='procurement',
        name='External Procurement Client', description='Separate Python application using hosted protected execution.',
        integration_type='PYTHON_SDK_CLIENT', required_security_boundaries=BOUNDARIES)
    entries['inspection-api'] = dict(id='inspection-api', agent_profile_id=None, name='Artifact Inspection API',
        description='Inspection signals and release guidance; the caller controls its own runtime.',
        integration_type='INSPECTION_ONLY', required_security_boundaries=['input_inspection'])
    return entries

def registration(identity):
    entry = catalog().get(identity)
    if entry is None: raise Denied('UNKNOWN_INTEGRATION')
    return entry

def verification(identity, runtime_verified, report_path=None):
    entry = registration(identity)
    path = report_path or Path(__file__).with_name('platform-linux-acceptance-report.json')
    try:
        report = json.loads(Path(path).read_text())
        hashes = report['source_sha256']
        required = ['firewall.py','api.py','agent_runtime.py','gate1.py','linux_guard.py',
                    'inspection.py','extractors.py','parsing.py','parser_worker.py','ocr.py','groq_ai.py',
                    'network.py','agents.py','semantic.py','storage.py','evaluation.py','integrations.py','runtime_tools.py','runtime_events.py','demo_access.py']
        matched = all(name in hashes and hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()==hashes[name]
                      for name in required)
        passed = report['status']=='PASS' and not report['failures'] and not report['errors'] and matched
    except (OSError, ValueError, KeyError, TypeError):
        report = {}; passed = False; matched = False
    verified = bool(runtime_verified and passed)
    return dict(status='PROTECTION_VERIFIED' if verified else 'CONNECTED' if runtime_verified else 'UNKNOWN',
        required_security_boundaries=entry['required_security_boundaries'],
        verified_security_boundaries=entry['required_security_boundaries'] if verified else [],
        last_verified_at=report.get('created_at') if verified else None,
        scope='Version-matching Linux acceptance; declared channels and contained mock effects only',
        evidence='platform-linux-acceptance-report.json', source_matches=matched,
        reason_code='VERSION_MATCHING_ACCEPTANCE_AND_STARTUP' if verified else 'VERIFICATION_UNAVAILABLE_OR_SOURCE_CHANGED',
        universal_external_enforcement=False)

def describe(identity, sessions, runtime_verified):
    entry = registration(identity); profile = PROFILES.get(entry['agent_profile_id'], {})
    proof = verification(identity, runtime_verified)
    runs = [run for run in sessions if run.get('integration_id',run.get('agent_id'))==identity]
    return dict(entry, environment='SYNTHETIC_PUBLIC_DEMO', lifecycle_status=proof['status'],
        verification=proof,
        policy_profile='SERVER_POLICY_V2', supported_inputs=profile.get('inputs',['declared artifacts']),
        available_tools=profile.get('tools',[]), verified_security_boundaries=proof['verified_security_boundaries'],
        last_execution_at=runs[0]['created_at'] if runs else None, last_verified_at=proof['last_verified_at'],
        deployment_mode='HOSTED_LINUX' if entry['agent_profile_id'] else 'INSPECTION_ONLY',
        limitations=['Anonymous visitor sessions; not enterprise accounts','24-hour temporary records','No live email, purchasing, shell, MCP or memory']+
        (['Caller must obey release guidance; external runtime is not enforced'] if not entry['agent_profile_id'] else []))
