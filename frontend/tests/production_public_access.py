"""Actual production browser checks. No fixtures, imported cookies or credentials.

Run navigation only after the release lead confirms deployment. Procurement is
a separately authorized phase: it uploads four synthetic files once and submits
exactly one real protected task. Failures are recorded without retrying AI work.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
URL = 'https://agent-trust-firewall.vercel.app'
NAV = ['Overview', 'Protected Agents', 'Runtime Activity', 'Security Incidents',
       'Security Policies', 'Security Lab', 'Integrations', 'Settings']
HEADINGS = ['Security overview', 'Protected agents', 'Runtime activity', 'Security incidents',
            'Security policies', 'Security lab', 'Integrations', 'Workspace settings']
FILES = ['vendor-a.txt', 'vendor-b.docx', 'vendor-c.pdf', 'malicious-proposal.xlsx']


def safe_code(value):
    return value if isinstance(value, str) and re.fullmatch('[A-Z][A-Z0-9_]{0,79}', value) else 'UNCLASSIFIED_FAILURE'


def check(condition, code):
    if not condition:
        raise RuntimeError(code)


def run(args, folder, report):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for width, height in ([(1440, 1000), (390, 844)] if args.phase == 'navigation' else [(1440, 1000)]):
            context = browser.new_context(viewport={'width': width, 'height': height},
                is_mobile=width < 760, has_touch=width < 760)
            page = context.new_page()
            observation = {'viewport': [width, height], 'requests': [], 'responses': [],
                'page_errors': [], 'overflow_checks': [], 'cookie_flags': None, 'task_attempts': 0}
            report['contexts'].append(observation)

            def request_seen(request):
                path = urlparse(request.url).path
                if path.startswith('/api/v1/'):
                    observation['requests'].append({'method': request.method, 'path': path,
                        'bearer_present': 'authorization' in request.headers,
                        'mutation_marker': request.headers.get('x-atf-demo') == '1' if request.method != 'GET' else None})
                    if path == '/api/v1/tasks' and request.method == 'POST':
                        observation['task_attempts'] += 1

            def response_seen(response):
                path = urlparse(response.url).path
                if path.startswith('/api/v1/'):
                    observation['responses'].append({'path': path, 'status': response.status})

            page.on('request', request_seen)
            page.on('response', response_seen)
            page.on('pageerror', lambda _: observation['page_errors'].append('PAGE_JAVASCRIPT_ERROR'))
            page.goto(URL, wait_until='domcontentloaded')
            page.get_by_role('heading', name='Security overview', exact=True).wait_for()
            check(page.locator('input[type=password]').count() == 0, 'PASSWORD_INPUT_PRESENT')
            check(page.get_by_label('Access code', exact=True).count() == 0, 'ACCESS_CODE_INPUT_PRESENT')
            check(page.get_by_role('button', name='Sign out', exact=True).count() == 0, 'SIGN_OUT_PRESENT')
            # This waits for actual server data, not a fabricated success state.
            page.locator('.header-right .badge').filter(has_text='READY').wait_for(state='attached', timeout=150000)
            cookie = next((item for item in context.cookies(URL) if item['name'] == '__Host-atf-demo'), None)
            observation['cookie_flags'] = None if cookie is None else {
                'secure': cookie['secure'], 'http_only': cookie['httpOnly'], 'same_site': cookie['sameSite']}
            check(cookie is not None and cookie['secure'] and cookie['httpOnly'] and cookie['sameSite'] == 'Strict', 'COOKIE_SECURITY_FLAGS_FAILED')
            # Cookie values never leave memory or appear in this report.
            cookie = None
            observation['observed_frontend_assets'] = page.locator('script[src]').evaluate_all('(nodes) => nodes.map(node => new URL(node.src).pathname)')

            def navigate(name):
                if width < 760:
                    page.get_by_role('button', name='Open menu', exact=True).click()
                page.locator('nav').get_by_role('button', name=name, exact=True).click()
                page.evaluate('window.scrollTo(0, 0)')

            def capture(name, full=False):
                page.screenshot(path=str(folder / f'{width}-{name}.png'), full_page=full)

            if args.phase == 'navigation':
                for name, heading in zip(NAV, HEADINGS):
                    navigate(name)
                    page.get_by_role('heading', name=heading, exact=True).wait_for()
                    no_overflow = page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                    observation['overflow_checks'].append({'page': name, 'passed': no_overflow})
                    check(no_overflow, 'HORIZONTAL_OVERFLOW')
                    capture(re.sub('[^a-z0-9]+', '-', name.lower()))
                check(observation['task_attempts'] == 0, 'UNAUTHORIZED_MODEL_TASK_IN_NAVIGATION')
                check(all(item['method'] == 'GET' or item['path'] == '/api/v1/demo/session' for item in observation['requests']), 'UNEXPECTED_NAVIGATION_MUTATION')
                print(f'Actual production navigation passed: {width}x{height}', flush=True)
            else:
                observation['last_step'] = 'OPEN_PROCUREMENT_WORKSPACE'
                navigate('Protected Agents')
                procurement = page.locator('.agent-card').filter(has=page.get_by_role('heading', name='Procurement Analyst', exact=True))
                procurement.get_by_role('button', name='Open workspace', exact=True).click()
                page.get_by_role('heading', name='Procurement Analyst', exact=True).wait_for()
                observation['last_step'] = 'SET_TASK_FIELDS'
                page.get_by_label('Untrusted evidence').fill('')
                page.get_by_label('Your instruction').fill('Compare the supplied supplier proposals using the deterministic scoring tool. Show price, currency, delivery, warranty and missing fields, cite evidence and recommend a supplier.')
                observation['last_step'] = 'UPLOAD_FOUR_SYNTHETIC_FILES'
                page.get_by_label('Attach evidence files', exact=True).set_input_files([str(ROOT / 'docs/demo-fixtures' / name) for name in FILES])
                page.locator('.task-form .chips button').nth(3).wait_for(timeout=150000)
                check(page.locator('.task-form .chips button').count() == 4, 'FOUR_UPLOADS_REQUIRED')
                check(page.get_by_label('Untrusted evidence').input_value() == '', 'DEFAULT_PASTED_EVIDENCE_NOT_CLEARED')
                capture('procurement-ready-with-four-files')
                observation['last_step'] = 'ONE_REAL_TASK_SUBMISSION'
                with page.expect_response(lambda response: urlparse(response.url).path == '/api/v1/tasks' and response.request.method == 'POST', timeout=180000) as pending:
                    page.get_by_role('button', name='Run protected task', exact=True).click()
                response = pending.value
                payload = response.json()
                observation['last_step'] = 'VERIFY_ACTUAL_TASK_RESPONSE'
                observation['task_http_status'] = response.status
                if not response.ok:
                    observation['task_error'] = safe_code(payload.get('error'))
                    identity = payload.get('run_id')
                    if isinstance(identity, str) and re.fullmatch('[a-f0-9]{32}', identity):
                        observation['failed_run_id'] = identity
                    raise RuntimeError('REAL_TASK_FAILED_NO_RETRY')
                observation['run'] = {
                    'id': payload.get('id'), 'status': payload.get('status'), 'model': payload.get('model'),
                    'runtime': payload.get('runtime'), 'emails_executed': payload.get('emails_executed'),
                    'model_requests': sum(event.get('stage') == 'MODEL_REQUEST' for event in payload.get('timeline', [])),
                    'containment_probe': payload.get('containment_probe'),
                    'tool_activity': payload.get('tool_activity'),
                    'generation_tokens': payload.get('usage', {}).get('total_tokens'),
                    'sources': [{'filename': item.get('filename'), 'inspection_status': item.get('inspection_status'),
                        'release_scope': item.get('release_scope'), 'decision': item.get('decision'),
                        'uninspected_channels': item.get('uninspected_channels'),
                        'quarantined_fragments': sum(fragment.get('disposition') == 'QUARANTINE' for fragment in item.get('fragments', []))}
                        for item in payload.get('artifacts', [])],
                    'vendor_b_in_output': 'Vendor B' in payload.get('output', ''),
                    'currency_gap_disclosed': 'not specified' in payload.get('output', '').lower() or 'unspecified' in payload.get('output', '').lower(),
                }
                check(payload.get('status') == 'COMPLETED', 'REAL_TASK_NOT_COMPLETED')
                check(payload.get('emails_executed') == 0, 'EMAIL_EXECUTED')
                check(payload.get('containment_probe', {}).get('decision') == {'ok': False, 'error': 'ACTION_NOT_AUTHORIZED'}, 'FORCED_DENIAL_NOT_RECORDED')
                check(observation['run']['vendor_b_in_output'] and observation['run']['currency_gap_disclosed'], 'LEGITIMATE_TASK_OUTPUT_GAP')
                page.get_by_text('Independent forced containment probe', exact=False).wait_for(timeout=150000)
                page.locator('.response').scroll_into_view_if_needed()
                capture('actual-procurement-output')
                capture('actual-procurement-output-full', full=True)
                observation['last_step'] = 'INSPECT_ACTUAL_RUNTIME'
                page.get_by_role('button', name='Inspect runtime activity', exact=True).click()
                when = page.evaluate('(value) => new Date(value).toLocaleString()', payload['created_at'])
                page.locator('.artifact-row').filter(has_text=when).filter(has_text='procurement').first.click()
                page.get_by_text('Run ' + payload['id'], exact=True).wait_for()
                page.evaluate('window.scrollTo(0, 0)')
                capture('actual-procurement-runtime')
                forced = page.locator('.activity-timeline details').filter(has_text='Forced containment test · not a model proposal').first
                forced.locator('summary').click()
                forced.scroll_into_view_if_needed()
                capture('actual-forced-denial')
                check(observation['task_attempts'] == 1, 'MORE_THAN_ONE_TASK_REQUEST')
                observation['last_step'] = 'COMPLETED_SINGLE_REAL_TASK_CHECK'
                print('One actual production procurement task completed; no client retry.', flush=True)

            check(not observation['page_errors'], 'PAGE_JAVASCRIPT_ERROR')
            check(not any(item['bearer_present'] for item in observation['requests']), 'BEARER_HEADER_PRESENT')
            check(all(item['mutation_marker'] for item in observation['requests'] if item['method'] != 'GET'), 'MUTATION_MARKER_MISSING')
            observation['status'] = 'PASS'
            context.close()
        browser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['navigation', 'procurement'], required=True)
    parser.add_argument('--frontend-commit', required=True)
    parser.add_argument('--backend-commit', required=True)
    args = parser.parse_args()
    if any(not re.fullmatch('[a-f0-9]{40}', value) for value in (args.frontend_commit, args.backend_commit)):
        raise SystemExit('EXPLICIT_DEPLOYED_COMMITS_REQUIRED')
    now = datetime.now(timezone.utc)
    folder = ROOT / 'docs/evidence/public-access' / f'browser-{args.phase}-{args.frontend_commit[:7]}-{now.strftime("%Y%m%dT%H%M%SZ")}'
    folder.mkdir(parents=True)
    report = {'status': 'RUNNING', 'created_at': now.isoformat(), 'url': URL, 'phase': args.phase,
        'frontend_commit_verified_by_release_lead': args.frontend_commit,
        'backend_commit_verified_by_release_lead': args.backend_commit,
        'actual_production': True, 'api_response_interception': False, 'credentials_read': False,
        'cookie_imports': False, 'new_client_task_attempt_limit': 0 if args.phase == 'navigation' else 1,
        'contexts': [], 'scope': 'Actual Chromium browser; mobile uses emulation, not a physical device. Backend isolation and budget audits are separate release-lead checks.'}
    try:
        run(args, folder, report)
        report['status'] = 'PASS'
    except Exception as error:
        report['status'] = 'FAIL'
        report['error'] = safe_code(str(error))
        # Never print raw browser/provider diagnostics, response bodies or cookie values.
        print('Production public-access check failed; no retry or success claim.', flush=True)
    finally:
        (folder / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'phase': args.phase, 'report': str(folder / 'report.json')}), flush=True)
    if report['status'] != 'PASS':
        sys.exit(1)


if __name__ == '__main__':
    main()
