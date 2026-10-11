"""Local real-browser UX checks; intercepted API fixtures are not deployment proof.
Run with an existing Playwright installation: python3 frontend/tests/browser_ux.py
"""
import json
from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path('/tmp/atf-public-session-ux')
OUTPUT.mkdir(exist_ok=True)
report = json.loads((ROOT / 'integration-platform-production-report.json').read_text())
run = report['workflows'][0]
artifact = next(a for a in run['artifacts'] if a['filename'].endswith('.xlsx'))
profiles = [
    dict(id='procurement', name='Procurement Analyst', description='Released supplier facts and deterministic scoring.', tools=['read_artifact', 'score_suppliers'], model='UI_TEST_FIXTURE'),
    dict(id='research', name='Web Research Agent', description='Two selected public pages.', tools=['read_public_page'], model='UI_TEST_FIXTURE'),
    dict(id='developer', name='Developer Assistant', description='Fixed repository; inert patch.', tools=['read_repo_file', 'propose_patch'], model='UI_TEST_FIXTURE'),
]
checks = []
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    for width, height in [(1440, 1000), (390, 844)]:
        context = browser.new_context(viewport=dict(width=width, height=height))
        page = context.new_page()
        calls = []
        state = dict(upload_attempts=0, retained=True, session_posts=0,
            bootstrap_failure=True, force_expiry=False, artifacts_visible=True, quota=None)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        def handler(route):
            url = route.request.url
            if '/api/v1/' in url:
                calls.append((route.request.method, url.split('/api/v1/')[1]))
                endpoint = url.split('/api/v1/')[1]
                assert 'authorization' not in route.request.headers, 'The public browser must not send a bearer credential'
                if route.request.method == 'POST':
                    assert route.request.headers.get('x-atf-demo') == '1', 'Every mutation needs the namespace marker'
                if endpoint == 'demo/session':
                    assert route.request.method == 'POST' and route.request.post_data_json == {}
                    state['session_posts'] += 1
                    if state['bootstrap_failure']:
                        route.fulfill(status=429, json=dict(error='SESSION_CAPACITY_EXHAUSTED'))
                    else:
                        route.fulfill(json=dict(status='ANONYMOUS_DEMO'))
                    return
                if state['force_expiry']:
                    state['force_expiry'] = False
                    route.fulfill(status=401, json=dict(error='DEMO_SESSION_REQUIRED'))
                    return
                if endpoint == 'tasks' and state['quota']:
                    route.fulfill(status=429, json=dict(error=state['quota']))
                    return
                if route.request.method == 'POST' and endpoint == 'artifacts':
                    state['upload_attempts'] += 1
                    if state['upload_attempts'] % 2:
                        route.fulfill(status=429, json=dict(error='BUSY_TRY_AGAIN'))
                        return
                    payload = route.request.post_data_json
                    route.fulfill(json=dict(artifact, filename=payload['filename']))
                    return
                values = dict(
                    agents=profiles,
                    overview=dict(protected_agents=3, verified_integrations=0, unverified_integrations=3, inputs=0, threats=0, blocked_actions=0, completed=0, category_counts={}, events=[], retention='UI-only fixture; temporary records.'),
                    artifacts=[artifact] if state['artifacts_visible'] else [], events=[], sessions=[], evaluations=[],
                    policies=dict(authority=['SERVER_POLICY','AUTHORIZED_TASK_INTENT','UNTRUSTED_EVIDENCE'], budgets={}, disposition=['ALLOW','BLOCK']),
                    coverage=dict(formats=[]), settings=dict(model='UI_TEST_FIXTURE', provider='UI_TEST_FIXTURE', access='Public anonymous visitor; no login', demo_limits=dict(concurrent_operations=1, session_seconds=86400, operation_scope='UI fixture: admitted inspections, tasks and evaluations; not a dollar or token budget')),
                    health=dict(status='UI_TEST_FIXTURE', isolation='UI_TEST_FIXTURE', semantic_detector='UI_TEST_FIXTURE'),
                    attacks=dict(scenarios=[], surfaces=[]), integrations=[], incidents=[],
                    runs=report['workflows'][:2] if state['retained'] else [],
                )
                route.fulfill(json=values.get(endpoint, {}))
            elif urlparse(url).hostname in ('127.0.0.1', 'localhost'):
                route.continue_()
            elif url.startswith('https://fonts.googleapis.com'):
                route.fulfill(body='', content_type='text/css')
            else:
                route.abort()
        page.route('**/*', handler)
        page.goto('http://127.0.0.1:5187/#Walkthrough')
        page.get_by_role('heading', name='Let agents use evidence. Keep permissions under control.').wait_for()
        assert calls == [], 'Public walkthrough must not call protected APIs'
        assert page.locator('.exhibit img').count() == 3
        page.locator('.exhibit img').evaluate_all('(images) => Promise.all(images.map(image => image.decode()))')
        assert page.get_by_text('8/9 attacks detected', exact=True).count() == 1
        assert page.get_by_text('7/9 attacks detected', exact=True).count() == 1
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), 'Walkthrough overflow'
        page.screenshot(path=str(OUTPUT / f'walkthrough-{width}.png'), full_page=True)
        page.goto('http://127.0.0.1:5187/')
        page.get_by_role('heading', name='Security overview').wait_for()
        assert page.locator('input[type=password]').count() == 0
        assert page.get_by_role('button', name='Sign out', exact=True).count() == 0
        page.get_by_role('alert').filter(has_text='capacity').wait_for()
        assert page.locator('nav button').count() == 8, 'Shell and navigation must remain visible on bootstrap failure'
        state['bootstrap_failure'] = False
        page.get_by_role('button', name='Retry connection', exact=True).click()
        page.get_by_role('alert').wait_for(state='detached')
        page.locator('.header-right .badge').filter(has_text='UI TEST FIXTURE').wait_for(state='attached')
        def navigate(name):
            if width < 760:
                page.get_by_role('button', name='Open menu', exact=True).click()
            page.locator('nav').get_by_role('button', name=name, exact=True).click()
        for name in ['Overview', 'Protected Agents', 'Runtime Activity', 'Security Incidents', 'Security Policies', 'Security Lab', 'Integrations', 'Settings']:
            navigate(name)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), f'{name} overflow at {width}'
        navigate('Security Lab')
        page.get_by_role('button', name='Artifact Inspector', exact=True).click()
        file_input = page.get_by_label('Scan files')
        file_input.set_input_files(str(ROOT / 'docs/demo-fixtures/malicious-proposal.xlsx'))
        page.get_by_role('alert').filter(has_text='same file').wait_for()
        assert file_input.input_value() == '', 'Failed upload must reset native file selection'
        file_input.set_input_files(str(ROOT / 'docs/demo-fixtures/malicious-proposal.xlsx'))
        page.locator('.investigation').wait_for()
        assert file_input.input_value() == '', 'Successful upload must also permit reselection'
        assert page.get_by_role('alert').count() == 0
        navigate('Protected Agents')
        page.get_by_role('button', name='Open workspace', exact=True).first.click()
        assert page.locator('.task-form .chips button').count() == 0, 'Scanner files must not silently attach to a task'
        attach_input = page.get_by_label('Attach evidence files')
        attach_input.set_input_files(str(ROOT / 'docs/demo-fixtures/educational-quotation.txt'))
        page.get_by_role('alert').filter(has_text='same file').wait_for()
        assert attach_input.input_value() == ''
        attach_input.set_input_files(str(ROOT / 'docs/demo-fixtures/educational-quotation.txt'))
        page.locator('.task-form .chips button').wait_for()
        page.get_by_role('alert').wait_for(state='detached')
        assert page.locator('.task-form .chips button').count() == 1, 'Scanner files must not silently attach to a task'
        navigate('Runtime Activity')
        page.locator('.artifact-row').first.click()
        page.get_by_text('Forced containment test · not a model proposal', exact=True).wait_for()
        page.get_by_text('Agent proposal · execution requires broker authorization', exact=True).wait_for()
        page.locator('.artifact-row').nth(1).click()
        page.get_by_text('User-selected source plan · brokered retrieval', exact=True).wait_for()
        page.locator('.artifact-row').first.click()
        state['retained'] = False
        page.get_by_role('button', name='Refresh records', exact=True).click()
        page.get_by_text("This run is no longer in the server's retained history.", exact=False).wait_for()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), 'Runtime detail overflow'
        page.screenshot(path=str(OUTPUT / f'runtime-ui-fixture-{width}.png'), full_page=True)
        before_replacement = state['session_posts']
        state['artifacts_visible'] = False
        state['force_expiry'] = True
        page.get_by_role('button', name='Refresh records', exact=True).click()
        page.get_by_text('Your previous temporary workspace expired.', exact=False).wait_for()
        page.get_by_text('Select a run to inspect its chronological security trace.', exact=True).wait_for()
        assert page.get_by_text('Run ' + run['id'], exact=True).count() == 0, 'Expired-session selection must be cleared'
        assert state['session_posts'] == before_replacement + 1, 'Concurrent expiry must bootstrap only once'
        navigate('Security Lab')
        page.get_by_role('button', name='Artifact Inspector', exact=True).click()
        page.get_by_text('Select an artifact to investigate its actual inspection.', exact=True).wait_for()
        assert page.locator('.investigation').count() == 0, 'Previously selected evidence must be cleared'
        navigate('Protected Agents')
        page.get_by_role('button', name='Open workspace', exact=True).first.click()
        assert page.locator('.task-form .chips button').count() == 0, 'Old-session attached IDs must be removed'
        for code, message in [('DEMO_RATE_LIMITED','request limit'), ('DEMO_DAILY_BUDGET_EXHAUSTED','shared processing budget'), ('DEMO_INFERENCE_DISABLED','temporarily disabled')]:
            state['quota'] = code
            page.get_by_role('button', name='Run protected task', exact=True).click()
            page.get_by_role('alert').filter(has_text=message).wait_for()
            page.get_by_role('button', name='Dismiss error', exact=True).click()
        navigate('Settings')
        page.get_by_role('heading', name='Workspace settings').wait_for()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), 'Public settings overflow'
        page.screenshot(path=str(OUTPUT / f'public-settings-ui-fixture-{width}.png'), full_page=True)
        assert not errors, errors
        checks.append(dict(viewport=f'{width}x{height}', static_walkthrough_api_calls=0, main_opens_without_login=True, bootstrap_failure_keeps_shell_visible=True, no_bearer_credentials=True, all_mutations_have_demo_marker=True, navigation_routes=8, scanner_same_file_retry=True, workspace_same_file_retry=True, no_horizontal_overflow=True, forced_probe_label_visible=True, source_plan_distinguished_from_model_proposal=True, eviction_label_visible=True, concurrent_expiry_replacement_count=1, old_visitor_selections_cleared=True, quota_errors_visible=3, page_errors=errors, scope='Actual local Chromium with intercepted UI fixtures; not live backend or cookie-isolation acceptance'))
        context.close()
    browser.close()
result = dict(status='PASS', checks=checks, screenshot_directory=str(OUTPUT), production_smoke=False)
(OUTPUT / 'report.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
