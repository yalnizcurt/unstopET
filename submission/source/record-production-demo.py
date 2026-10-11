"""Record existing production records only. No model calls, API fixtures, or credentials exported."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / '.runtime'), str(ROOT / 'sdk/python'), str(ROOT / '.runtime/atf-video-tools')]
from render_client import api
from agent_trust_firewall import ATFClient
import imageio_ffmpeg

URL = 'https://agent-trust-firewall.vercel.app'
SID = 'srv-db3v5p3l550s73c220d0'
DEST = ROOT / 'submission'
VIDEO = DEST / 'video'
VIDEO.mkdir(exist_ok=True)
REPORT = DEST / 'evidence/production-video-report.json'
TEMP = ROOT / '.runtime/production-video'
TEMP.mkdir(parents=True, exist_ok=True)

SHOTS = [
    (0, 15, 'Introduction', 'Agent Trust Firewall: inspect agent evidence, independently authorize actions, and review security outcomes.'),
    (15, 35, 'Attack explanation', 'A supplier workbook can combine legitimate facts with instructions that try to change the task or authorize an external action.'),
    (35, 55, 'Protected agents', 'Three bounded reference workflows use the same hosted security layer. Verification covers declared controls, not universal attack detection.'),
    (55, 75, 'Integration', 'The Python SDK is a separate client of the protected hosted runtime. Inspection-only clients must enforce returned decisions themselves.'),
    (75, 100, 'Recorded SDK execution', 'This is an actual retained SDK procurement run. Its trace records model requests, permitted tools, inspected receipts and released output.'),
    (100, 125, 'Workbook inspection', 'Actual captured workbook evidence: hostile hidden-sheet content is withheld while permitted commercial facts remain available.'),
    (125, 145, 'Compromise containment', 'Forced containment test, not a model-generated attack: the broker denied an unauthorized email request. The model cannot grant itself permission.'),
    (145, 155, 'Incident evidence', 'The recorded security incident links the denial to its execution. Detection, denial and business correctness are separate observations.'),
    (155, 170, 'Legitimate outcome', 'The released supplier comparison recommends Vendor B, retains delivery and warranty facts, cites evidence and discloses unspecified currency.'),
    (170, 180, 'Measured limits', 'The first-use challenge detected only 4 of 48 attacks, with 6 of 16 benign cases flagged. Detector reliability needs improvement; no universal protection is claimed.'),
]


def timestamp(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f'{hours:02d}:{minutes:02d}:{seconds % 60:02d},000'


def captions():
    text = '\n\n'.join(f'{index}\n{timestamp(start)} --> {timestamp(end)}\n{caption}' for index, (start, end, _, caption) in enumerate(SHOTS, 1))
    (VIDEO / 'Agent-Trust-Firewall-demo.srt').write_text(text + '\n')
    narration = '# Three-minute production demonstration\n\nThis recording shows the actual deployed interface and previously completed synthetic tasks. It does not launch new model requests. Captions distinguish forced tests, archived results and live retained records.\n\n'
    narration += '\n\n'.join(f'**{timestamp(start)[:8]}–{timestamp(end)[:8]} — {title}**\n\n{caption}' for start, end, title, caption in SHOTS)
    narration += '\n\nThe MP4 contains burned explanatory captions and no audio narration. These lines are the optional narration script. Login/setup footage is trimmed before export; access codes are never shown.\n'
    (VIDEO / 'NARRATION.md').write_text(narration)


def ffmpeg(*args):
    process = subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-hide_banner', '-loglevel', 'error', *args], cwd=ROOT, capture_output=True, timeout=180)
    if process.returncode:
        raise RuntimeError('MEDIA_CONVERSION_FAILED')


def record(args):
    token = next(x['envVar']['value'] for x in api('/services/' + SID + '/env-vars?limit=100') if x['envVar']['key'] == 'APP_ACCESS_TOKEN')
    deployments = [item['deploy'] for item in api('/services/' + SID + '/deploys?limit=10')]
    live = next(deploy for deploy in deployments if deploy['status'] == 'live')
    if live['commit']['id'] != args.backend_commit:
        raise RuntimeError('BACKEND_REVISION_CHANGED')
    client = ATFClient(URL, token)
    run = client.get_run(args.run_id)
    if run['status'] != 'COMPLETED' or run['integration_id'] != 'python-sdk-procurement':
        raise RuntimeError('CURRENT_SDK_RUN_REQUIRED')
    if run['model'] != 'openai/gpt-oss-120b' or run['emails_executed'] != 0:
        raise RuntimeError('SDK_MODEL_OR_OUTCOME_MISMATCH')
    if run.get('containment_probe', {}).get('decision') != {'ok': False, 'error': 'ACTION_NOT_AUTHORIZED'}:
        raise RuntimeError('DENIED_FORCED_PROBE_REQUIRED')
    workbook = next(a for a in run['artifacts'] if a['filename'].endswith('.xlsx'))
    hostile = next(f for f in workbook['fragments'] if f['signals'] and f['disposition'] in ('QUARANTINE', 'BLOCK', 'SANITIZE'))
    forced = next(e for e in run['timeline'] if e.get('origin') == 'FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT' and e['decision'] == 'DENY')
    retained_incidents = client._request('incidents')
    incident = next(e for e in retained_incidents if e.get('run_id') == run['id'] and e['result'] == 'DENY')
    evidence = dict(status='RECORDING', created_at=datetime.now(timezone.utc).isoformat(), public_url=URL,
        backend_commit=live['commit']['id'], frontend_commit_verified_by_release_lead=args.frontend_commit,
        run_id=run['id'], integration_id=run['integration_id'], model=run['model'], workbook_id=workbook['id'],
        hostile_fragment_id=hostile['id'], forced_probe_event_id=forced['event_id'], incident_id=incident.get('id', incident['event_id']),
        viewport=[1440, 1000], paid_model_calls_in_recording=0, intercepted_api_responses=False,
        footage='Actual production browser; existing retained synthetic task results; no generated mock UI',
        narration_audio=False, forced_probe_is_model_output=False)
    checks = []
    requests = []
    page_errors = []
    captions()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width':1440,'height':1000}, record_video_dir=str(TEMP), record_video_size={'width':1440,'height':1000})
        page = context.new_page()
        video_start = time.monotonic()
        page.on('pageerror', lambda _: page_errors.append('PAGE_JAVASCRIPT_ERROR'))
        def observe(request):
            path = urlparse(request.url).path
            if '/api/v1/' in path:
                requests.append({'method':request.method, 'path':path})
                if request.method != 'GET':
                    raise RuntimeError('RECORDING_MUST_REMAIN_READ_ONLY')
        page.on('request', observe)
        page.goto(URL + '/#Overview', wait_until='domcontentloaded')
        password = page.get_by_label('Access code')
        if password.get_attribute('type') != 'password':
            raise RuntimeError('MASKED_LOGIN_REQUIRED')
        password.fill(token)
        page.get_by_role('button', name='Open console', exact=True).click()
        page.get_by_role('heading', name='Security overview', exact=True).wait_for(timeout=150000)
        page.goto(URL + '/#Walkthrough', wait_until='domcontentloaded')
        page.get_by_role('heading', name='Let agents use evidence. Keep permissions under control.').wait_for()
        record_start = time.monotonic()
        trim_start = record_start - video_start
        def wait_until(seconds):
            remaining = record_start + seconds - time.monotonic()
            if remaining < -4:
                raise RuntimeError('DEMO_TIMELINE_OVERRUN')
            if remaining > 0:
                page.wait_for_timeout(remaining * 1000)
        def phase(name):
            print('Recorded view: ' + name, flush=True)
            checks.append({'view':name, 'seconds':round(time.monotonic()-record_start, 3)})
            screenshots = DEST / 'screenshots'
            screenshots.mkdir(exist_ok=True)
            slug = re.sub('[^a-z0-9]+', '-', name.lower()).strip('-')
            page.screenshot(path=str(screenshots / ('final-' + slug + '.png')))
        def navigate(name):
            page.locator('nav').get_by_role('button', name=name, exact=True).click()
            page.wait_for_timeout(350)
            page.evaluate('window.scrollTo(0, 0)')
        def frame(element):
            # Position the real element below the fixed header; no content is changed.
            element.evaluate("element => element.scrollIntoView({block: 'start'})")
            page.evaluate('window.scrollBy(0, -100)')
            page.wait_for_timeout(200)
        def choose_run():
            navigate('Runtime Activity')
            when = page.evaluate('(value) => new Date(value).toLocaleString()', run['created_at'])
            page.locator('.artifact-row').filter(has_text='python-sdk-procurement').filter(has_text=when).first.click()
            page.get_by_text('Run ' + run['id'], exact=True).wait_for()
        phase('Public introduction')
        wait_until(15)
        page.locator('#exhibit-attack').scroll_into_view_if_needed()
        phase('Public illustrative attack explanation')
        wait_until(35)
        page.get_by_role('button', name='Protected console', exact=True).click()
        navigate('Protected Agents')
        page.get_by_role('heading', name='Protected agents', exact=True).wait_for()
        phase('Actual protected-agent registry')
        wait_until(55)
        navigate('Integrations')
        page.get_by_role('heading', name='Integrations', exact=True).wait_for()
        frame(page.locator('.panel').filter(has=page.get_by_role('heading', name='Python SDK · hosted protected execution', exact=True)))
        phase('Actual SDK integration instructions')
        wait_until(75)
        choose_run()
        phase('Current retained SDK run')
        wait_until(90)
        receipt = page.locator('.activity-timeline details').filter(has_text='TOOL RESULT').first
        receipt.locator('summary').click()
        frame(receipt)
        phase('Actual authorized tool receipt')
        wait_until(100)
        page.locator('.source-button').filter(has_text=workbook['filename']).first.click()
        page.locator('.investigation .fragment').filter(has_text=hostile['location']).first.scroll_into_view_if_needed()
        phase('Actual hidden-workbook inspection')
        wait_until(125)
        choose_run()
        probe = page.locator('.activity-timeline details').filter(has_text='Forced containment test · not a model proposal').first
        if probe.get_attribute('open') is None:
            probe.locator('summary').click()
        probe.scroll_into_view_if_needed()
        phase('Actual denied forced containment probe')
        wait_until(145)
        navigate('Security Incidents')
        when = page.evaluate('(value) => new Date(value).toLocaleString()', incident['created_at'])
        page.locator('.artifact-row').filter(has_text=incident['operation']).filter(has_text=when).first.click()
        page.locator('pre').filter(has_text=incident.get('id', incident['event_id'])).wait_for()
        phase('Actual correlated incident')
        wait_until(155)
        choose_run()
        page.locator('.response').scroll_into_view_if_needed()
        if 'Vendor B' not in page.locator('.response').inner_text():
            raise RuntimeError('EXPECTED_OUTPUT_NOT_VISIBLE')
        phase('Actual released supplier comparison')
        wait_until(170)
        page.goto(URL + '/#Walkthrough', wait_until='domcontentloaded')
        page.locator('.exhibit-challenge').scroll_into_view_if_needed()
        phase('Archived metrics and first-use reliability limits')
        wait_until(180)
        page.wait_for_timeout(250)
        if page_errors:
            raise RuntimeError('PAGE_JAVASCRIPT_ERROR')
        if any(row['method'] != 'GET' for row in requests):
            raise RuntimeError('RECORDING_WAS_NOT_READ_ONLY')
        video = page.video
        context.close()
        original = Path(video.path())
        browser.close()
    output = VIDEO / 'Agent-Trust-Firewall-demo.mp4'
    style = "Fontsize=8,PrimaryColour=&H00FFFFFF,OutlineColour=&H00121B25,BackColour=&HA0121B25,BorderStyle=3,Alignment=2,MarginV=10"
    subtitle_filter = "subtitles=filename='submission/video/Agent-Trust-Firewall-demo.srt':force_style='" + style + "'"
    ffmpeg('-y','-ss',str(trim_start),'-i',str(original),'-t','180','-vf',subtitle_filter,
           '-r','25','-c:v','libx264','-preset','fast','-crf','18','-pix_fmt','yuv420p','-an','-movflags','+faststart',str(output))
    # Full decode is a playback check; metadata comes from the actual exported file.
    ffmpeg('-i',str(output),'-f','null','-')
    frames = imageio_ffmpeg.read_frames(str(output))
    metadata = next(frames)
    frames.close()
    if tuple(metadata['size']) != (1440, 1000) or not 179.8 <= metadata['duration'] <= 180.2:
        raise RuntimeError('VIDEO_DURATION_OR_RESOLUTION_MISMATCH')
    qa = DEST / 'evidence/video-frame-checks'
    qa.mkdir(exist_ok=True)
    for seconds in (5, 22, 44, 66, 86, 113, 135, 149, 162, 175):
        ffmpeg('-y','-ss',str(seconds),'-i',str(output),'-frames:v','1',str(qa / f'frame-{seconds:03d}.png'))
    evidence.update(status='RECORDED_AND_DECODE_VERIFIED', duration_seconds=metadata['duration'],
        exported_size=list(metadata['size']), fps=metadata['fps'], full_file_decode_passed=True,
        shots=checks, protected_api_requests=len(requests), non_get_api_requests=0,
        page_javascript_errors=page_errors, captions='Burned explanatory captions; matching standalone SRT and narration script',
        login_setup_trimmed=True, file_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        visual_frame_qa='PENDING_MANUAL_INSPECTION', universal_protection=False)
    REPORT.write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({k:evidence[k] for k in ['status','duration_seconds','exported_size','non_get_api_requests','run_id']}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--backend-commit', required=True)
    parser.add_argument('--frontend-commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{32}', args.run_id) or any(not re.fullmatch('[a-f0-9]{40}', value) for value in (args.backend_commit,args.frontend_commit)):
        raise SystemExit('EXPLICIT_SOURCE_BOUND_RECORDING_ARGUMENTS_REQUIRED')
    try:
        record(args)
    except Exception:
        # Browser/provider exceptions may contain sensitive diagnostics: no raw exception output.
        failure = dict(status='FAILED', created_at=datetime.now(timezone.utc).isoformat(), run_id=args.run_id, backend_commit=args.backend_commit, frontend_commit=args.frontend_commit, error='PRODUCTION_DEMO_RECORDING_FAILED', successful_recording_claim=False)
        attempts = DEST / 'evidence/production-video-failed-attempts.json'
        prior = json.loads(attempts.read_text()) if attempts.exists() else []
        attempts.write_text(json.dumps(prior + [failure], indent=2) + '\n')
        print('PRODUCTION_DEMO_RECORDING_FAILED; no successful recording claim.', flush=True)
        raise SystemExit(1) from None

if __name__ == '__main__':
    main()
