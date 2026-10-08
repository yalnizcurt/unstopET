"""Imports trusted parsers before sealing the worker; consumes upload bytes only afterwards."""
import base64
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from extractors import extract
from linux_guard import restrict
from ocr import initialize, TESSDATA
initialize()
restrict(read_files=[str(Path(__file__)),TESSDATA])
if len(sys.argv)>1 and sys.argv[1]=='--probe':
    import os, socket
    def denied(action):
        try: action()
        except PermissionError: return True
        except OSError as e: return e.errno in (1,13)
        return False
    print(json.dumps(dict(protected_read=denied(lambda:Path(sys.argv[2]).read_bytes()),
        network=denied(lambda:socket.create_connection(('127.0.0.1',int(sys.argv[3])),timeout=1)),
        direct_shell_exec=denied(lambda:os.execve('/bin/sh',['/bin/sh','-c','exit 73'],{})),
        credentials_absent='PARSER_PROBE_CREDENTIAL' not in os.environ)),flush=True)
    raise SystemExit(0)
try:
    line=sys.stdin.buffer.readline(1_500_001)
    if len(line)>1_500_000: raise ValueError('PARSER_INPUT_TOO_LARGE')
    body=json.loads(line)
    if set(body)!= {'name','data'}: raise ValueError('INVALID_PARSER_REQUEST')
    result=extract(body['name'],base64.b64decode(body['data'],validate=True))
    print(json.dumps(dict(ok=True,tree=result)),flush=True)
except Exception:
    print(json.dumps(dict(ok=False,error='PARSER_REJECTED_OR_BUDGET_EXHAUSTED')),flush=True)
