"""Bounded parent/worker protocol. Raw uploads never share credentials or host mounts."""
import base64
import json
from pathlib import Path
import subprocess
import sys
from firewall import Denied
import gate1

def parse_file(name, raw):
    if not gate1.LINUX_VERIFIED: raise Denied('PARSER_ISOLATION_UNAVAILABLE')
    if len(raw)>1_048_576 or not isinstance(name,str) or not 1<=len(name)<=180:
        raise Denied('INVALID_FILE')
    request=json.dumps(dict(name=name,data=base64.b64encode(raw).decode())).encode()+b'\n'
    try:
        process=subprocess.run([sys.executable,'-I',str(Path(__file__).with_name('parser_worker.py'))],
            input=request,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={},timeout=12)
        if process.returncode or len(process.stdout)>256_000: raise ValueError
        result=json.loads(process.stdout)
        if not result.get('ok'): raise ValueError
        return result['tree']
    except (subprocess.TimeoutExpired,ValueError,KeyError):
        raise Denied('PARSER_REJECTED_OR_BUDGET_EXHAUSTED') from None
