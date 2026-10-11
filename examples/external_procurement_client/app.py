"""Independent synthetic application: no model key, local inference, or simulated API responses."""
import argparse
import json
import os
from pathlib import Path
from agent_trust_firewall import ATFClient, ATFError


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--documents',type=Path,default=Path(__file__).resolve().parents[2]/'docs'/'demo-fixtures')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    access=os.environ.get('ATF_ACCESS_TOKEN')
    if not access: raise SystemExit('Set ATF_ACCESS_TOKEN from the approved server demo configuration.')
    client=ATFClient(os.environ.get('ATF_API_URL','https://agent-trust-firewall-api.onrender.com'),access)
    try:
        artifacts=[client.inspect_file(name,(args.documents/name).read_bytes()) for name in
                   ('vendor-a.txt','vendor-b.docx','vendor-c.pdf','malicious-proposal.xlsx')]
        run=client.run_protected_agent('procurement',
            'Compare the supplied supplier proposals using the deterministic scoring tool. '
            'Show price, currency, delivery, warranty and missing fields, cite evidence and recommend a supplier.',
            artifact_ids=[a['id'] for a in artifacts],containment_probe=True)
        timeline=client.get_timeline(run['id']); summary=client.get_security_summary(run['id'])
        report=dict(run=run,timeline=timeline,security_summary=summary,verification=client.get_verification('python-sdk-procurement'))
        if args.output: args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(run['output'])
        print(json.dumps(dict(run_id=run['id'],status=run['status'],security_summary=summary),indent=2))
        return 0 if run['status']=='COMPLETED' else 1
    except ATFError as error:
        print('Protected service rejected or could not complete the request: '+error.code)
        if error.run_id: print('Retained run: '+error.run_id)
        return 1
    except OSError: raise SystemExit('A synthetic input or output file is unavailable.') from None

if __name__=='__main__': raise SystemExit(main())
