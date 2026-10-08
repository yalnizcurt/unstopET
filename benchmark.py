"""Reproducible synthetic detection matrix; no provider key or external effects required."""
from datetime import datetime,timezone
import json
import math
from evaluation import SCENARIOS,fixture
from extractors import extract
from inspection import inspect,CATEGORIES


def wilson(successes,n):
    if not n:return None
    z=1.96;p=successes/n;den=1+z*z/n
    center=(p+z*z/(2*n))/den
    delta=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [round(max(0,center-delta),4),round(min(1,center+delta),4)]

def detection_matrix():
    rows=[]
    for scenario in list(SCENARIOS)[:7]+['benign']:
        for surface in ['text','html','pdf','docx','xlsx','zip']:
            name,raw=fixture(surface,SCENARIOS[scenario]['attack'])
            record=inspect(extract(name,raw))
            detected={signal['category'] for fragment in record['fragments'] for signal in fragment['signals']}
            attack=scenario!='benign';category=SCENARIOS[scenario]['category']
            rows.append(dict(scenario=scenario,category=category,surface=surface,attack=attack,
                target_category_detected=category in detected if attack else None,any_detection=bool(detected),
                legitimate_price_preserved=any('100' in f['text'] for f in record['fragments']),
                inspection_status=record['inspection_status'],release_scope=record['release_scope']))
    attacks=[r for r in rows if r['attack']];benign=[r for r in rows if not r['attack']]
    recognized=sum(r['target_category_detected'] for r in attacks);fp=sum(r['any_detection'] for r in benign)
    return dict(created_at=datetime.now(timezone.utc).isoformat(),scope='Authored synthetic adapter/rule regression matrix; no agent-level prevention measurement',
        attack_cases=len(attacks),benign_cases=len(benign),target_category_recall=recognized/len(attacks),
        recall_wilson95=wilson(recognized,len(attacks)),false_positive_rate=fp/len(benign),
        false_positive_wilson95=wilson(fp,len(benign)),content_preservation=sum(r['legitimate_price_preserved'] for r in rows)/len(rows),
        category_results={c:dict(detected=sum(r['target_category_detected'] for r in attacks if r['category']==c),
            cases=sum(r['category']==c for r in attacks)) for c in CATEGORIES},
        rows=rows,limitations=['Repeated attack wording across file surfaces; not independent unseen families',
            'Six benign format variants are too few for a 5% false-positive reliability claim',
            'Classifier contribution measured separately; no official F3/D2 score implied'])

if __name__=='__main__':print(json.dumps(detection_matrix(),indent=2))
