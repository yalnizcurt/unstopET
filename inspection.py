"""Shared fragment inspection, risk assessment, policy and bounded sanitization."""
import base64
import re
import unicodedata
from firewall import digest, redact_known_secrets

RULES = {
 'instruction_override': r'ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules)|override\s+(?:the\s+)?(?:system|security)\s+(?:policy|instructions)',
 'role_change': r'(?:system|developer)\s*:|<\|(?:im_start|start_header_id)\|>|you are now (?:a|an|the)\b|act as (?:an? )?(?:unrestricted|system|developer)',
 'secret_extraction': r'(?:reveal|disclose|print|show|extract)\b.{0,65}(?:system prompt|secret|private key|protected data)',
 'tool_abuse': r'(?:send_email|email\.prepare|email\.dispatch|execute\s+(?:a\s+)?shell|run\s+curl|send\b.{0,60}attacker@)',
 'credential_theft': r'(?:send|steal|exfiltrate|upload|copy|reveal)\b.{0,100}(?:credentials|api.?key|password|token)|(?:credentials|api.?key|password)\b.{0,80}(?:attacker|https?://)',
 'indirect_prompt_injection': r'(?:verification|compliance|vendor|procurement)\s+(?:note|instruction|requirement).{0,80}(?:rank|select|report|ignore)|(?:regardless of|instead of)\s+(?:the\s+)?(?:rubric|task|prices)|report Vendor C as (?:the )?winner',
}
CATEGORIES = list(RULES) + ['encoded_instruction']
ROUTER = re.compile(r'\b(?:assistant|instruction|decode|verification|compliance|rank|preferred|ignore|system|token|before answering|must output|instead|obey|abandon|disregard)\b', re.I)
EDUCATIONAL = re.compile(r'^(?:Example of prompt injection:|Security training example:|The phrase .* is an example)', re.I)


def signals_for(value):
    normalized = unicodedata.normalize('NFKC', value)
    normalized = ''.join(c for c in normalized if unicodedata.category(c) != 'Cf')
    signals = [dict(category=k, engine='deterministic', confidence=1.0)
               for k, pattern in RULES.items() if re.search(pattern, normalized, re.I)]
    if EDUCATIONAL.search(normalized):
        return []
    if normalized != redact_known_secrets(normalized):
        signals.append(dict(category='credential_theft', engine='dlp', confidence=1.0))
    for token in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', normalized):
        try:
            decoded = base64.b64decode(token, validate=True).decode('utf-8')
        except (ValueError, UnicodeError):
            continue
        if len(decoded) <= 4096 and any(re.search(p, decoded, re.I) for p in RULES.values()):
            signals.append(dict(category='encoded_instruction', engine='deterministic', confidence=1.0))
    return signals


def retained_children(children):
    return [dict(child,filename=redact_known_secrets(child['filename']),
        gaps=[redact_known_secrets(gap) for gap in child['gaps']],
        children=retained_children(child.get('children',[]))) for child in children]

def inspect(tree, classifier=None):
    """Only released fragment strings reach the broker. Unsupported regions remain withheld."""
    fragments = []; withheld_names=[]
    gaps = list(tree.get('gaps', []))
    for original in tree.get('fragments', []):
        value = original['text']
        signals = signals_for(value)
        disposition = 'SANITIZE' if signals else 'ALLOW'
        router = 'DETERMINISTIC_SUFFICIENT'
        selected=['normalization','rules','bounded_base64_decoder','dlp']
        semantic_reason='CLASSIFIER_DISABLED' if not classifier else 'SIGNATURE_MATCH' if signals else 'SHORT_FRAGMENT' if len(value.split())<5 else 'EDUCATIONAL_QUOTATION' if EDUCATIONAL.search(value) else 'NO_SEMANTIC_CUE' if not ROUTER.search(value) else 'AMBIGUOUS_INSTRUCTION_CUE'
        if semantic_reason=='AMBIGUOUS_INSTRUCTION_CUE':
            router = 'SEMANTIC_REQUIRED'
            selected.append('prompt_guard_2')
            # Byte-sized windows conservatively bound the classifier's 512-token context.
            data = value.encode()
            try:
                scores = []
                for offset in range(0, len(data), 320):
                    scores.append(classifier(data[offset:offset+400].decode('utf-8', 'ignore')))
                if scores and max(scores) >= .9:
                    signals.append(dict(category='semantic_prompt_injection', engine='prompt_guard_2',
                                        confidence=round(max(scores), 5)))
                    disposition = 'SANITIZE'
            except Exception:
                disposition = 'REQUIRE_REVIEW'
                gaps.append(original['location'] + ':semantic_inspection_unavailable')
        released = '[Instruction attempt quarantined]' if disposition == 'SANITIZE' else value
        if disposition == 'REQUIRE_REVIEW': released = '[Fragment withheld pending inspection]'
        if original['channel']=='filename' and disposition!='ALLOW': withheld_names.append(value)
        fragments.append(dict(original, location=redact_known_secrets(original['location']), original_hash=digest(value.encode()),
            original_text=redact_known_secrets(value), text=redact_known_secrets(released),
            disposition=disposition, signals=signals, router=router,
            routing=dict(selected=selected,reason=semantic_reason,skipped=[] if 'prompt_guard_2' in selected else [dict(engine='prompt_guard_2',reason=semantic_reason)],analysis_complete=disposition!='REQUIRE_REVIEW'),
            risk=95 if signals else None if disposition == 'REQUIRE_REVIEW' else 0))
    for fragment in fragments:
        fragment['released_location']=fragment['id'] if any(name in fragment['location'] for name in withheld_names) else fragment['location']
    status = 'UNSUPPORTED' if tree.get('status') == 'UNSUPPORTED' else 'PARTIAL' if gaps else 'COMPLETE'
    if not fragments and status != 'UNSUPPORTED': status = 'PARTIAL'; gaps.append('no_extracted_content')
    return dict(schema_version=1, id=tree['id'], filename=redact_known_secrets(tree['filename']), sha256=tree['sha256'],
        media_type=tree['media_type'], parser_version='atf-extract-v2', policy_version=2,
        inspection_status=status, inspected_channels=sorted(set(f['channel'] for f in fragments)),
        uninspected_channels=sorted(set(redact_known_secrets(gap) for gap in gaps)), release_scope='INSPECTED_FRAGMENTS_ONLY' if status=='PARTIAL' else
        'NONE' if status=='UNSUPPORTED' else 'DECLARED_PROFILE_FRAGMENTS',
        decision='BLOCK' if status=='UNSUPPORTED' or not fragments else 'REQUIRE_REVIEW' if any(f['disposition']=='REQUIRE_REVIEW' for f in fragments) else
        'SANITIZE' if any(f['signals'] for f in fragments) else 'ALLOW',
        fragments=fragments, children=retained_children(tree.get('children', [])),
        safe_claim=False, note='Completeness describes declared parser channels, not immunity to prompt injection.')

MANIFEST = [
 dict(format='TXT / source code', status='ENABLED', channels=['UTF-8 text'], gaps=['binary / legacy encodings']),
 dict(format='HTML', status='ENABLED', channels=['static text','hidden text','attributes','comments'], gaps=['script-generated content','embedded resources']),
 dict(format='PDF', status='ENABLED', channels=['page text','metadata','annotation text'], gaps=['raster text / OCR','embedded objects','complex layout']),
 dict(format='DOCX', status='ENABLED', channels=['body','comments','metadata','headers / footers','relationships'], gaps=['embedded OLE / media','unrendered layouts']),
 dict(format='XLSX', status='ENABLED', channels=['cells','hidden sheets','comments','metadata','relationships','formulas as inert text'], gaps=['embedded objects / drawings','calculated formula values']),
 dict(format='PNG / JPEG', status='PARTIAL', channels=['metadata','English pixel OCR'], gaps=['OCR recognition not guaranteed','QR codes']),
 dict(format='ZIP', status='ENABLED', channels=['bounded recursive supported children','filenames'], gaps=['unsupported children withheld']),
 dict(format='PPTX / audio / video / legacy binaries', status='UNSUPPORTED', channels=[], gaps=['no adapter']),
]

for profile in MANIFEST: profile["profile_version"]="atf-extract-v2"
