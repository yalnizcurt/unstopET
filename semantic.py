"""Specialist classifier. Scores never authorize actions or label a whole file safe."""
import json
import math
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request
from firewall import Denied, encode, redact_known_secrets
from groq_ai import ENDPOINT

GUARD_MODEL = 'meta-llama/llama-prompt-guard-2-86m'

class PromptGuard:
    def __init__(self, provider):
        self.provider = provider
        self.calls = 0
        self.seconds = 0.0
        self.tokens = 0

    def __call__(self, content):
        if len(content.encode()) > 400 or content!=redact_known_secrets(content) or self.calls >= 16:
            raise Denied('CLASSIFIER_BUDGET_OR_DISCLOSURE_DENIED')
        self.calls += 1
        started = time.monotonic()
        request = Request(ENDPOINT, data=encode(dict(model=GUARD_MODEL,
            messages=[dict(role='user', content=content)])), headers={
            'Authorization': 'Bearer ' + self.provider._api_key,
            'Content-Type': 'application/json', 'User-Agent': 'AgentTrustFirewall/1.0'})
        try:
            with self.provider.opener.open(request, timeout=8) as response:
                if response.geturl() != ENDPOINT:
                    raise Denied('CLASSIFIER_REDIRECT_DENIED')
                raw = response.read(8193)
            if len(raw) > 8192:
                raise Denied('CLASSIFIER_RESPONSE_TOO_LARGE')
            result = json.loads(raw)
            score = float(result['choices'][0]['message']['content'])
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError
            self.tokens += max(0, int(result.get('usage', {}).get('prompt_tokens', 0)))
            return score
        except HTTPError as error:
            error.close()
            raise Denied('CLASSIFIER_HTTP_' + str(error.code)) from None
        except (URLError, TimeoutError, OSError):
            raise Denied('CLASSIFIER_UNAVAILABLE') from None
        except (ValueError, TypeError, KeyError, IndexError):
            raise Denied('CLASSIFIER_INVALID_RESPONSE') from None
        finally:
            self.seconds += time.monotonic() - started
