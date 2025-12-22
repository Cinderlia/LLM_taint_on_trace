import json
import urllib.error
import urllib.request
from typing import Any

from .config import LLMConfig, load_llm_config


class OpenAIClient:
    def __init__(self, base_url: str, api_key: str, default_model: str | None = None, timeout_s: float = 60.0):
        self.base_url = (base_url or '').rstrip('/')
        self.api_key = api_key or ''
        self.default_model = default_model
        self.timeout_s = float(timeout_s)

    def create_chat_completion(
        self,
        *,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        use_model = model or self.default_model
        if not use_model:
            raise ValueError('missing model')
        if not self.api_key:
            raise ValueError('missing api_key')
        if not self.base_url:
            raise ValueError('missing base_url')

        payload: dict[str, Any] = {
            'model': use_model,
            'messages': messages,
        }
        if temperature is not None:
            payload['temperature'] = float(temperature)
        if max_tokens is not None:
            payload['max_tokens'] = int(max_tokens)
        if isinstance(extra, dict) and extra:
            payload.update(extra)

        url = self.base_url + '/v1/chat/completions'
        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
            headers={
                'Authorization': 'Bearer ' + self.api_key,
                'Content-Type': 'application/json; charset=utf-8',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            raise RuntimeError(f'openai_http_error status={getattr(e, "code", None)} body={body[:2000]}') from e
        except urllib.error.URLError as e:
            raise RuntimeError(f'openai_url_error reason={getattr(e, "reason", None)}') from e

        txt = raw.decode('utf-8', errors='replace')
        obj = json.loads(txt)
        if not isinstance(obj, dict):
            raise RuntimeError('openai_bad_response')
        return obj

    def chat_text(
        self,
        *,
        prompt: str,
        system: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        msgs: list[dict[str, Any]] = []
        if system:
            msgs.append({'role': 'system', 'content': system})
        msgs.append({'role': 'user', 'content': prompt})
        obj = self.create_chat_completion(
            messages=msgs,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
        choices = obj.get('choices')
        if not isinstance(choices, list) or not choices:
            raise RuntimeError('openai_missing_choices')
        msg = (choices[0] or {}).get('message') or {}
        content = msg.get('content')
        if not isinstance(content, str):
            raise RuntimeError('openai_missing_content')
        return content


class AnthropicClient:
    def __init__(self, base_url: str, api_key: str, default_model: str | None = None, timeout_s: float = 60.0, default_max_tokens: int = 1024):
        self.base_url = (base_url or '').rstrip('/')
        self.api_key = api_key or ''
        self.default_model = default_model
        self.timeout_s = float(timeout_s)
        self.default_max_tokens = int(default_max_tokens)

    def create_message(
        self,
        *,
        messages: list[dict[str, Any]],
        system: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        use_model = model or self.default_model
        if not use_model:
            raise ValueError('missing model')
        if not self.api_key:
            raise ValueError('missing api_key')
        if not self.base_url:
            raise ValueError('missing base_url')

        use_max_tokens = int(max_tokens) if max_tokens is not None else int(self.default_max_tokens)
        if use_max_tokens < 1:
            use_max_tokens = 1

        payload: dict[str, Any] = {
            'model': use_model,
            'messages': messages,
            'max_tokens': use_max_tokens,
        }
        if system:
            payload['system'] = system
        if temperature is not None:
            payload['temperature'] = float(temperature)
        if isinstance(extra, dict) and extra:
            payload.update(extra)

        url = self.base_url + '/v1/messages'
        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
            headers={
                'x-api-key': self.api_key,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json; charset=utf-8',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            raise RuntimeError(f'anthropic_http_error status={getattr(e, "code", None)} body={body[:2000]}') from e
        except urllib.error.URLError as e:
            raise RuntimeError(f'anthropic_url_error reason={getattr(e, "reason", None)}') from e

        txt = raw.decode('utf-8', errors='replace')
        obj = json.loads(txt)
        if not isinstance(obj, dict):
            raise RuntimeError('anthropic_bad_response')
        return obj

    def chat_text(
        self,
        *,
        prompt: str,
        system: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        msgs: list[dict[str, Any]] = [{'role': 'user', 'content': prompt}]
        obj = self.create_message(
            messages=msgs,
            system=system,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
        content = obj.get('content')
        if not isinstance(content, list) or not content:
            raise RuntimeError('anthropic_missing_content')
        parts = []
        for it in content:
            if isinstance(it, dict) and isinstance(it.get('text'), str):
                parts.append(it.get('text') or '')
            elif isinstance(it, str):
                parts.append(it)
        out = ''.join(parts).strip()
        if not out:
            raise RuntimeError('anthropic_empty_text')
        return out


def get_default_client(config_path: str | None = None) -> OpenAIClient | AnthropicClient:
    cfg: LLMConfig = load_llm_config(config_path)
    base_url = (cfg.base_url or '').strip()
    api_key = (cfg.api_key or '').strip()
    if ('anthropic' in base_url.lower()) or api_key.startswith('sk-ant-'):
        return AnthropicClient(
            base_url=cfg.base_url,
            api_key=cfg.api_key,
            default_model=cfg.model,
            timeout_s=cfg.timeout_s,
            default_max_tokens=(cfg.max_tokens if cfg.max_tokens is not None else 1024),
        )
    return OpenAIClient(base_url=cfg.base_url, api_key=cfg.api_key, default_model=cfg.model, timeout_s=cfg.timeout_s)
