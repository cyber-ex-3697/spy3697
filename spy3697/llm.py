"""Pluggable LLM connectors. The LLM is used purely for *planning* and
*write-up* — deciding which tool to run next given evidence-so-far, and later
turning verified findings into report prose. It never directly executes
anything; the orchestrator interprets its structured proposals and runs them
through the guardrailed tool wrappers.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import requests

from .config import LLMConfig

SYSTEM_PROMPT = """You are the planning module inside SPY-3697, an authorized \
penetration-testing orchestrator. You NEVER invent scan results, flags, credentials, \
or vulnerability confirmations. You may only state a finding as "verified" if you were \
given an evidence_id from the evidence store that supports it. If you are not sure, say so \
and propose the next tool call that would gather more evidence, instead of guessing. \
When asked to produce findings or report content, every factual claim must include the \
evidence_id(s) it is based on in the form [evidence:ID]. If no evidence_id applies, do not \
state the claim as fact — mark it clearly as a hypothesis to verify next."""


def _extract_json_substring(text: str) -> str | None:
    """Find the first balanced {...} or [...] substring in text, scanning past
    any preamble/explanation the model added and ignoring anything after it.
    Handles braces/brackets inside string literals so it doesn't get confused
    by JSON values that themselves contain '{' or '}' characters."""
    start_chars = "{["
    end_chars = "}]"
    for i, ch in enumerate(text):
        if ch in start_chars:
            depth = 0
            in_string = False
            escape = False
            for j in range(i, len(text)):
                c = text[j]
                if in_string:
                    if escape:
                        escape = False
                    elif c == "\\":
                        escape = True
                    elif c == '"':
                        in_string = False
                    continue
                if c == '"':
                    in_string = True
                elif c in start_chars:
                    depth += 1
                elif c in end_chars:
                    depth -= 1
                    if depth == 0:
                        return text[i:j + 1]
            break  # unbalanced from this start point, no valid substring
    return None


class LLMConnector(ABC):
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg

    @abstractmethod
    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        ...

    def complete_json(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> Any:
        """Ask for strict JSON and parse it. Tries a straight parse first
        (after stripping markdown code fences), and if that fails -- common
        with smaller local models that add a preamble or trailing
        explanation around the JSON -- falls back to extracting the first
        balanced JSON object/array substring from the response."""
        raw = self.complete(messages, system=system)
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        extracted = _extract_json_substring(cleaned)
        if extracted is not None:
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass
        raise json.JSONDecodeError(
            f"No valid JSON found in model response: {raw[:300]!r}", cleaned, 0
        )

class AnthropicConnector(LLMConnector):
    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        import anthropic  # local import so other backends don't require this dep
        key = cfg.resolve_api_key()
        if not key:
            raise RuntimeError(
                f"No API key found. Set 'api_key' directly in config.yaml under llm:, "
                f"or export the {cfg.api_key_env} environment variable before running."
            )
        self.client = anthropic.Anthropic(api_key=key)

    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        # NOTE: anthropic-python SDK v1.0+ (Aug 2026) removed temperature/top_p/top_k
        # from messages.create() — current Claude models reject non-default sampling
        # values outright, so the SDK dropped the kwarg. Do not add it back here.
        resp = self.client.messages.create(
            model=self.cfg.model,
            max_tokens=self.cfg.max_tokens,
            system=system,
            messages=messages,
        )
        return "".join(block.text for block in resp.content if block.type == "text")


class OpenAICompatibleConnector(LLMConnector):
    """Works with OpenAI, Azure OpenAI (with base_url set), or any server
    implementing the /v1/chat/completions contract."""

    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        if not cfg.resolve_api_key():
            raise RuntimeError(
                f"No API key found. Set 'api_key' directly in config.yaml under llm:, "
                f"or export the {cfg.api_key_env} environment variable before running."
            )
        self.base_url = (cfg.base_url or "https://api.openai.com/v1").rstrip("/")

    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        payload = {
            "model": self.cfg.model,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            "messages": [{"role": "system", "content": system}] + messages,
        }
        r = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.cfg.resolve_api_key()}"},
            json=payload,
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class OllamaConnector(LLMConnector):
    """Fully local backend via Ollama's OpenAI-compatible /v1/chat/completions.
    CPU-only inference can be slow on real workloads (identify/verify prompts
    include recon evidence, not just a short test message), so the timeout
    here is generous by default -- override via llm.timeout_seconds in
    config.yaml if you need it shorter/longer for your hardware."""

    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        self.base_url = (cfg.base_url or "http://localhost:11434/v1").rstrip("/")
        self.timeout = getattr(cfg, "timeout_seconds", None) or 900

    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        payload = {
            "model": self.cfg.model,
            "temperature": self.cfg.temperature,
            "messages": [{"role": "system", "content": system}] + messages,
        }
        r = requests.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def build_llm(cfg: LLMConfig) -> LLMConnector:
    if cfg.provider == "anthropic":
        return AnthropicConnector(cfg)
    if cfg.provider == "openai_compatible":
        return OpenAICompatibleConnector(cfg)
    if cfg.provider == "ollama":
        return OllamaConnector(cfg)
    raise ValueError(f"Unknown llm.provider: {cfg.provider!r}")
