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


class LLMConnector(ABC):
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg

    @abstractmethod
    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        ...

    def complete_json(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> Any:
        """Ask for strict JSON and parse it, stripping code fences defensively."""
        raw = self.complete(messages, system=system)
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
        return json.loads(cleaned)


class AnthropicConnector(LLMConnector):
    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        import anthropic  # local import so other backends don't require this dep
        if not cfg.api_key:
            raise RuntimeError(
                f"No API key found in env var {cfg.api_key_env}. Set it before running."
            )
        self.client = anthropic.Anthropic(api_key=cfg.api_key)

    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
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
        if not cfg.api_key:
            raise RuntimeError(
                f"No API key found in env var {cfg.api_key_env}. Set it before running."
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
            headers={"Authorization": f"Bearer {self.cfg.api_key}"},
            json=payload,
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class OllamaConnector(LLMConnector):
    """Fully local backend via Ollama's OpenAI-compatible /v1/chat/completions."""

    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        self.base_url = (cfg.base_url or "http://localhost:11434/v1").rstrip("/")

    def complete(self, messages: list[dict[str, str]], system: str = SYSTEM_PROMPT) -> str:
        payload = {
            "model": self.cfg.model,
            "temperature": self.cfg.temperature,
            "messages": [{"role": "system", "content": system}] + messages,
        }
        r = requests.post(f"{self.base_url}/chat/completions", json=payload, timeout=180)
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
