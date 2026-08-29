"""Config loading for SPY-3697."""
from __future__ import annotations

import os
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass
class LLMConfig:
    provider: str = "anthropic"
    model: str = "claude-sonnet-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    api_key: str | None = None      # optional: set directly in config.yaml instead of an env var
    base_url: str | None = None
    max_tokens: int = 4000
    temperature: float = 0.2
    timeout_seconds: int | None = None  # HTTP request timeout for openai_compatible/ollama;
                                          # falls back to a provider-specific default if unset

    def resolve_api_key(self) -> str | None:
        """Priority: explicit `api_key` in config.yaml, then the env var named
        by `api_key_env`. Letting people put it straight in config.yaml means
        they don't have to `export` it in every new terminal session."""
        if self.api_key:
            return self.api_key
        return os.environ.get(self.api_key_env)


@dataclass
class ToolPaths:
    nmap_path: str = "nmap"
    nuclei_path: str = "nuclei"
    httpx_path: str = "httpx"
    sqlmap_path: str = "sqlmap"
    gobuster_path: str = "gobuster"
    tshark_path: str = "tshark"
    dalfox_path: str = "dalfox"
    trivy_path: str = "trivy"
    wordlist_dir: str = "/usr/share/wordlists"


@dataclass
class Limits:
    max_scan_seconds: int = 900
    max_verify_attempts_per_finding: int = 3
    max_exec_seconds: int = 60
    rate_limit_requests_per_sec: int = 10


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    authorized_targets: list[str] = field(default_factory=list)
    passive_only_targets: list[str] = field(default_factory=list)
    workspace_dir: Path = Path("./workspace")
    tools: ToolPaths = field(default_factory=ToolPaths)
    limits: Limits = field(default_factory=Limits)

    def is_authorized(self, target: str) -> bool:
        """Check target against the authorized_targets allow-list (supports CIDR)."""
        for entry in self.authorized_targets:
            if entry == target:
                return True
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                    addr = ipaddress.ip_address(_resolve_hint(target))
                    if addr in net:
                        return True
            except ValueError:
                continue
        return False

    def is_passive_only(self, target: str) -> bool:
        return target in self.passive_only_targets


def _resolve_hint(target: str) -> str:
    """Best-effort: if target already looks like an IP, use it as-is; otherwise
    this raises and the CIDR check is simply skipped for hostnames (exact-match
    entries in authorized_targets still work for hostnames)."""
    ipaddress.ip_address(target)  # raises ValueError if not an IP literal
    return target


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found at {path}. Copy config.example.yaml to config.yaml first."
        )
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}

    llm_raw = raw.get("llm", {})
    tools_raw = raw.get("tools", {})
    limits_raw = raw.get("limits", {})

    return Config(
        llm=LLMConfig(**{k: v for k, v in llm_raw.items() if k in LLMConfig.__annotations__}),
        authorized_targets=raw.get("authorized_targets", []) or [],
        passive_only_targets=raw.get("passive_only_targets", []) or [],
        workspace_dir=Path(raw.get("workspace_dir", "./workspace")),
        tools=ToolPaths(**{k: v for k, v in tools_raw.items() if k in ToolPaths.__annotations__}),
        limits=Limits(**{k: v for k, v in limits_raw.items() if k in Limits.__annotations__}),
    )
