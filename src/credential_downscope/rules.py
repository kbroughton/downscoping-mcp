"""Rule matching: given a service config and a command or tool name, return the slot."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class RuleMatcher:
    """Evaluate service rules top-to-bottom; first match wins."""

    def __init__(self, config: dict[str, Any], service: str) -> None:
        self._svc = config.get("services", {}).get(service, {})
        self._service = service

    @property
    def default_slot(self) -> str:
        return self._svc.get("default_slot", "default")

    def resolve_for_command(self, command_args: str) -> str:
        """Return slot name for a Bash command (args after the binary name)."""
        for rule in self._svc.get("rules", []):
            match_cfg = rule.get("match", {})
            pattern = match_cfg.get("args_pattern")
            if pattern and re.search(pattern, command_args):
                slot = rule.get("slot", self.default_slot)
                logger.info(
                    "[downscope] service=%s rule=%r matched → slot=%s",
                    self._service, rule.get("name", pattern), slot,
                )
                return slot
        return self.default_slot

    def resolve_for_tool(self, tool_name: str) -> str:
        """Return slot name for an MCP tool call."""
        for rule in self._svc.get("rules", []):
            match_cfg = rule.get("match", {})
            tools = match_cfg.get("tools")
            if tools and tool_name in tools:
                slot = rule.get("slot", self.default_slot)
                logger.info(
                    "[downscope] service=%s tool=%s rule=%r matched → slot=%s",
                    self._service, tool_name, rule.get("name", str(tools)), slot,
                )
                return slot
        return self.default_slot


def resolve_token(config: dict[str, Any], service: str, slot_name: str) -> tuple[str | None, str | None]:
    """Return (token_value, inject_as) for the given slot, with fallback logic.

    Fallback chain:
      1. env_var value
      2. inject_as value (if different from env_var)
      3. (None, inject_as) — no token available
    """
    import os

    slots = config.get("services", {}).get(service, {}).get("token_slots", {})
    slot = slots.get(slot_name, {})

    env_var = slot.get("env_var")
    inject_as = slot.get("inject_as", env_var)

    token = None
    if env_var:
        token = os.environ.get(env_var)
    if token is None and inject_as and inject_as != env_var:
        token = os.environ.get(inject_as)

    return token, inject_as
