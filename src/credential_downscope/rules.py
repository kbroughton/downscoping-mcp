"""Rule matching: given a service config and a command or tool name, return a RuleDecision."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

VALID_ACTIONS = {"allow", "deny", "review"}


@dataclass
class RuleDecision:
    """Result of evaluating a rule against a command or tool call."""

    action: str           # "allow", "deny", or "review"
    slot: str | None      # token slot name (for action="allow" with token_slot mode)
    rule_name: str        # human-readable name, used in block messages
    matched_pattern: str | None  # the pattern that triggered this decision


class RuleMatcher:
    """Evaluate service rules top-to-bottom; first match wins."""

    def __init__(self, config: dict[str, Any], service: str) -> None:
        self._svc = config.get("services", {}).get(service, {})
        self._service = service

    @property
    def default_slot(self) -> str:
        return self._svc.get("default_slot", "default")

    def resolve_for_command(self, command_args: str) -> RuleDecision:
        """Return a RuleDecision for a Bash command (args after the binary name)."""
        for rule in self._svc.get("rules", []):
            match_cfg = rule.get("match", {})
            pattern = match_cfg.get("args_pattern")
            if not pattern:
                continue
            if re.search(pattern, command_args):
                action = rule.get("action", "allow")
                slot = rule.get("slot", self.default_slot)
                rule_name = rule.get("name", pattern)
                decision = RuleDecision(
                    action=action,
                    slot=slot if action == "allow" else None,
                    rule_name=rule_name,
                    matched_pattern=pattern,
                )
                logger.info(
                    "[downscope] service=%s rule=%r matched → action=%s slot=%s",
                    self._service, rule_name, action, decision.slot,
                )
                return decision

        return RuleDecision(
            action="allow",
            slot=self.default_slot,
            rule_name="default",
            matched_pattern=None,
        )

    def resolve_for_tool(self, tool_name: str) -> RuleDecision:
        """Return a RuleDecision for an MCP tool call."""
        for rule in self._svc.get("rules", []):
            match_cfg = rule.get("match", {})
            tools = match_cfg.get("tools")
            if tools and tool_name in tools:
                action = rule.get("action", "allow")
                slot = rule.get("slot", self.default_slot)
                rule_name = rule.get("name", str(tools))
                decision = RuleDecision(
                    action=action,
                    slot=slot if action == "allow" else None,
                    rule_name=rule_name,
                    matched_pattern=f"tool:{tool_name}",
                )
                logger.info(
                    "[downscope] service=%s tool=%s rule=%r matched → action=%s",
                    self._service, tool_name, rule_name, action,
                )
                return decision

        return RuleDecision(
            action="allow",
            slot=self.default_slot,
            rule_name="default",
            matched_pattern=None,
        )


def resolve_token(config: dict[str, Any], service: str, slot_name: str) -> tuple[str | None, str | None]:
    """Return (token_value, inject_as) for the given slot, with fallback logic.

    Fallback chain:
      1. env_var value
      2. inject_as value (if different from env_var) — uses ambient credential
      3. (None, inject_as) — no token available, command passes through unmodified
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
