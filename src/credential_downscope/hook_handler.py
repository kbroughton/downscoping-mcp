"""Parse Claude Code hook JSON, apply downscoping rules, emit updatedInput or block."""

from __future__ import annotations

import json
import logging
import os
import shlex
import sys
from typing import Any

from .config import load_config
from .rules import RuleMatcher, RuleDecision, resolve_token

logger = logging.getLogger(__name__)


def _detect_service(command: str, config: dict[str, Any]) -> str | None:
    """Return the service key (e.g. 'gh', 'gcloud') if the command starts with a known service binary."""
    services = config.get("services", {})
    cli_services = {k: v for k, v in services.items() if k != "mcp"}

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return None

    binary = os.path.basename(parts[0])
    if binary in cli_services:
        return binary

    for svc in cli_services:
        if svc in binary:
            return svc

    return None


def _args_after_binary(command: str) -> str:
    """Return everything after the first token (the binary name)."""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    return " ".join(parts[1:]) if len(parts) > 1 else ""


def _block_response(decision: RuleDecision, service: str, action_label: str) -> dict[str, Any]:
    """Build a hook response that blocks the command with a descriptive reason."""
    pattern_detail = f" (matched: `{decision.matched_pattern}`)" if decision.matched_pattern else ""
    if action_label == "review":
        reason = (
            f"[downscope] Command blocked for AI use — rule '{decision.rule_name}'"
            f"{pattern_detail} on service '{service}' requires human review. "
            f"If this operation is intentional, run it manually in your terminal."
        )
    else:
        reason = (
            f"[downscope] Command denied — rule '{decision.rule_name}'"
            f"{pattern_detail} on service '{service}' is not permitted for AI use."
        )
    return {"continue": False, "stopReason": reason}


def process_hook(hook_data: dict[str, Any]) -> dict[str, Any] | None:
    """Core logic: given hook payload, return a response dict or None (pass-through).

    Return values:
      None                          → pass-through, no intervention
      {"updatedInput": {...}}       → rewrite command with scoped token
      {"continue": False, ...}      → block command (deny or review)
    """
    tool = hook_data.get("tool") or hook_data.get("toolName", "")
    if tool != "Bash":
        return None

    command = (hook_data.get("input") or {}).get("command", "")
    if not command:
        return None

    cwd = hook_data.get("cwd") or os.getcwd()
    config = load_config(cwd)
    if config is None:
        return None

    service = _detect_service(command, config)
    if service is None:
        return None

    args = _args_after_binary(command)
    matcher = RuleMatcher(config, service)
    decision: RuleDecision = matcher.resolve_for_command(args)

    if decision.action == "deny":
        logger.warning("[downscope] DENIED service=%s rule=%r", service, decision.rule_name)
        return _block_response(decision, service, "deny")

    if decision.action == "review":
        logger.warning("[downscope] REVIEW REQUIRED service=%s rule=%r", service, decision.rule_name)
        return _block_response(decision, service, "review")

    # action == "allow" — inject scoped token if available
    slot_name = decision.slot
    token, inject_as = resolve_token(config, service, slot_name)

    if not token or not inject_as:
        logger.debug(
            "[downscope] service=%s slot=%s: no token available, passing through",
            service, slot_name,
        )
        return None

    quoted_token = shlex.quote(token)
    new_command = f"{inject_as}={quoted_token} {command}"
    logger.info(
        "[downscope] service=%s slot=%s inject_as=%s → rewriting command",
        service, slot_name, inject_as,
    )
    return {"updatedInput": {"command": new_command}}


def run() -> None:
    """Entry point called by Claude Code hook system."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stderr,
    )

    try:
        hook_data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        logger.error("[downscope] failed to parse hook JSON: %s", exc)
        sys.exit(0)

    result = process_hook(hook_data)
    if result is not None:
        print(json.dumps(result))

    sys.exit(0)
