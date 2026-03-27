"""Load and validate .claude/downscoping.yaml, walking up from cwd."""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "downscoping.yaml"
CONFIG_DIR = ".claude"


def find_config_path(start: str | Path) -> Path | None:
    """Walk up directory tree from *start* looking for .claude/downscoping.yaml."""
    current = Path(start).resolve()
    while True:
        candidate = current / CONFIG_DIR / CONFIG_FILENAME
        if candidate.exists():
            return candidate
        parent = current.parent
        if parent == current:
            return None
        current = parent


def load_config(cwd: str | Path) -> dict[str, Any] | None:
    """Return parsed config dict, or None if no config file is found."""
    path = find_config_path(cwd)
    if path is None:
        logger.debug("No %s/%s found in %s or any parent", CONFIG_DIR, CONFIG_FILENAME, cwd)
        return None
    return _load_config_from_path(str(path))


@lru_cache(maxsize=32)
def _load_config_from_path(path: str) -> dict[str, Any]:
    with open(path) as fh:
        cfg = yaml.safe_load(fh)
    _validate(cfg, path)
    return cfg


def _validate(cfg: dict[str, Any], path: str) -> None:
    """Warn about misconfigured slots; never raise (plugin must not break normal operation)."""
    if not isinstance(cfg, dict):
        logger.warning("[downscope] %s: config root must be a mapping", path)
        return

    version = cfg.get("version")
    if version != 1:
        logger.warning("[downscope] %s: unknown config version %r (expected 1)", path, version)

    services = cfg.get("services", {})
    if not isinstance(services, dict):
        logger.warning("[downscope] %s: 'services' must be a mapping", path)
        return

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        slots = svc.get("token_slots", {})
        for slot_name, slot in (slots or {}).items():
            if not isinstance(slot, dict):
                continue
            env_var = slot.get("env_var")
            if env_var and not os.environ.get(env_var):
                inject_as = slot.get("inject_as", env_var)
                fallback = os.environ.get(inject_as)
                if not fallback:
                    logger.warning(
                        "[downscope] service=%s slot=%s: env var %s not set and no fallback %s",
                        svc_name, slot_name, env_var, inject_as,
                    )
