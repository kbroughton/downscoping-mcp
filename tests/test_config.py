"""Tests for config loading."""

import os
import textwrap
import tempfile
from pathlib import Path

import pytest
import yaml

from credential_downscope.config import find_config_path, load_config


def _write_config(directory: Path, content: str) -> Path:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    config_path = claude_dir / "downscoping.yaml"
    config_path.write_text(textwrap.dedent(content))
    return config_path


def test_find_config_in_current_dir(tmp_path):
    _write_config(tmp_path, "version: 1\nservices: {}")
    assert find_config_path(tmp_path) == tmp_path / ".claude" / "downscoping.yaml"


def test_find_config_in_parent_dir(tmp_path):
    _write_config(tmp_path, "version: 1\nservices: {}")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    found = find_config_path(nested)
    assert found == tmp_path / ".claude" / "downscoping.yaml"


def test_find_config_returns_none_when_missing(tmp_path):
    assert find_config_path(tmp_path) is None


def test_load_config_returns_none_when_missing(tmp_path):
    assert load_config(tmp_path) is None


def test_load_config_parses_services(tmp_path):
    _write_config(tmp_path, """
        version: 1
        services:
          gh:
            token_slots:
              readonly:
                env_var: GITHUB_TOKEN_READONLY
                inject_as: GITHUB_TOKEN
            default_slot: readonly
            rules: []
    """)
    cfg = load_config(tmp_path)
    assert cfg is not None
    assert "gh" in cfg["services"]
    assert cfg["services"]["gh"]["default_slot"] == "readonly"
