"""Tests for hook_handler.process_hook."""

import textwrap
from pathlib import Path

import pytest

from credential_downscope.hook_handler import process_hook


def _make_payload(command: str, cwd: str) -> dict:
    return {"tool": "Bash", "input": {"command": command}, "cwd": cwd}


def _write_config(directory: Path, content: str) -> None:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "downscoping.yaml").write_text(textwrap.dedent(content))


GH_CONFIG_YAML = """
    version: 1
    services:
      gh:
        token_slots:
          readonly:
            env_var: GITHUB_TOKEN_READONLY
            inject_as: GITHUB_TOKEN
          org-write:
            env_var: GITHUB_TOKEN_ORG_WRITE
            inject_as: GITHUB_TOKEN
        default_slot: readonly
        rules:
          - match:
              args_pattern: "pr (create|merge|edit)|issue (create|edit)|push|release create"
            slot: org-write
"""


class TestProcessHook:
    def test_non_bash_tool_passes_through(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook({"tool": "Read", "input": {"file_path": "/tmp/x"}, "cwd": str(tmp_path)})
        assert result is None

    def test_no_config_passes_through(self, tmp_path):
        # No config file in tmp_path
        result = process_hook(_make_payload("gh pr list", str(tmp_path)))
        assert result is None

    def test_unknown_service_passes_through(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("docker build .", str(tmp_path)))
        assert result is None

    def test_injects_readonly_token_for_pr_list(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", "ghp_read")
        result = process_hook(_make_payload("gh pr list", str(tmp_path)))
        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert "GITHUB_TOKEN=" in cmd
        assert "ghp_read" in cmd
        assert "gh pr list" in cmd

    def test_injects_write_token_for_pr_create(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", "ghp_write")
        result = process_hook(_make_payload("gh pr create --title test", str(tmp_path)))
        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert "ghp_write" in cmd

    def test_no_injection_when_token_unset(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.delenv("GITHUB_TOKEN_READONLY", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        result = process_hook(_make_payload("gh pr list", str(tmp_path)))
        assert result is None

    def test_token_is_shell_quoted(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", "ghp_read with spaces")
        result = process_hook(_make_payload("gh pr list", str(tmp_path)))
        assert result is not None
        cmd = result["updatedInput"]["command"]
        # shlex.quote wraps in single quotes when value contains spaces
        assert "'ghp_read with spaces'" in cmd

    def test_inherits_config_from_parent(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", "ghp_read")
        nested = tmp_path / "deep" / "dir"
        nested.mkdir(parents=True)
        result = process_hook(_make_payload("gh pr list", str(nested)))
        assert result is not None
        assert "ghp_read" in result["updatedInput"]["command"]
