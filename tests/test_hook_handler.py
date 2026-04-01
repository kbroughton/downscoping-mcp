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
        downscope_mode: token_slot
        token_slots:
          readonly:
            env_var: GITHUB_TOKEN_READONLY
            inject_as: GITHUB_TOKEN
          org-write:
            env_var: GITHUB_TOKEN_ORG_WRITE
            inject_as: GITHUB_TOKEN
        default_slot: readonly
        rules:
          - name: "repo deletion denied"
            match:
              args_pattern: "repo delete"
            action: deny
          - name: "pr merge requires human review"
            match:
              args_pattern: "pr merge"
            action: review
          - name: "writes need elevated token"
            match:
              args_pattern: "pr (create|edit)|issue (create|edit)|push|release create"
            action: allow
            slot: org-write
"""

AWS_CONFIG_YAML = """
    version: 1
    services:
      aws:
        downscope_mode: token_slot
        token_slots:
          readonly:
            env_var: AWS_ACCESS_KEY_ID_READONLY
            inject_as: AWS_ACCESS_KEY_ID
          admin:
            env_var: AWS_ACCESS_KEY_ID_ADMIN
            inject_as: AWS_ACCESS_KEY_ID
        default_slot: readonly
        rules:
          - name: "S3 writes require review"
            match:
              args_pattern: "s3 (cp|mv|rm|sync) .*s3://"
            action: review
          - name: "IAM mutations denied"
            match:
              args_pattern: "iam (create|delete|put|attach|detach)"
            action: deny
"""


class TestPassThrough:
    def test_non_bash_tool_passes_through(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook({"tool": "Read", "input": {"file_path": "/tmp/x"}, "cwd": str(tmp_path)})
        assert result is None

    def test_no_config_passes_through(self, tmp_path):
        result = process_hook(_make_payload("gh pr list", str(tmp_path)))
        assert result is None

    def test_unknown_service_passes_through(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("docker build .", str(tmp_path)))
        assert result is None


class TestTokenInjection:
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
        assert "'ghp_read with spaces'" in cmd

    def test_inherits_config_from_parent(self, tmp_path, monkeypatch):
        _write_config(tmp_path, GH_CONFIG_YAML)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", "ghp_read")
        nested = tmp_path / "deep" / "dir"
        nested.mkdir(parents=True)
        result = process_hook(_make_payload("gh pr list", str(nested)))
        assert result is not None
        assert "ghp_read" in result["updatedInput"]["command"]


class TestDenyAction:
    def test_repo_delete_is_blocked(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh repo delete my-repo", str(tmp_path)))
        assert result is not None
        assert result.get("continue") is False

    def test_deny_message_contains_rule_name(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh repo delete my-repo", str(tmp_path)))
        reason = result["stopReason"]
        assert "repo deletion denied" in reason

    def test_deny_message_contains_matched_pattern(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh repo delete my-repo", str(tmp_path)))
        reason = result["stopReason"]
        assert "repo delete" in reason

    def test_deny_message_says_not_permitted(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh repo delete my-repo", str(tmp_path)))
        reason = result["stopReason"].lower()
        assert "not permitted" in reason or "denied" in reason

    def test_aws_iam_create_is_denied(self, tmp_path):
        _write_config(tmp_path, AWS_CONFIG_YAML)
        result = process_hook(_make_payload("aws iam create-user --user-name alice", str(tmp_path)))
        assert result is not None
        assert result.get("continue") is False
        assert "IAM mutations denied" in result["stopReason"]


class TestReviewAction:
    def test_pr_merge_requires_review(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh pr merge 42", str(tmp_path)))
        assert result is not None
        assert result.get("continue") is False

    def test_review_message_mentions_manual_run(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh pr merge 42", str(tmp_path)))
        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason

    def test_review_message_contains_rule_name(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        result = process_hook(_make_payload("gh pr merge 42", str(tmp_path)))
        assert "pr merge requires human review" in result["stopReason"]

    def test_aws_s3_upload_requires_review(self, tmp_path):
        _write_config(tmp_path, AWS_CONFIG_YAML)
        result = process_hook(_make_payload("aws s3 cp ./file.txt s3://my-bucket/file.txt", str(tmp_path)))
        assert result is not None
        assert result.get("continue") is False
        assert "S3 writes require review" in result["stopReason"]

    def test_review_differs_from_deny_message(self, tmp_path):
        _write_config(tmp_path, GH_CONFIG_YAML)
        deny_result = process_hook(_make_payload("gh repo delete my-repo", str(tmp_path)))
        review_result = process_hook(_make_payload("gh pr merge 42", str(tmp_path)))
        # deny says "not permitted"; review says "requires human review" / "run manually"
        assert deny_result["stopReason"] != review_result["stopReason"]
        assert "not permitted" in deny_result["stopReason"].lower() or "denied" in deny_result["stopReason"].lower()
        assert "review" in review_result["stopReason"].lower() or "manual" in review_result["stopReason"].lower()
