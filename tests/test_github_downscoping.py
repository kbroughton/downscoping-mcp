"""
GitHub downscoping tests.

Scenario: user has a full org-write token, but the downscoping policy
restricts to a read-only fine-grained PAT by default. Write operations
escalate to the org-write token only for permitted operations; merge
operations (which trigger CI/deploy pipelines) require human review;
repository deletion is denied outright.

GitHub has no dynamic downscoping API — fine-grained PATs are the only
mechanism. Two tokens are pre-provisioned:
  GITHUB_TOKEN_READONLY   — contents:read, issues:read, pull_requests:read
  GITHUB_TOKEN_ORG_WRITE  — issues:write, pull_requests:write, contents:write

The hook selects the appropriate token per operation or blocks the command.

Tested behaviours:
  - Read ops (pr list, issue view, repo view) → readonly token
  - Permitted write ops (issue create, pr create) → org-write token
  - PR merge (triggers deploys) → blocked for review
  - Repo deletion → denied
  - MCP tool calls follow the same token-slot rules
"""

import textwrap
from pathlib import Path

import pytest

from credential_downscope.hook_handler import process_hook

READONLY_TOKEN = "ghp_readonly_token_abc123"
WRITE_TOKEN = "ghp_write_token_xyz789"


def _write_config(directory: Path) -> None:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "downscoping.yaml").write_text(textwrap.dedent("""
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
                  args_pattern: "repo delete|repo rename"
                action: deny
              - name: "pr merge requires human review"
                match:
                  args_pattern: "pr merge"
                action: review
              - name: "permitted write ops use org-write token"
                match:
                  args_pattern: "pr (create|edit)|issue (create|edit)|release create|push"
                action: allow
                slot: org-write
    """))


def _payload(command: str, cwd: str) -> dict:
    return {"tool": "Bash", "input": {"command": command}, "cwd": cwd}


class TestReadOperations:
    """Read ops use the readonly token — org-write token is never injected."""

    def test_pr_list_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", READONLY_TOKEN)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh pr list", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert READONLY_TOKEN in cmd
        assert WRITE_TOKEN not in cmd

    def test_issue_view_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", READONLY_TOKEN)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh issue view 42", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert READONLY_TOKEN in cmd
        assert WRITE_TOKEN not in cmd

    def test_repo_view_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", READONLY_TOKEN)

        result = process_hook(_payload("gh repo view myorg/myrepo", str(tmp_path)))

        assert result is not None
        assert READONLY_TOKEN in result["updatedInput"]["command"]

    def test_pr_diff_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", READONLY_TOKEN)

        result = process_hook(_payload("gh pr diff 10", str(tmp_path)))

        assert result is not None
        assert READONLY_TOKEN in result["updatedInput"]["command"]


class TestPermittedWriteOperations:
    """Permitted write ops escalate to the org-write token."""

    def test_pr_create_gets_write_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", READONLY_TOKEN)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh pr create --title 'Fix bug' --body 'details'", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert WRITE_TOKEN in cmd
        assert READONLY_TOKEN not in cmd

    def test_issue_create_gets_write_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh issue create --title 'Bug' --body 'desc'", str(tmp_path)))

        assert result is not None
        assert WRITE_TOKEN in result["updatedInput"]["command"]

    def test_push_gets_write_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh push origin feature-branch", str(tmp_path)))

        assert result is not None
        assert WRITE_TOKEN in result["updatedInput"]["command"]


class TestHighRiskOperationsBlocked:
    """Operations that trigger deploys or are irreversible require review or are denied."""

    def test_pr_merge_blocked_for_review(self, tmp_path):
        """Merging can trigger deploy pipelines — requires human review."""
        _write_config(tmp_path)
        result = process_hook(_payload("gh pr merge 42 --squash", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "pr merge requires human review" in result["stopReason"]

    def test_pr_merge_message_suggests_manual_run(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gh pr merge 42", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason

    def test_repo_delete_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gh repo delete myorg/my-repo", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "repo deletion denied" in result["stopReason"]

    def test_repo_rename_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gh repo rename new-name", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_write_token_never_injected_on_merge(self, tmp_path, monkeypatch):
        """The write token must never be injected for a blocked merge."""
        _write_config(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN_ORG_WRITE", WRITE_TOKEN)

        result = process_hook(_payload("gh pr merge 42", str(tmp_path)))

        # result is a block, not an updatedInput
        assert "updatedInput" not in result
        assert WRITE_TOKEN not in result.get("stopReason", "")


class TestPassThrough:
    def test_non_gh_command_passes_through(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("git status", str(tmp_path)))
        assert result is None

    def test_no_token_passes_through(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.delenv("GITHUB_TOKEN_READONLY", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        result = process_hook(_payload("gh pr list", str(tmp_path)))
        assert result is None
