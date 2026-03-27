"""Tests for RuleMatcher and token resolution."""

import os
import pytest

from credential_downscope.rules import RuleMatcher, resolve_token

GH_CONFIG = {
    "services": {
        "gh": {
            "token_slots": {
                "readonly": {
                    "env_var": "GITHUB_TOKEN_READONLY",
                    "inject_as": "GITHUB_TOKEN",
                },
                "org-write": {
                    "env_var": "GITHUB_TOKEN_ORG_WRITE",
                    "inject_as": "GITHUB_TOKEN",
                },
            },
            "default_slot": "readonly",
            "rules": [
                {
                    "name": "writes need elevated token",
                    "match": {
                        "args_pattern": r"pr (create|merge|edit)|issue (create|edit)|push|release create"
                    },
                    "slot": "org-write",
                },
                {
                    "name": "specific org",
                    "match": {"args_pattern": r"--repo myorg/"},
                    "slot": "org-write",
                },
            ],
        }
    }
}

MCP_CONFIG = {
    "services": {
        "mcp": {
            "token_slots": {
                "readonly": {"env_var": "GITHUB_TOKEN_READONLY", "inject_as": "GITHUB_TOKEN"},
                "org-write": {"env_var": "GITHUB_TOKEN_ORG_WRITE", "inject_as": "GITHUB_TOKEN"},
            },
            "default_slot": "readonly",
            "rules": [
                {
                    "match": {
                        "tools": ["create_issue", "create_pr", "merge_pr", "update_pr_description"]
                    },
                    "slot": "org-write",
                }
            ],
        }
    }
}


class TestRuleMatcherBash:
    def _matcher(self):
        return RuleMatcher(GH_CONFIG, "gh")

    def test_default_slot_for_read(self):
        assert self._matcher().resolve_for_command("pr list") == "readonly"

    def test_pr_create_maps_to_write(self):
        assert self._matcher().resolve_for_command("pr create --title foo") == "org-write"

    def test_pr_merge_maps_to_write(self):
        assert self._matcher().resolve_for_command("pr merge 42") == "org-write"

    def test_issue_create_maps_to_write(self):
        assert self._matcher().resolve_for_command("issue create") == "org-write"

    def test_push_maps_to_write(self):
        assert self._matcher().resolve_for_command("push origin main") == "org-write"

    def test_release_create_maps_to_write(self):
        assert self._matcher().resolve_for_command("release create v1.0") == "org-write"

    def test_org_repo_maps_to_write(self):
        assert self._matcher().resolve_for_command("pr list --repo myorg/myrepo") == "org-write"

    def test_issue_view_stays_readonly(self):
        assert self._matcher().resolve_for_command("issue view 10") == "readonly"

    def test_pr_view_stays_readonly(self):
        assert self._matcher().resolve_for_command("pr view 5") == "readonly"


class TestRuleMatcherMcp:
    def _matcher(self):
        return RuleMatcher(MCP_CONFIG, "mcp")

    def test_create_issue_maps_to_write(self):
        assert self._matcher().resolve_for_tool("create_issue") == "org-write"

    def test_merge_pr_maps_to_write(self):
        assert self._matcher().resolve_for_tool("merge_pr") == "org-write"

    def test_get_pr_diff_stays_readonly(self):
        assert self._matcher().resolve_for_tool("get_pr_diff") == "readonly"

    def test_list_open_issues_stays_readonly(self):
        assert self._matcher().resolve_for_tool("list_open_issues_prs") == "readonly"


class TestResolveToken:
    def test_returns_env_var_value(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN_READONLY", "ghp_read123")
        token, inject_as = resolve_token(GH_CONFIG, "gh", "readonly")
        assert token == "ghp_read123"
        assert inject_as == "GITHUB_TOKEN"

    def test_falls_back_to_inject_as(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN_READONLY", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_fallback")
        token, inject_as = resolve_token(GH_CONFIG, "gh", "readonly")
        assert token == "ghp_fallback"
        assert inject_as == "GITHUB_TOKEN"

    def test_returns_none_when_no_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN_READONLY", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        token, inject_as = resolve_token(GH_CONFIG, "gh", "readonly")
        assert token is None
        assert inject_as == "GITHUB_TOKEN"
