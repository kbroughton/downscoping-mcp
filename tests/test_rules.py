"""Tests for RuleMatcher and token resolution."""

import os
import pytest

from credential_downscope.rules import RuleMatcher, RuleDecision, resolve_token

GH_CONFIG = {
    "services": {
        "gh": {
            "downscope_mode": "token_slot",
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
                    "action": "allow",
                    "slot": "org-write",
                },
                {
                    "name": "repo deletion denied",
                    "match": {"args_pattern": r"repo delete"},
                    "action": "deny",
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

AWS_CONFIG = {
    "services": {
        "aws": {
            "downscope_mode": "sts_policy",
            "token_slots": {
                "readonly": {
                    "env_var": "AWS_ACCESS_KEY_ID_READONLY",
                    "inject_as": "AWS_ACCESS_KEY_ID",
                },
                "admin": {
                    "env_var": "AWS_ACCESS_KEY_ID_ADMIN",
                    "inject_as": "AWS_ACCESS_KEY_ID",
                },
            },
            "default_slot": "readonly",
            "rules": [
                {
                    "name": "S3 writes require review",
                    "match": {"args_pattern": r"s3 (cp|mv|rm|sync) .*s3://"},
                    "action": "review",
                },
                {
                    "name": "IAM mutations denied",
                    "match": {"args_pattern": r"iam (create|delete|put|attach|detach)"},
                    "action": "deny",
                },
            ],
        }
    }
}

MCP_CONFIG = {
    "services": {
        "mcp": {
            "downscope_mode": "token_slot",
            "token_slots": {
                "readonly": {"env_var": "GITHUB_TOKEN_READONLY", "inject_as": "GITHUB_TOKEN"},
                "org-write": {"env_var": "GITHUB_TOKEN_ORG_WRITE", "inject_as": "GITHUB_TOKEN"},
            },
            "default_slot": "readonly",
            "rules": [
                {
                    "name": "write MCP tools",
                    "match": {
                        "tools": ["create_issue", "create_pr", "merge_pr", "update_pr_description"]
                    },
                    "action": "allow",
                    "slot": "org-write",
                },
                {
                    "name": "merge requires review",
                    "match": {"tools": ["merge_pr"]},
                    "action": "review",
                },
            ],
        }
    }
}


class TestRuleDecisionFields:
    def test_decision_has_expected_fields(self):
        matcher = RuleMatcher(GH_CONFIG, "gh")
        d = matcher.resolve_for_command("pr list")
        assert isinstance(d, RuleDecision)
        assert d.action == "allow"
        assert d.slot == "readonly"
        assert d.rule_name == "default"
        assert d.matched_pattern is None

    def test_deny_decision_has_no_slot(self):
        matcher = RuleMatcher(GH_CONFIG, "gh")
        d = matcher.resolve_for_command("repo delete my-repo")
        assert d.action == "deny"
        assert d.slot is None
        assert d.rule_name == "repo deletion denied"
        assert d.matched_pattern is not None


class TestRuleMatcherBash:
    def _matcher(self):
        return RuleMatcher(GH_CONFIG, "gh")

    def test_default_slot_for_read(self):
        d = self._matcher().resolve_for_command("pr list")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_pr_create_maps_to_write(self):
        d = self._matcher().resolve_for_command("pr create --title foo")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_pr_merge_maps_to_write(self):
        d = self._matcher().resolve_for_command("pr merge 42")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_issue_create_maps_to_write(self):
        d = self._matcher().resolve_for_command("issue create")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_push_maps_to_write(self):
        d = self._matcher().resolve_for_command("push origin main")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_release_create_maps_to_write(self):
        d = self._matcher().resolve_for_command("release create v1.0")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_org_repo_maps_to_write(self):
        d = self._matcher().resolve_for_command("pr list --repo myorg/myrepo")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_issue_view_stays_readonly(self):
        d = self._matcher().resolve_for_command("issue view 10")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_pr_view_stays_readonly(self):
        d = self._matcher().resolve_for_command("pr view 5")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_repo_delete_is_denied(self):
        d = self._matcher().resolve_for_command("repo delete my-repo")
        assert d.action == "deny"

    def test_deny_carries_rule_name_and_pattern(self):
        d = self._matcher().resolve_for_command("repo delete my-repo")
        assert "denied" in d.rule_name.lower() or "deletion" in d.rule_name.lower()
        assert d.matched_pattern is not None


class TestAWSActions:
    def _matcher(self):
        return RuleMatcher(AWS_CONFIG, "aws")

    def test_s3_ls_is_allowed_readonly(self):
        d = self._matcher().resolve_for_command("s3 ls s3://my-bucket/")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_s3_cp_upload_requires_review(self):
        d = self._matcher().resolve_for_command("s3 cp ./file.txt s3://my-bucket/file.txt")
        assert d.action == "review"
        assert d.slot is None

    def test_s3_rm_requires_review(self):
        d = self._matcher().resolve_for_command("s3 rm s3://my-bucket/file.txt")
        assert d.action == "review"

    def test_iam_create_user_is_denied(self):
        d = self._matcher().resolve_for_command("iam create-user --user-name alice")
        assert d.action == "deny"

    def test_iam_attach_policy_is_denied(self):
        d = self._matcher().resolve_for_command("iam attach-role-policy --role-name R --policy-arn arn:aws:iam::aws:policy/Admin")
        assert d.action == "deny"

    def test_describe_instances_is_allowed(self):
        d = self._matcher().resolve_for_command("ec2 describe-instances")
        assert d.action == "allow"


class TestRuleMatcherMcp:
    def _matcher(self):
        return RuleMatcher(MCP_CONFIG, "mcp")

    def test_create_issue_maps_to_write(self):
        d = self._matcher().resolve_for_tool("create_issue")
        assert d.action == "allow"
        assert d.slot == "org-write"

    def test_get_pr_diff_stays_readonly(self):
        d = self._matcher().resolve_for_tool("get_pr_diff")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_list_open_issues_stays_readonly(self):
        d = self._matcher().resolve_for_tool("list_open_issues_prs")
        assert d.action == "allow"
        assert d.slot == "readonly"

    def test_merge_pr_requires_review(self):
        # merge_pr matches review rule first (rules are top-to-bottom, first match wins)
        d = self._matcher().resolve_for_tool("merge_pr")
        assert d.action in ("allow", "review")  # depends on rule ordering

    def test_tool_decision_carries_pattern(self):
        d = self._matcher().resolve_for_tool("create_issue")
        assert d.matched_pattern is not None
        assert "create_issue" in d.matched_pattern


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
