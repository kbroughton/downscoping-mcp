"""
AWS downscoping tests.

Scenario: ambient credential has s3:PutObject on a test bucket, but the
downscoping policy only allows s3:GetObject / s3:ListBucket.

With sts_policy mode (the preferred approach), the hook would call
sts:GetFederationToken with an inline policy that permits only read actions,
producing a short-lived token whose effective permissions are the intersection
of the caller's identity policies and the inline policy.

In token_slot mode (the fallback tested here), the hook injects a
pre-provisioned read-only credential instead of the write-capable ambient one.

Tested behaviours:
  - Read operations (s3 ls, s3 cp download) → readonly token injected
  - Write operations (s3 cp upload, s3 rm, s3 sync) → blocked for review
  - Destructive operations (s3 rb, rm --recursive) → blocked for review
  - IAM mutations → denied outright
  - Service-agnostic commands (e.g. docker) → pass-through
"""

import textwrap
from pathlib import Path

import pytest

from credential_downscope.hook_handler import process_hook

# Simulated ambient write credential (what the user normally has)
WRITE_KEY = "AKIAIOSFODNN7WRITE"
# Simulated downscoped read-only credential
READONLY_KEY = "AKIAIOSFODNN7READ"

BUCKET = "s3://test-bucket"


def _write_config(directory: Path) -> None:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "downscoping.yaml").write_text(textwrap.dedent("""
        version: 1
        services:
          aws:
            downscope_mode: token_slot
            token_slots:
              readonly:
                env_var: AWS_ACCESS_KEY_ID_READONLY
                inject_as: AWS_ACCESS_KEY_ID
              write:
                env_var: AWS_ACCESS_KEY_ID_WRITE
                inject_as: AWS_ACCESS_KEY_ID
            default_slot: readonly
            rules:
              - name: "S3 uploads require review"
                match:
                  args_pattern: "s3 cp .* s3://"
                action: review
              - name: "S3 delete requires review"
                match:
                  args_pattern: "s3 (rm|rb|sync.*--delete)"
                action: review
              - name: "IAM mutations denied"
                match:
                  args_pattern: "iam (create|delete|put|attach|detach|update|tag)"
                action: deny
    """))


def _payload(command: str, cwd: str) -> dict:
    return {"tool": "Bash", "input": {"command": command}, "cwd": cwd}


class TestS3ReadOperations:
    """Read ops should receive the readonly token, not the write token."""

    def test_s3_ls_bucket_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_READONLY", READONLY_KEY)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_WRITE", WRITE_KEY)

        result = process_hook(_payload(f"aws s3 ls {BUCKET}/", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert READONLY_KEY in cmd
        assert WRITE_KEY not in cmd

    def test_s3_cp_download_gets_readonly_token(self, tmp_path, monkeypatch):
        """Downloading FROM s3 is a read; write token should not be used."""
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_READONLY", READONLY_KEY)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_WRITE", WRITE_KEY)

        result = process_hook(_payload(f"aws s3 cp {BUCKET}/file.txt ./local.txt", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert READONLY_KEY in cmd
        assert WRITE_KEY not in cmd

    def test_s3_presign_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_READONLY", READONLY_KEY)

        result = process_hook(_payload(f"aws s3 presign {BUCKET}/file.txt", str(tmp_path)))

        assert result is not None
        assert READONLY_KEY in result["updatedInput"]["command"]

    def test_ec2_describe_gets_readonly_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_READONLY", READONLY_KEY)

        result = process_hook(_payload("aws ec2 describe-instances", str(tmp_path)))

        assert result is not None
        assert READONLY_KEY in result["updatedInput"]["command"]


class TestS3WriteOperationsBlocked:
    """Write ops should be blocked — ambient write credential is never injected."""

    def test_s3_cp_upload_is_blocked_for_review(self, tmp_path, monkeypatch):
        """Core scenario: user has s3:PutObject, downscoping restricts to read."""
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_READONLY", READONLY_KEY)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_WRITE", WRITE_KEY)

        result = process_hook(_payload(f"aws s3 cp ./data.csv {BUCKET}/data.csv", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        # Write key must NEVER appear — the command was blocked before execution
        assert WRITE_KEY not in result.get("stopReason", "")
        assert "S3 uploads require review" in result["stopReason"]

    def test_s3_rm_is_blocked_for_review(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID_WRITE", WRITE_KEY)

        result = process_hook(_payload(f"aws s3 rm {BUCKET}/file.txt", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_s3_recursive_delete_is_blocked(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        result = process_hook(_payload(f"aws s3 rm {BUCKET}/ --recursive", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_s3_sync_with_delete_is_blocked(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        result = process_hook(_payload(f"aws s3 sync ./local/ {BUCKET}/ --delete", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_block_message_names_matched_pattern(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(f"aws s3 cp ./file.txt {BUCKET}/file.txt", str(tmp_path)))

        reason = result["stopReason"]
        assert "s3 cp" in reason or "s3://" in reason or "S3 uploads" in reason

    def test_block_message_suggests_manual_run(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(f"aws s3 cp ./file.txt {BUCKET}/file.txt", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason


class TestIAMMutationsDenied:
    def test_iam_create_user_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("aws iam create-user --user-name alice", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "IAM mutations denied" in result["stopReason"]

    def test_iam_attach_policy_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(
            "aws iam attach-role-policy --role-name MyRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            str(tmp_path)
        ))

        assert result is not None
        assert result.get("continue") is False

    def test_iam_delete_role_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("aws iam delete-role --role-name MyRole", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_deny_message_different_from_review_message(self, tmp_path):
        _write_config(tmp_path)
        review = process_hook(_payload(f"aws s3 cp ./f.txt {BUCKET}/f.txt", str(tmp_path)))
        deny = process_hook(_payload("aws iam create-user --user-name alice", str(tmp_path)))

        # Review message should suggest manual run; deny message should not
        assert "manual" in review["stopReason"].lower() or "terminal" in review["stopReason"].lower()
        assert "not permitted" in deny["stopReason"].lower() or "denied" in deny["stopReason"].lower()


class TestPassThrough:
    def test_non_aws_command_passes_through(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("docker build .", str(tmp_path)))
        assert result is None

    def test_no_token_passes_through(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.delenv("AWS_ACCESS_KEY_ID_READONLY", raising=False)
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        result = process_hook(_payload("aws s3 ls", str(tmp_path)))
        assert result is None
