"""
GCP downscoping tests.

Scenario: ambient credential has storage.objects.create on a test bucket, but
the downscoping policy only allows storage.objects.get / storage.buckets.list.

With credential_access_boundary mode (preferred for GCS), the hook exchanges
the ambient token via sts.googleapis.com for a downscoped token restricted to
the viewer role on the bucket. No separate service account needed.

In token_slot mode (fallback, tested here), a pre-provisioned viewer token is
injected instead of the editor token.

Tested behaviours:
  - Read operations (gcloud storage ls, cat) → viewer token injected
  - Write operations (gcloud storage cp upload) → blocked for review
  - Deploy operations (gcloud run deploy, functions deploy) → denied
  - Project-level destructive ops → denied
  - Non-gcloud commands → pass-through
"""

import textwrap
from pathlib import Path

import pytest

from credential_downscope.hook_handler import process_hook

VIEWER_TOKEN = "ya29.viewer_token"
EDITOR_TOKEN = "ya29.editor_token"

BUCKET = "gs://test-bucket"


def _write_config(directory: Path) -> None:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "downscoping.yaml").write_text(textwrap.dedent("""
        version: 1
        services:
          gcloud:
            downscope_mode: token_slot
            token_slots:
              viewer:
                env_var: GCLOUD_TOKEN_VIEWER
                inject_as: CLOUDSDK_AUTH_ACCESS_TOKEN
              editor:
                env_var: GCLOUD_TOKEN_EDITOR
                inject_as: CLOUDSDK_AUTH_ACCESS_TOKEN
            default_slot: viewer
            rules:
              - name: "GCS writes require review"
                match:
                  args_pattern: "storage (cp .* gs://|mv |rm |rsync .*gs://)"
                action: review
              - name: "GCS bucket create/delete require review"
                match:
                  args_pattern: "storage buckets (create|delete)"
                action: review
              - name: "deploys denied"
                match:
                  args_pattern: "run deploy|functions deploy|app deploy|builds submit"
                action: deny
              - name: "project deletion denied"
                match:
                  args_pattern: "projects delete|sql instances delete"
                action: deny
    """))


def _payload(command: str, cwd: str) -> dict:
    return {"tool": "Bash", "input": {"command": command}, "cwd": cwd}


class TestGCSReadOperations:
    """Read ops should receive the viewer token, not the editor token."""

    def test_storage_ls_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("GCLOUD_TOKEN_EDITOR", EDITOR_TOKEN)

        result = process_hook(_payload(f"gcloud storage ls {BUCKET}/", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert VIEWER_TOKEN in cmd
        assert EDITOR_TOKEN not in cmd

    def test_storage_cat_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("GCLOUD_TOKEN_EDITOR", EDITOR_TOKEN)

        result = process_hook(_payload(f"gcloud storage cat {BUCKET}/file.txt", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert VIEWER_TOKEN in cmd
        assert EDITOR_TOKEN not in cmd

    def test_compute_instances_list_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_VIEWER", VIEWER_TOKEN)

        result = process_hook(_payload("gcloud compute instances list", str(tmp_path)))

        assert result is not None
        assert VIEWER_TOKEN in result["updatedInput"]["command"]

    def test_logging_read_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_VIEWER", VIEWER_TOKEN)

        result = process_hook(_payload("gcloud logging read 'resource.type=gce_instance'", str(tmp_path)))

        assert result is not None
        assert VIEWER_TOKEN in result["updatedInput"]["command"]


class TestGCSWriteOperationsBlocked:
    """Write ops should be blocked — editor token is never injected."""

    def test_storage_cp_upload_is_blocked(self, tmp_path, monkeypatch):
        """Core scenario: user has storage.objects.create, downscoping restricts to read."""
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("GCLOUD_TOKEN_EDITOR", EDITOR_TOKEN)

        result = process_hook(_payload(f"gcloud storage cp ./data.csv {BUCKET}/data.csv", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        # Editor token must NEVER appear in the block message
        assert EDITOR_TOKEN not in result.get("stopReason", "")
        assert "GCS writes require review" in result["stopReason"]

    def test_storage_rm_is_blocked(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("GCLOUD_TOKEN_EDITOR", EDITOR_TOKEN)

        result = process_hook(_payload(f"gcloud storage rm {BUCKET}/file.txt", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_storage_rsync_upload_is_blocked(self, tmp_path):
        _write_config(tmp_path)

        result = process_hook(_payload(f"gcloud storage rsync ./local/ {BUCKET}/", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_storage_bucket_create_is_blocked(self, tmp_path):
        _write_config(tmp_path)

        result = process_hook(_payload(f"gcloud storage buckets create {BUCKET}", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_block_message_suggests_manual_run(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(f"gcloud storage cp ./file.txt {BUCKET}/file.txt", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason


class TestDeployOperationsDenied:
    def test_cloud_run_deploy_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gcloud run deploy my-service --image gcr.io/my-project/my-image", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "deploys denied" in result["stopReason"]

    def test_cloud_functions_deploy_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gcloud functions deploy my-function --runtime python311", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_app_engine_deploy_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gcloud app deploy", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_project_delete_is_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gcloud projects delete my-project", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "project deletion denied" in result["stopReason"]

    def test_deploy_deny_message_says_not_permitted(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("gcloud run deploy svc --image img", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "not permitted" in reason or "denied" in reason


class TestPassThrough:
    def test_non_gcloud_command_passes_through(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("kubectl get pods", str(tmp_path)))
        assert result is None

    def test_no_token_passes_through(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.delenv("GCLOUD_TOKEN_VIEWER", raising=False)
        monkeypatch.delenv("CLOUDSDK_AUTH_ACCESS_TOKEN", raising=False)
        result = process_hook(_payload("gcloud storage ls", str(tmp_path)))
        assert result is None
