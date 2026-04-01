"""
kubectl downscoping tests.

Scenario: ambient credential has full deployer access to a cluster namespace,
but the downscoping policy restricts to viewer access by default. Mutations
(apply, scale, delete deployments) require human review; RBAC mutations are
denied outright; exec into pods requires review.

token_slot mode is used here (the current implementation). For EKS clusters
the backing AWS IAM role can be downscoped via sts:AssumeRole; for GKE clusters
via GCP Credential Access Boundary. See docs/KUBECTL_DOWNSCOPING.md for details.

Tested behaviours:
  - Read ops (get, describe, logs) → viewer token injected
  - Mutating ops (apply, scale, delete deploy) → blocked for review
  - RBAC mutations → denied
  - exec into pod → blocked for review
  - Non-kubectl commands → pass-through
"""

import textwrap
from pathlib import Path

import pytest

from credential_downscope.hook_handler import process_hook

VIEWER_TOKEN = "kube_viewer_token_abc"
DEPLOYER_TOKEN = "kube_deployer_token_xyz"


def _write_config(directory: Path) -> None:
    claude_dir = directory / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "downscoping.yaml").write_text(textwrap.dedent("""
        version: 1
        services:
          kubectl:
            downscope_mode: token_slot
            token_slots:
              viewer:
                env_var: KUBE_TOKEN_VIEWER
                inject_as: KUBE_TOKEN
              deployer:
                env_var: KUBE_TOKEN_DEPLOYER
                inject_as: KUBE_TOKEN
            default_slot: viewer
            rules:
              - name: "RBAC mutations denied"
                match:
                  args_pattern: "(create|delete|edit) (clusterrole|clusterrolebinding|role|rolebinding)"
                action: deny
              - name: "exec into pod requires review"
                match:
                  args_pattern: "exec "
                action: review
              - name: "cluster mutations require review"
                match:
                  args_pattern: "apply|scale|rollout|patch|replace|delete (deployment|service|pod|statefulset|daemonset|job|namespace)"
                action: review
    """))


def _payload(command: str, cwd: str) -> dict:
    return {"tool": "Bash", "input": {"command": command}, "cwd": cwd}


class TestReadOperations:
    """Read ops should receive the viewer token, not the deployer token."""

    def test_get_pods_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("KUBE_TOKEN_DEPLOYER", DEPLOYER_TOKEN)

        result = process_hook(_payload("kubectl get pods -n default", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert VIEWER_TOKEN in cmd
        assert DEPLOYER_TOKEN not in cmd

    def test_describe_deployment_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("KUBE_TOKEN_DEPLOYER", DEPLOYER_TOKEN)

        result = process_hook(_payload("kubectl describe deployment my-app -n production", str(tmp_path)))

        assert result is not None
        cmd = result["updatedInput"]["command"]
        assert VIEWER_TOKEN in cmd
        assert DEPLOYER_TOKEN not in cmd

    def test_get_logs_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)

        result = process_hook(_payload("kubectl logs deploy/my-app -n default --tail=100", str(tmp_path)))

        assert result is not None
        assert VIEWER_TOKEN in result["updatedInput"]["command"]

    def test_get_services_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)

        result = process_hook(_payload("kubectl get services -n production", str(tmp_path)))

        assert result is not None
        assert VIEWER_TOKEN in result["updatedInput"]["command"]

    def test_get_configmap_gets_viewer_token(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)

        result = process_hook(_payload("kubectl get configmap app-config -n default -o yaml", str(tmp_path)))

        assert result is not None
        assert VIEWER_TOKEN in result["updatedInput"]["command"]


class TestMutatingOperationsBlocked:
    """Mutating ops should be blocked — deployer token is never injected."""

    def test_apply_manifest_is_blocked(self, tmp_path, monkeypatch):
        """Core scenario: user has deploy access, downscoping restricts to read."""
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_VIEWER", VIEWER_TOKEN)
        monkeypatch.setenv("KUBE_TOKEN_DEPLOYER", DEPLOYER_TOKEN)

        result = process_hook(_payload("kubectl apply -f deployment.yaml", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert DEPLOYER_TOKEN not in result.get("stopReason", "")
        assert "cluster mutations require review" in result["stopReason"]

    def test_scale_deployment_is_blocked(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_DEPLOYER", DEPLOYER_TOKEN)

        result = process_hook(_payload("kubectl scale deployment my-app --replicas=0", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_delete_deployment_is_blocked(self, tmp_path):
        _write_config(tmp_path)

        result = process_hook(_payload("kubectl delete deployment my-app -n production", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_rollout_restart_is_blocked(self, tmp_path):
        _write_config(tmp_path)

        result = process_hook(_payload("kubectl rollout restart deployment/my-app", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_delete_namespace_is_blocked(self, tmp_path):
        _write_config(tmp_path)

        result = process_hook(_payload("kubectl delete namespace staging", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_block_message_suggests_manual_run(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("kubectl apply -f deploy.yaml", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason

    def test_deployer_token_never_injected_on_apply(self, tmp_path, monkeypatch):
        """Confirms the deployer token is not present in the blocked response."""
        _write_config(tmp_path)
        monkeypatch.setenv("KUBE_TOKEN_DEPLOYER", DEPLOYER_TOKEN)

        result = process_hook(_payload("kubectl apply -f deploy.yaml", str(tmp_path)))

        assert "updatedInput" not in result
        assert DEPLOYER_TOKEN not in result.get("stopReason", "")


class TestRBACMutationsDenied:
    def test_create_clusterrolebinding_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(
            "kubectl create clusterrolebinding admin-binding --clusterrole=cluster-admin --user=alice",
            str(tmp_path)
        ))

        assert result is not None
        assert result.get("continue") is False
        assert "RBAC mutations denied" in result["stopReason"]

    def test_delete_clusterrole_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("kubectl delete clusterrole my-role", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False

    def test_create_rolebinding_denied(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload(
            "kubectl create rolebinding dev-binding --role=developer --user=alice -n dev",
            str(tmp_path)
        ))

        assert result is not None
        assert result.get("continue") is False


class TestExecBlocked:
    def test_exec_into_pod_requires_review(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("kubectl exec -it my-pod -- /bin/bash", str(tmp_path)))

        assert result is not None
        assert result.get("continue") is False
        assert "exec into pod requires review" in result["stopReason"]

    def test_exec_block_message_suggests_manual_run(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("kubectl exec -it my-pod -- sh", str(tmp_path)))

        reason = result["stopReason"].lower()
        assert "manual" in reason or "manually" in reason or "terminal" in reason


class TestPassThrough:
    def test_non_kubectl_command_passes_through(self, tmp_path):
        _write_config(tmp_path)
        result = process_hook(_payload("helm list -n default", str(tmp_path)))
        assert result is None

    def test_no_token_passes_through(self, tmp_path, monkeypatch):
        _write_config(tmp_path)
        monkeypatch.delenv("KUBE_TOKEN_VIEWER", raising=False)
        monkeypatch.delenv("KUBE_TOKEN", raising=False)
        result = process_hook(_payload("kubectl get pods", str(tmp_path)))
        assert result is None
