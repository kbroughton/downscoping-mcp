# kubectl Downscoping

## Current implementation: token_slot mode

The current implementation uses pre-provisioned bearer tokens selected per operation via YAML rules. Two tokens are exported:

- `KUBE_TOKEN_VIEWER` — bound to a read-only ClusterRole
- `KUBE_TOKEN_DEPLOYER` — bound to a deployer Role in specific namespaces

The hook injects the appropriate token via the `KUBE_TOKEN` environment variable before each `kubectl` call.

---

## config.yaml example

```yaml
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
```

---

## Kubernetes RBAC setup

Create minimal ClusterRoles and bind them to dedicated ServiceAccounts:

```yaml
# viewer-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ai-viewer
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps", "events", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ai-viewer
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ai-viewer-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ai-viewer
subjects:
  - kind: ServiceAccount
    name: ai-viewer
    namespace: default
```

Extract the token:

```bash
kubectl create token ai-viewer --duration=8760h > /tmp/viewer-token
export KUBE_TOKEN_VIEWER=$(cat /tmp/viewer-token)
```

---

## Dynamic downscoping: EKS (future)

On EKS, Kubernetes identity maps to AWS IAM via [IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html). This enables dynamic downscoping at the AWS IAM layer:

1. The AI agent assumes a restricted IAM role via `sts:AssumeRole` with an inline policy (see `AWS_DOWNSCOPING.md`)
2. The assumed role maps to a Kubernetes ServiceAccount via the EKS OIDC provider
3. kubectl calls made with that ServiceAccount's token carry only the downscoped IAM permissions

This means the AWS `sts_policy` downscope mode can flow through to EKS workloads without separate Kubernetes RBAC configuration. Implementation is tracked as a future enhancement.

---

## Dynamic downscoping: GKE (future)

On GKE, [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) maps Kubernetes ServiceAccounts to GCP service accounts. Downscoped GCP credentials derived via Credential Access Boundary (see `GCP_DOWNSCOPING.md`) flow through to GKE workloads.

Planned approach:
1. Derive a CAB-restricted GCP access token from the ambient credential
2. Inject via `CLOUDSDK_AUTH_ACCESS_TOKEN` before the `kubectl` call
3. GKE authenticates the call using Workload Identity with the downscoped token

---

## Security notes

- `kubectl exec` opens a shell into a running container — equivalent to SSH access. It is blocked for review by default.
- RBAC mutations (`create clusterrolebinding`) can grant arbitrary cluster-admin. Always denied.
- `kubectl delete namespace` is irreversible in most clusters. Blocked for review.
- Token rotation: ServiceAccount tokens created with `kubectl create token` expire. Use short durations (8h for daily use) and recreate via your shell profile's credential-refresh hook.
- For multi-cluster setups, export separate `KUBE_TOKEN_VIEWER_<CONTEXT>` variables and add context-matching rules to the YAML.
