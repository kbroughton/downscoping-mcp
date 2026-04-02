# GCP Downscoping

## Mechanism overview

GCP offers two levels of dynamic downscoping, with different coverage:

| Mechanism | Services covered | Granularity |
|-----------|-----------------|-------------|
| Credential Access Boundary (CAB) | **GCS only** | Resource + permission level |
| OAuth scope restriction (`generateAccessToken --scopes`) | All GCP services | API level (coarse) |
| Token slot (fallback) | All services | N/A — pre-provisioned tokens |

---

## Tier 1 (preferred): Credential Access Boundary

CAB derives a downscoped token from your ambient credential via the GCP STS token exchange endpoint. The effective permissions are the intersection of the source credential and the boundary rules — you cannot exceed what you already have.

```
effective_permissions = source_credential_permissions ∩ access_boundary
```

**CAB is only supported for Cloud Storage.** For all other GCP services, use OAuth scope restriction or token slots.

### Python implementation (google-auth)

```python
import google.auth
from google.auth import downscoped

# Load ambient credentials
source_creds, project = google.auth.default()

# Define boundary: restrict to objectViewer on a specific bucket
boundary = downscoped.CredentialAccessBoundary([
    downscoped.CredentialAccessBoundary.AccessBoundaryRule(
        available_resource="//storage.googleapis.com/projects/_/buckets/my-bucket",
        available_permissions=["inRole:roles/storage.objectViewer"],
        # Optionally restrict further to a path prefix:
        availability_condition=downscoped.CredentialAccessBoundary.AvailabilityCondition(
            expression="resource.name.startsWith('projects/_/buckets/my-bucket/objects/logs/')"
        )
    )
])

# Derive downscoped credentials
scoped_creds = downscoped.Credentials(
    source_credentials=source_creds,
    credential_access_boundary=boundary,
)

# Inject into gcloud CLI via env var
access_token = scoped_creds.token
```

The derived token can be injected via `CLOUDSDK_AUTH_ACCESS_TOKEN` for gcloud CLI calls.

### STS token exchange endpoint

CAB is implemented via the [Security Token Service API](https://cloud.google.com/iam/docs/reference/sts/rest):

```bash
curl -X POST https://sts.googleapis.com/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
    "subjectToken": "<source_access_token>",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:access_token",
    "options": "{\"accessBoundary\":{\"accessBoundaryRules\":[{
      \"availableResource\":\"//storage.googleapis.com/projects/_/buckets/my-bucket\",
      \"availablePermissions\":[\"inRole:roles/storage.objectViewer\"]
    }]}}"
  }'
```

---

## Tier 2 (fallback for non-GCS): OAuth scope restriction

For services where CAB is not supported, use `generateAccessToken` with narrower OAuth 2.0 scopes via service account impersonation:

```bash
gcloud auth print-access-token --scopes=https://www.googleapis.com/auth/devstorage.read_only
```

Or via the IAM Credentials API:

```bash
curl -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA_EMAIL:generateAccessToken" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform.read-only"]}'
```

**Scope granularity is API-level, not resource-level.** `cloud-platform.read-only` restricts to read across all services — you cannot restrict to a single project or bucket with scope alone.

---

## config.yaml example

```yaml
version: 1

services:
  gcloud:
    downscope_mode: credential_access_boundary  # active for GCS; falls back to token_slot
    access_boundary:
      - available_resource: "//storage.googleapis.com/projects/_/buckets/my-bucket"
        available_permissions:
          - "inRole:roles/storage.objectViewer"
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
      - name: "deploys denied"
        match:
          args_pattern: "run deploy|functions deploy|app deploy"
        action: deny
      - name: "project-level deletions denied"
        match:
          args_pattern: "projects delete|sql instances delete"
        action: deny
```

---

## Future: EKS/GKE dynamic downscoping

For GKE clusters, Workload Identity maps Kubernetes service accounts to GCP service accounts. A downscoped GCP credential derived via CAB or scope restriction flows through to the GKE node's workload. This enables dynamic per-call restriction without separate Kubernetes RBAC roles. See `KUBECTL_DOWNSCOPING.md` for details.

---

## Permission mapping reference

The [IAM Dataset](https://github.com/iann0036/iam-dataset) (`gcp/methods.json`, `gcp/permissions.json`) provides GCP API method metadata and permission definitions. Browse interactively at [gcp.permissions.cloud](https://gcp.permissions.cloud).

Example: `gcloud storage cp` calls `storage.objects.create`. The IAM permission required is `storage.objects.create`, which is granted by `roles/storage.objectCreator` or `roles/storage.objectAdmin`.

---

## Security notes

- CAB enforces the intersection at the GCP STS layer — no client-side enforcement risk.
- An ambient credential with viewer-only access cannot be expanded by CAB (intersection cannot exceed the source).
- OAuth scope restriction does NOT prevent a principal from calling APIs within that scope on resources they have IAM access to — it is an additional filter, not a replacement for IAM.
- `CLOUDSDK_AUTH_ACCESS_TOKEN` overrides gcloud's credential chain entirely. Set it only for the duration of the CLI call.
