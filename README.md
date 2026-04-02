# downscoping-mcp

Downgrade user credential privileges to a configurable subset for use by AI tools. A user should already be given a subset of permissions for daily work which maps to services in particular GCP projects or AWS accounts. Downscoping refers to further restricting the actions to conform with company standards.

Permission grants are typically `<Action allowed> on <Resource>`. The downscoping affects the `<Action allowed>` by reducing capabilities, for example from read/write to read-only.

**Examples**
- Allow read but not write to Google Drive documents
- Allow GitHub read for PRs but not merging or approving
- Allow reading logs but not deploying to a project in GCP

---

## Problem

Claude Code runs with whatever credentials are present in your environment. A model that can read files can also call `gh repo delete`, `gcloud projects delete`, or `aws iam delete-user` — using the same token. A single jailbreak, prompt injection, or confused-deputy attack is enough to cause damage. So are accidental errors — Claude pushing directly to a release branch can trigger a deploy pipeline if branch protections or GitHub Actions are not correctly configured.

## Why this approach?

The obvious alternative is creating dedicated low-privilege IAM roles or service accounts for AI use — one per team, per environment. This runs into hard limits fast.

A typical `~/.aws/config` already has 60+ profiles covering different accounts and roles. Doubling that with AI-specific downscoped counterparts means 120+ profiles, ongoing IaC maintenance, and per-engineer configuration in `.claude/settings.local.json` to wire up the right profile. AWS has a default IAM role quota of 1,000 per account (higher limits require a quota increase request), and each new role is another thing to audit, rotate, and keep in sync with the original.

This tool takes a different approach: downscope dynamically at call time, without touching IAM. It works analogously to `aws sts assume-role --policy-arns`, which restricts the effective permissions of an assumed role to the intersection of the role's policies and the supplied policy ARNs. Here, the intersection is defined in a YAML file checked into your project rather than an IAM policy document — but the semantics are the same. Your existing credentials are used; their effective capabilities are narrowed per operation according to the rules you define.

One important property is preserved: **this tool can only reduce privileges, never increase them.** It sets guardrails to keep AI tool use safe and conformant with company policy, without requiring any changes to your IAM setup.

---

## How it works

Rules are evaluated top-to-bottom for each command. The first match wins. Three outcomes are possible:

| Action | Behaviour |
|--------|-----------|
| `allow` | Inject the scoped token for the matched slot; command proceeds |
| `review` | Block the command; tell Claude to ask the user to run it manually |
| `deny` | Block the command; tell Claude it is not permitted for AI use |

Block messages include the rule name and the matched pattern so the reason is always explicit.

### Tier 1 — Dynamic downscoping (preferred)

Native cloud STS derives a restricted token from your ambient credential at call time. No new IAM roles or pre-provisioned tokens required.

- **AWS**: `sts:GetFederationToken` or `sts:AssumeRole` with an inline policy. Effective permissions = intersection of your identity policies and the inline policy. See [docs/AWS_DOWNSCOPING.md](docs/AWS_DOWNSCOPING.md).
- **GCP**: Credential Access Boundary via `sts.googleapis.com`. Restricts the ambient token to specific resources and roles. **Supported for Cloud Storage only.** For other GCP services, falls back to OAuth scope restriction. See [docs/GCP_DOWNSCOPING.md](docs/GCP_DOWNSCOPING.md).

### Tier 2 — Token slots (fallback)

Used when no dynamic API exists. Pre-provisioned narrowly-scoped tokens are selected per operation based on YAML rules.

- **GitHub**: Fine-grained PATs (no dynamic downscoping API available). See [docs/GITHUB_DOWNSCOPING.md](docs/GITHUB_DOWNSCOPING.md).
- **GCP non-GCS services**: OAuth scope restriction via `generateAccessToken`. API-level granularity only.
- **kubectl**: Kubernetes ServiceAccount tokens bound to minimal RBAC roles. EKS and GKE clusters can use the backing cloud provider's dynamic downscoping — see [docs/KUBECTL_DOWNSCOPING.md](docs/KUBECTL_DOWNSCOPING.md).

### Two enforcement modes

**Mode 1 — Bash hook (CLI tools)**

A `PreToolUse` hook intercepts every `Bash` tool call. If the command starts with a known service binary (`gh`, `gcloud`, `aws`, `kubectl`), the hook matches the arguments against your YAML rules, evaluates the action, and either rewrites the command with a scoped token or emits a block message. Claude never sees the rewrite.

**Mode 2 — MCP proxy**

An MCP proxy wraps an upstream MCP server. Before forwarding each tool call, it applies the same YAML rules to inject the scoped token for that specific tool. Currently supports the `github-pr-issue-analyser` server; other servers are a future extension.

---

## Quick Start

### 1. Install

```bash
pip install -e .
```

### 2. Configure credentials

Export scoped tokens in your shell profile or CI environment:

```bash
# GitHub (token_slot mode — only option for GitHub)
export GITHUB_TOKEN_READONLY=ghp_...       # fine-grained: contents:read, issues:read
export GITHUB_TOKEN_ORG_WRITE=ghp_...      # fine-grained: issues:write, pull_requests:write

# GCP (token_slot fallback — preferred is CAB via google.auth.downscoped)
export GCLOUD_TOKEN_VIEWER=ya29....
export GCLOUD_TOKEN_EDITOR=ya29....

# AWS (token_slot fallback — preferred is sts:GetFederationToken)
export AWS_ACCESS_KEY_ID_READONLY=AKIA...
```

### 3. Create a policy file

```bash
cp config.example.yaml .claude/downscoping.yaml
```

Edit to match your org's access model. The `downscope_mode` field selects the mechanism per service:

```yaml
version: 1

services:
  aws:
    downscope_mode: sts_policy      # Tier 1: derive restricted token from ambient creds
    inline_policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: ["s3:GetObject", "s3:ListBucket", "ec2:Describe*"]
          Resource: "*"
    rules:
      - name: "S3 writes require review"
        match:
          args_pattern: "s3 (cp|mv|rm|sync) .* s3://"
        action: review
      - name: "IAM mutations denied"
        match:
          args_pattern: "iam (create|delete|put|attach|detach)"
        action: deny

  gh:
    downscope_mode: token_slot      # Tier 2: GitHub has no dynamic API
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
      - name: "permitted writes use org-write token"
        match:
          args_pattern: "pr (create|edit)|issue (create|edit)|push"
        action: allow
        slot: org-write
```

### 4. Register the hook

Add to your project's `.claude/settings.json`:

```json
{
  "env": {
    "CLAUDE_PLUGIN_ROOT": "/path/to/downscoping-mcp"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/pre_tool_use.py",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

### 5. (Optional) Enable the MCP proxy

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "credential-downscope-proxy": {
      "command": "python3",
      "args": ["-m", "credential_downscope.mcp_proxy"],
      "env": {
        "PYTHONPATH": "${CLAUDE_PLUGIN_ROOT}/src",
        "GITHUB_INTEGRATION_SRC": "/path/to/upstream-mcp-server/src"
      }
    }
  }
}
```

---

## Policy file reference

### Rule actions

```yaml
rules:
  - name: "human-readable name — appears in block messages"
    match:
      args_pattern: "<regex matched against CLI args after the binary>"
      # OR for MCP tools:
      tools: [tool_name_1, tool_name_2]
    action: allow    # inject scoped token (default if action omitted)
    slot: readonly   # which token slot to use (action: allow only)

  - name: "example deny"
    match:
      args_pattern: "iam delete"
    action: deny     # blocked; Claude told it is not permitted for AI use

  - name: "example review"
    match:
      args_pattern: "s3 cp .* s3://"
    action: review   # blocked; Claude told to ask user to run manually
```

**Rule ordering matters** — rules are evaluated top-to-bottom; the first match wins. Place specific `deny`/`review` rules before broad `allow` rules.

### Token resolution order (token_slot mode)

1. Read `env_var` from the current process environment
2. If unset, fall back to the `inject_as` variable (uses the ambient credential)
3. If neither is set, pass the command through unmodified

---

## Architecture

```
Claude Code
    │
    ├─ Bash tool call ──► PreToolUse hook (hooks/pre_tool_use.py)
    │                          │
    │                          ├─ load .claude/downscoping.yaml
    │                          ├─ detect service binary
    │                          ├─ match args against rules → RuleDecision
    │                          │
    │                          ├─ action=deny   → {"continue": false, "stopReason": "...denied..."}
    │                          ├─ action=review → {"continue": false, "stopReason": "...run manually..."}
    │                          └─ action=allow  → {"updatedInput": {"command": "TOKEN=value <cmd>"}}
    │
    └─ MCP tool call ──► credential-downscope-proxy (mcp_proxy.py)
                              │
                              ├─ match tool name against MCP rules → RuleDecision
                              ├─ inject scoped token into env
                              └─ forward to upstream MCP server
```

---

## Supported services

| Service | Binary / Interface | Downscope mode | Doc |
|---------|--------------------|----------------|-----|
| GitHub CLI | `gh` | token_slot | [GITHUB_DOWNSCOPING.md](docs/GITHUB_DOWNSCOPING.md) |
| AWS CLI | `aws` | sts_policy (preferred), token_slot | [AWS_DOWNSCOPING.md](docs/AWS_DOWNSCOPING.md) |
| Google Cloud | `gcloud` | credential_access_boundary (GCS), oauth_scope, token_slot | [GCP_DOWNSCOPING.md](docs/GCP_DOWNSCOPING.md) |
| Kubernetes | `kubectl` | token_slot; EKS/GKE dynamic (future) | [KUBECTL_DOWNSCOPING.md](docs/KUBECTL_DOWNSCOPING.md) |
| MCP servers | proxy | token_slot | [GITHUB_DOWNSCOPING.md](docs/GITHUB_DOWNSCOPING.md) |

Additional services can be added by extending `config.yaml` — no code changes required.

---

## Security notes

- Token values are `shlex.quote`-escaped before shell injection to prevent command injection via crafted token values.
- Prepending `TOKEN=value` before a command makes the token visible in process listings (`ps aux`). For higher-security environments, use a credential helper that injects tokens via a file descriptor or secrets manager.
- Block messages include the matched rule name and pattern so the reason is always auditable.
- The fallback to the ambient `inject_as` token means that if you have not yet provisioned a scoped token, commands pass through using the ambient credential. Set `DOWNSCOPE_REQUIRE_SCOPED=1` (future) to harden this.
- `.claude/settings.json` containing local paths should be gitignored — see `.gitignore` in this repo.

---

## Development

```bash
pip install -e .
pytest tests/
```

---

## License

MIT
