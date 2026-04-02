# GitHub Downscoping

## Mechanism: Fine-Grained Personal Access Tokens (token_slot only)

GitHub does not provide a dynamic downscoping API analogous to AWS STS or GCP CAB. There is no token exchange endpoint that derives a restricted token from an existing one.

The only available mechanism is **pre-provisioned fine-grained PATs**: create one token per privilege level, export them as environment variables, and the hook selects the appropriate one per operation.

---

## Token setup

### Fine-grained PAT permissions

Create two tokens at [github.com/settings/tokens](https://github.com/settings/tokens):

**Read-only token** (`GITHUB_TOKEN_READONLY`):
- Repository permissions: `Contents: Read`, `Issues: Read`, `Pull requests: Read`, `Metadata: Read`
- Scope: your org or specific repositories

**Write token** (`GITHUB_TOKEN_ORG_WRITE`):
- Repository permissions: `Contents: Write`, `Issues: Write`, `Pull requests: Write`
- Scope: specific repositories only (avoid org-wide)
- Do **not** grant `Administration` — this allows repo deletion and branch protection changes

Export in your shell profile:

```bash
export GITHUB_TOKEN_READONLY=ghp_...
export GITHUB_TOKEN_ORG_WRITE=ghp_...
```

---

## config.yaml example

```yaml
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
      # Specific rules before catch-all (first match wins)
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
          args_pattern: "pr (create|edit)|issue (create|edit)|release create|push"
        action: allow
        slot: org-write
```

**Rule ordering matters.** Rules are evaluated top-to-bottom; the first match wins. Place more specific rules (deny, review) before catch-all allow rules to avoid them being shadowed.

---

## MCP proxy (Mode 2)

When using the GitHub MCP integration, the proxy applies the same token-slot logic to individual tool calls:

```yaml
services:
  mcp:
    downscope_mode: token_slot
    server: github-pr-issue-analyser
    token_slots:
      readonly:
        env_var: GITHUB_TOKEN_READONLY
        inject_as: GITHUB_TOKEN
      org-write:
        env_var: GITHUB_TOKEN_ORG_WRITE
        inject_as: GITHUB_TOKEN
    default_slot: readonly
    rules:
      - name: "merge via MCP requires review"
        match:
          tools: [merge_pr]
        action: review
      - name: "write tools use org-write token"
        match:
          tools:
            - create_issue
            - create_pr
            - update_pr_description
            - update_issue
            - create_tag
            - create_release
            - add_pr_comments
            - add_inline_pr_comment
            - update_reviews
            - update_assignees
        action: allow
        slot: org-write
```

---

## Why no dynamic downscoping for GitHub?

GitHub's token model is scoped at creation time and cannot be narrowed after issuance. Unlike AWS IAM or GCP IAM, there is no STS-style exchange endpoint that takes an existing token and returns a less-privileged derivative.

GitHub's OAuth App and GitHub App installation tokens can be scoped per-repository, but they still require pre-registration of the app and are not suitable as a general-purpose downscoping mechanism for developer CLI workflows.

Fine-grained PATs are the closest equivalent — they allow precise permission selection per repository — but they must be created and exported before use.

---

## Security notes

- Tokens injected via `GITHUB_TOKEN=value command` are visible in process listings (`ps aux`). For higher-security environments, use a credential helper (e.g. GitHub CLI's built-in keychain integration).
- The org-write token should never include `Administration` or `Secrets` permissions — these allow deleting repositories and reading CI secrets.
- Set token expiry (30–90 days) and rotate via CI secrets management rather than long-lived personal tokens in shell profiles.
- If `GITHUB_TOKEN_READONLY` is unset, the hook falls back to the ambient `GITHUB_TOKEN`. Ensure your read-only token is always exported to avoid accidentally using the full-privilege ambient token for read operations.
