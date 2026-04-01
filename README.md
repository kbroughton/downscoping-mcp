# downscoping-mcp

Downgrade user credential privileges to a configurable subset for use by AI tools. A user should already be given a subset of permissions for daily work which maps to services in particular GCP projects or AWS accounts. Downscoping refers to further restricting the actions to conform with company standards.

Permission grants are typically `<Action allowed> on <Resource>`. The downscoping affects the `<Action allowed>` by reducing capabilities, for example from read/write to read-only.

**Examples**
- Allow read but not write to Google Drive documents
- Allow GitHub read for PRs but not merging or approving
- Allow reading logs but not deploying to a project in GCP

## Problem

Claude Code runs with whatever credentials are present in your environment. A model that can read files can also call `gh repo delete`, `gcloud projects delete`, or `aws iam delete-user` — using the same token. A single jailbreak, prompt injection, or confused-deputy attack is enough to cause damage. So are accidental errors — Claude pushing directly to a release branch can trigger a deploy pipeline if branch protections or GitHub Actions are not correctly configured.

## Solution

Two complementary enforcement modes:

**Mode 1 — Bash hook (CLI tools)**
A `PreToolUse` hook intercepts every `Bash` tool call. If the command starts with a known service binary (`gh`, `gcloud`, `aws`, `kubectl`), the hook pattern-matches the arguments against your policy rules, selects the appropriate token slot, and rewrites the command to prepend the scoped credential before execution. Claude never sees the rewrite.

**Mode 2 — MCP proxy**
An MCP proxy server wraps an upstream MCP server. Before forwarding each tool call, it injects the scoped token for that specific tool into the subprocess environment. Read-only tools get a read-only token; write tools require an elevated token.

## Quick Start

### 1. Install

```bash
pip install -e .
```

### 2. Configure credentials

Export scoped tokens in your shell profile or CI environment:

```bash
export GITHUB_TOKEN_READONLY=ghp_...      # fine-grained: contents:read, issues:read
export GITHUB_TOKEN_ORG_WRITE=ghp_...     # fine-grained: issues:write, pull_requests:write
export GCLOUD_TOKEN_VIEWER=ya29....
export GCLOUD_TOKEN_EDITOR=ya29....
```

### 3. Create a policy file

Copy `config.example.yaml` to `.claude/downscoping.yaml` in your project root:

```bash
cp config.example.yaml .claude/downscoping.yaml
```

Edit the rules to match your org's access model. The file is `.gitignore`-safe for personal token slot names; the structure itself can be committed.

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

## Policy File Reference

```yaml
version: 1

services:
  gh:
    token_slots:
      readonly:
        env_var: GITHUB_TOKEN_READONLY   # read from process env
        inject_as: GITHUB_TOKEN          # injected into subprocess
      org-write:
        env_var: GITHUB_TOKEN_ORG_WRITE
        inject_as: GITHUB_TOKEN
    default_slot: readonly               # used when no rule matches
    rules:
      - name: "writes need elevated token"
        match:
          args_pattern: "pr (create|merge|edit)|issue (create|edit)|push"
        slot: org-write
```

**Token resolution order:**
1. Read `env_var` from the current process environment
2. If unset, fall back to the `inject_as` variable (uses the ambient credential)
3. If neither is set, pass the command through unmodified

## Architecture

```
Claude Code
    │
    ├─ Bash tool call ──► PreToolUse hook (hooks/pre_tool_use.py)
    │                          │
    │                          ├─ load .claude/downscoping.yaml
    │                          ├─ detect service binary
    │                          ├─ match args against rules
    │                          ├─ resolve token slot
    │                          └─ rewrite command: TOKEN=value <original command>
    │
    └─ MCP tool call ──► credential-downscope-proxy (mcp_proxy.py)
                              │
                              ├─ receive tool call from Claude
                              ├─ match tool name against MCP rules
                              ├─ inject scoped token into env
                              └─ forward to upstream MCP server
```

## Supported Services

| Service | Binary | Token env var pattern |
|---------|--------|-----------------------|
| GitHub CLI | `gh` | `GITHUB_TOKEN` |
| Google Cloud | `gcloud` | `CLOUDSDK_AUTH_ACCESS_TOKEN` |
| AWS CLI | `aws` | `AWS_ACCESS_KEY_ID` |
| Kubernetes | `kubectl` | `KUBE_TOKEN` |
| MCP servers | via proxy | configurable per server |

Additional services can be added by extending `config.yaml` — no code changes required.

## Security Notes

- Token values are `shlex.quote`-escaped before shell injection to prevent command injection via crafted token values.
- Prepending `TOKEN=value` before a command makes the token visible in process listings (`ps aux`). For higher-security environments, use a credential helper that injects tokens via a file descriptor or secrets manager.
- The hook never blocks commands (exit 0 always); it only rewrites them. Blocking logic can be added by returning `{"continue": false}` from the hook.
- `.claude/settings.json` containing local paths should be gitignored — see `.gitignore` in this repo for an example.

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
