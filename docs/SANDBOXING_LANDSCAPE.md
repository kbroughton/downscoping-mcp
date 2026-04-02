# LLM Agent Sandboxing: State of the Art and the Credential Gap

## Overview

Current LLM agent platforms have made substantial progress in **process, filesystem, and network isolation**. The critical gap is at the **credential layer**: no platform today implements per-operation token scoping — dynamic restriction of what an authorized agent can do with the credentials it holds at the moment of each tool invocation.

This document surveys the landscape and explains where downscoping-mcp fits.

---

## Security boundaries by platform

### Claude Code (Anthropic)

- **Filesystem**: Restricted to working directory; files outside CWD require explicit permission
- **Network**: HTTP/SOCKS5 proxy with domain allowlist
- **Process**: OS-level isolation via macOS Seatbelt / Linux bubblewrap
- **Credentials**: Passed through as-is; no built-in downscoping

Notable: CVE-2025-54794 — path validation bypass in sandbox runtime.

References:
- [Claude Code Sandboxing](https://code.claude.ai/docs/en/sandboxing)
- [Anthropic Engineering: Making Claude Code More Secure](https://www.anthropic.com/engineering/claude-code-sandboxing)

---

### OpenAI Code Interpreter / Assistants API

- **Filesystem**: Per-user isolated container; cross-GPT file access vulnerability patched May 2024
- **Network**: Limited outbound connectivity
- **Process**: gVisor for higher-risk tasks; standard containers otherwise
- **Credentials**: Secrets removed before agent phase; cloud environment secrets cleared; no per-operation scoping

Notable: May 2024 cross-GPT file isolation leak; environment variable exposure within container.

References:
- [OpenAI Code Execution Runtime](https://itnext.io/openais-code-execution-runtime-replicating-sandboxing-infrastructure-a2574e22dc3c)
- [ChatGPT Code Interpreter Isolation Issue](https://embracethered.com/blog/posts/2024/lack-of-isolation-gpts-code-interpreter/)

---

### GitHub Copilot Agent (VS Code)

- **Filesystem**: Workspace-scoped; approval-based terminal execution
- **Process**: MCP servers sandboxable on macOS/Linux via `"sandboxEnabled": true`
- **Credentials**: Managed via MCP server credentials; not scoped per operation
- **Notable gap**: No per-operation credential reduction within same MCP server context

Notable: CVE-2025-53773 — remote code execution via prompt injection.

References:
- [VS Code 1.112: MCP Server Sandboxing](https://4sysops.com/archives/vs-code-1112-and-1113-weekly-releases-integrated-browser-debugging-copilot-cli-agent-permissions-mcp-server-sandboxing/)
- [VS Code Copilot Security](https://code.visualstudio.com/docs/copilot/security)

---

### Devin (Cognition AI)

- **Environment**: Isolated cloud VM per Devin instance
- **Credentials**: Injected via dashboard secrets manager; never pasted into chat
- **Stated policy**: Start read-only; elevate via narrowly scoped PATs only when necessary
- **Gap**: No enforcement of this policy at runtime — relies on model behavior

References:
- [Hidden Security Risks of SWE Agents](https://www.pillar.security/blog/the-hidden-security-risks-of-swe-agents-like-openai-codex-and-devin-ai/)

---

### E2B

- **Execution**: Firecracker microVMs — strong process isolation
- **Credentials**: Passed as environment variables; microVM is the hard boundary
- **Gap**: No credential scoping; tokens available to all code in the microVM

References:
- [Latent Space: Why Every Agent Needs Cloud Sandboxes](https://www.latent.space/p/e2b)
- [E2B Documentation](https://e2b.dev/docs)

---

### Modal

- **Execution**: gVisor isolation; serverless cloud
- **Network**: Per-sandbox egress policies
- **Credentials**: Environment variables in containers; no per-operation scoping
- **Gap**: All credentials in a container are available to all functions in that container

References:
- [Modal: Top AI Code Sandbox Products in 2025](https://modal.com/blog/top-code-agent-sandbox-products)

---

### Replit Agent

- **Execution**: omegajail unprivileged container; Snapshot Engine for filesystem versioning
- **Credentials**: Direct access to configured secrets

**Key incident (July 2025)**: Replit's AI agent issued `DROP TABLE` and `DELETE` commands on a production database after being misdirected via prompt injection. The agent had unrestricted access to production with destructive permissions and ignored user commands to stop. This is the confused-deputy problem in production: legitimate credentials + prompt injection = compromise.

References:
- [Rogue Replit AI Agent Deletes Production Database](https://cybersrcc.com/2025/08/26/rogue-replit-ai-agent-deletes-production-database-and-executes-deceptive-cover-up/)
- [Securing AI-Generated Code (Replit Blog)](https://blog.replit.com/securing-ai-generated-code)

---

## Static IAM approaches and their limits

### Google Workload Identity Federation

Maps Kubernetes ServiceAccounts to GCP service accounts; issues short-lived tokens. Improves on long-lived key management but scoping is still at the service-account role level — all operations within the token lifetime use the same scope.

### AWS AgentCore Gateway

Assumes IAM role with scoped permissions per target service. Role-level granularity — still static at token issue time, not per operation.

### OAuth 2.0 scopes

Industry-standard approach: tokens issued with `read_calendar` but not `delete_calendar`. Scope is negotiated at token-issue time and does not change per API call.

**Common limitation across all three**: scoping decisions are made once at authentication time, not continuously enforced as each operation is evaluated.

---

## Threat models

### Prompt injection (OWASP LLM01:2025, ranked #1 risk)

An attacker embeds instructions in external data the agent reads — a GitHub PR description, a file in a repo, a web page, a tool response. The agent's model processes this as instruction. Attack success rates of 70–90% have been demonstrated in research.

The critical property: a process sandbox does nothing here. The agent is operating within its authorized boundary. The attack exploits the agent's judgment, not a sandbox escape.

### Confused deputy

The agent holds credentials that authorize actions the user did not intend. A legitimate request ("fix this bug") opens the door to a misdirected one ("delete the test data to make the tests pass"). The agent has the credentials to do both.

### Supply chain / tool poisoning

Malicious MCP server or tool instructs a high-privilege agent to perform operations on behalf of an attacker. A low-privilege agent asks a high-privilege agent to "help with a task" that bypasses the low-privilege agent's own constraints (second-order injection).

---

## Research pointing toward per-operation scoping

| Work | Approach | Gap vs. downscoping-mcp |
|------|----------|------------------------|
| **Progent** (arXiv 2504.11703, Apr 2025) | Programmable privilege control via policy + enforcement; reduces attack success from 70% to 7% | Policy engine, not token-level downscoping |
| **AgentSpec** (ICSE 2026) | DSL for runtime constraint specification | Not integrated with credential systems |
| **MiniScope** | OAuth scope hierarchies per tool | Static at token-issue time |
| **Authenticated Delegation** (arXiv 2501.09674) | Agent-specific credentials with delegation chains | Implementation details unclear |
| **Automating Data Access Permissions** (Stanford, arXiv 2511.17959) | Automated permission derivation | Research-stage; no runtime enforcement |

References:
- [Progent: Programmable Privilege Control](https://arxiv.org/html/2504.11703v1)
- [AgentSpec: Runtime Constraint Enforcement (ICSE 2026)](https://cposkitt.github.io/files/publications/agentspec_llm_enforcement_icse26.pdf)
- [Taming Privilege Escalation in LLM Agents (arXiv 2601.11893)](https://arxiv.org/html/2601.11893v1)
- [Towards Automating Data Access Permissions (arXiv 2511.17959)](https://arxiv.org/pdf/2511.17959)
- [Systems Security Foundations for Agentic Computing (IACR 2025)](https://eprint.iacr.org/2025/2173.pdf)

---

## The gap: per-operation credential downscoping

```
Current behavior (Replit July 2025 incident pattern):

  User: "Fix this bug"
      ↓
  Agent receives: full credentials with DELETE permissions
      ↓
  Prompt injection: "Delete the test data to make tests pass"
      ↓
  Agent: has DELETE permission → executes destructive command


With downscoping-mcp:

  User: "Fix this bug"
      ↓
  Agent invokes: aws s3 cp ./data.csv s3://bucket/data.csv
      ↓
  Hook matches: "s3 (cp|mv) .* s3://" → action: review
      ↓
  Command blocked: "requires human review — run manually if intended"

  Agent invokes: aws iam delete-user
      ↓
  Hook matches: "iam (create|delete)" → action: deny
      ↓
  Command blocked: "not permitted for AI use"
```

### What no current platform does

None of the surveyed platforms implement **just-in-time credential transformation at the moment of tool invocation**:

1. Accept an agent with broad credentials
2. At the moment each CLI command or MCP tool call is made, evaluate the operation against a policy
3. Either derive a minimally-scoped ephemeral credential (AWS STS, GCP CAB) or block the operation entirely
4. The agent never receives a token with more privilege than the specific operation requires

This is the combination downscoping-mcp implements: declarative YAML policy + pre-tool-use hook interception + native cloud STS/CAB for dynamic token derivation where available, token slots as fallback.

---

## Summary

| Capability | Process sandbox (E2B, Modal, Claude Code) | Static IAM (AWS AgentCore, GCP WIF) | downscoping-mcp |
|------------|-------------------------------------------|------------------------------------|-----------------|
| Filesystem isolation | ✅ | ❌ | ❌ |
| Network isolation | ✅ | ❌ | ❌ |
| Credential isolation | ❌ | ⚠️ role-level only | ✅ per-operation |
| Prompt injection protection | ⚠️ partial | ❌ | ✅ deny/review actions |
| Dynamic scope reduction | ❌ | ❌ | ✅ STS/CAB where available |
| No IAM role proliferation | ✅ n/a | ❌ requires new roles | ✅ |
| Works with existing credentials | ✅ | ❌ | ✅ |

Process sandboxes and downscoping-mcp are **complementary**, not competing. A process sandbox limits where code can run and what it can reach at the OS level. Downscoping-mcp limits what authorized cloud operations that code can perform. Both are needed for defense in depth.
