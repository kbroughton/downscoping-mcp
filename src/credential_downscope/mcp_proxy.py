"""MCP proxy server (Mode 2) — wraps the github-pr-issue-analyser MCP server.

Applies per-call token injection using the same RuleMatcher + downscoping config
as the Bash hook, but for MCP tool calls.

Registration in .mcp.json:
  {
    "mcpServers": {
      "credential-downscope-proxy": {
        "command": "python3",
        "args": ["-m", "credential_downscope.mcp_proxy"],
        "env": {}
      }
    }
  }

The proxy exposes all tools from the upstream GitHub integration under the same
names, transparently injecting the least-privileged token before each call.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .rules import RuleMatcher, resolve_token

# Import upstream GitHub integration — located in the sibling project.
# Adjust sys.path so we can reach it when running from this repo.
_UPSTREAM_SRC = os.environ.get("GITHUB_INTEGRATION_SRC", "")
if _UPSTREAM_SRC not in sys.path:
    sys.path.insert(0, os.path.abspath(_UPSTREAM_SRC))

from mcp_github.github_integration import GitHubIntegration  # noqa: E402

logger = logging.getLogger(__name__)

mcp = FastMCP("credential-downscope-proxy")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_integration(tool_name: str) -> GitHubIntegration:
    """Return a GitHubIntegration instance with the correct scoped token injected."""
    cwd = os.environ.get("CLAUDE_TOOL_CWD") or os.getcwd()
    config = load_config(cwd)

    if config is not None:
        mcp_cfg = config.get("services", {}).get("mcp", {})
        matcher = RuleMatcher({"services": {"mcp": mcp_cfg}}, "mcp")
        slot_name = matcher.resolve_for_tool(tool_name)
        token, inject_as = resolve_token({"services": {"mcp": mcp_cfg}}, "mcp", slot_name)

        if token:
            logger.info("[downscope] MCP tool=%s slot=%s → injecting token", tool_name, slot_name)
            old = os.environ.get(inject_as or "GITHUB_TOKEN")
            os.environ[inject_as or "GITHUB_TOKEN"] = token
            try:
                return GitHubIntegration()
            finally:
                # Restore the original value so we don't permanently mutate env
                if old is None:
                    os.environ.pop(inject_as or "GITHUB_TOKEN", None)
                else:
                    os.environ[inject_as or "GITHUB_TOKEN"] = old

    return GitHubIntegration()


# ---------------------------------------------------------------------------
# Proxied tools — one per upstream method
# ---------------------------------------------------------------------------

@mcp.tool()
def get_pr_diff(repo_owner: str, repo_name: str, pr_number: int) -> str:
    """Fetch the diff/patch of a specific pull request."""
    return _get_integration("get_pr_diff").get_pr_diff(repo_owner, repo_name, pr_number)


@mcp.tool()
def get_pr_content(repo_owner: str, repo_name: str, pr_number: int) -> dict[str, Any]:
    """Fetch the content/details of a specific pull request."""
    return _get_integration("get_pr_content").get_pr_content(repo_owner, repo_name, pr_number)


@mcp.tool()
def add_pr_comments(repo_owner: str, repo_name: str, pr_number: int, comment: str) -> dict[str, Any]:
    """Add a comment to a specific pull request."""
    return _get_integration("add_pr_comments").add_pr_comments(repo_owner, repo_name, pr_number, comment)


@mcp.tool()
def add_inline_pr_comment(
    repo_owner: str, repo_name: str, pr_number: int, path: str, line: int, comment_body: str
) -> dict[str, Any]:
    """Add an inline review comment to a file line within a pull request."""
    return _get_integration("add_inline_pr_comment").add_inline_pr_comment(
        repo_owner, repo_name, pr_number, path, line, comment_body
    )


@mcp.tool()
def update_pr_description(
    repo_owner: str, repo_name: str, pr_number: int, new_title: str, new_description: str
) -> dict[str, Any]:
    """Update the title and description of a pull request."""
    return _get_integration("update_pr_description").update_pr_description(
        repo_owner, repo_name, pr_number, new_title, new_description
    )


@mcp.tool()
def create_pr(
    repo_owner: str,
    repo_name: str,
    title: str,
    body: str,
    head: str,
    base: str,
    draft: bool = False,
) -> dict[str, Any]:
    """Create a new pull request."""
    return _get_integration("create_pr").create_pr(repo_owner, repo_name, title, body, head, base, draft)


@mcp.tool()
def list_open_issues_prs(
    repo_owner: str,
    issue: str = "pr",
    filtering: str = "involves",
    per_page: int = 50,
    page: int = 1,
) -> dict[str, Any]:
    """List open pull requests or issues for a repository owner."""
    return _get_integration("list_open_issues_prs").list_open_issues_prs(
        repo_owner, issue, filtering, per_page, page  # type: ignore[arg-type]
    )


@mcp.tool()
def create_issue(
    repo_owner: str, repo_name: str, title: str, body: str, labels: list[str]
) -> dict[str, Any]:
    """Create a new issue in a GitHub repository."""
    return _get_integration("create_issue").create_issue(repo_owner, repo_name, title, body, labels)


@mcp.tool()
def merge_pr(
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    commit_title: str | None = None,
    commit_message: str | None = None,
    merge_method: str = "squash",
) -> dict[str, Any]:
    """Merge a pull request."""
    return _get_integration("merge_pr").merge_pr(
        repo_owner, repo_name, pr_number, commit_title, commit_message, merge_method  # type: ignore[arg-type]
    )


@mcp.tool()
def update_issue(
    repo_owner: str,
    repo_name: str,
    issue_number: int,
    title: str,
    body: str,
    labels: list[str] | None = None,
    state: str = "open",
) -> dict[str, Any]:
    """Update an existing issue."""
    return _get_integration("update_issue").update_issue(
        repo_owner, repo_name, issue_number, title, body, labels or [], state  # type: ignore[arg-type]
    )


@mcp.tool()
def update_reviews(
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    event: str,
    body: str | None = None,
) -> dict[str, Any]:
    """Submit a review for a pull request."""
    return _get_integration("update_reviews").update_reviews(
        repo_owner, repo_name, pr_number, event, body  # type: ignore[arg-type]
    )


@mcp.tool()
def update_assignees(
    repo_owner: str, repo_name: str, issue_number: int, assignees: list[str]
) -> dict[str, Any]:
    """Update assignees for an issue or pull request."""
    return _get_integration("update_assignees").update_assignees(
        repo_owner, repo_name, issue_number, assignees
    )


@mcp.tool()
def get_latest_sha(repo_owner: str, repo_name: str) -> str | None:
    """Fetch the SHA of the latest commit."""
    return _get_integration("get_latest_sha").get_latest_sha(repo_owner, repo_name)


@mcp.tool()
def create_tag(repo_owner: str, repo_name: str, tag_name: str, message: str) -> dict[str, Any]:
    """Create a new tag in a GitHub repository."""
    return _get_integration("create_tag").create_tag(repo_owner, repo_name, tag_name, message)


@mcp.tool()
def create_release(
    repo_owner: str, repo_name: str, tag_name: str, release_name: str, body: str
) -> dict[str, Any]:
    """Create a new release in a GitHub repository."""
    return _get_integration("create_release").create_release(
        repo_owner, repo_name, tag_name, release_name, body
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
