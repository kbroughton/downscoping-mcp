#!/usr/bin/env python3
"""Claude Code PreToolUse hook — credential downscoping for Bash tool calls.

Called by Claude Code before every Bash tool invocation.
Reads JSON from stdin, rewrites the command with a scoped token if applicable,
and prints JSON with `updatedInput` to stdout.

Hook contract:
  stdin:  {"tool": "Bash", "input": {"command": "..."}, "cwd": "...", ...}
  stdout: {"updatedInput": {"command": "..."}}   (or empty → pass-through)
  exit 0: allow (modified or as-is)
  exit 1: block (not used here — we never block, only downscope)
"""

import sys
import os

# Allow running from the repo root without installing the package
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_src_dir = os.path.join(_repo_root, "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from credential_downscope.hook_handler import run

if __name__ == "__main__":
    run()
