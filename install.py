#!/usr/bin/env python3
"""install.py: add the read-only guard hook and the skill to Claude Code.

  python3 install.py            show exactly what would change (changes nothing)
  python3 install.py --apply    make the change (backs up settings.json first)
  python3 install.py --remove   take the hook out again

What --apply does:
  1. copies guard/readonly_guard.py and guard/lock.py to ~/.claude/hooks/readonly-audit/
  2. copies skill/what-claude-really-finds/ and audit/mac_audit.py to ~/.claude/skills/what-claude-really-finds/
  3. adds ONE PreToolUse hook (matcher "*", absolute path) to ~/.claude/settings.json, merged
     with your existing hooks, after saving settings.json.bak-<timestamp>
The hook does nothing until you start an audit (it sleeps unless ~/.claude/readonly-audit.lock exists).
Restart Claude Code afterwards so it loads the hook.
"""
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLAUDE = os.path.expanduser("~/.claude")
SETTINGS = os.path.join(CLAUDE, "settings.json")
HOOK_DIR = os.path.join(CLAUDE, "hooks", "readonly-audit")
SKILL_DIR = os.path.join(CLAUDE, "skills", "what-claude-really-finds")
CMD = f"python3 {os.path.join(HOOK_DIR, 'readonly_guard.py')}"
ENTRY = {"matcher": "*", "hooks": [{"type": "command", "command": CMD, "timeout": 10}]}


def load():
    if os.path.exists(SETTINGS):
        with open(SETTINGS) as f:
            return json.load(f)
    return {}


def has_hook(s):
    return any(h.get("command") == CMD for e in s.get("hooks", {}).get("PreToolUse", []) for h in e.get("hooks", []))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--dry-run"
    s = load()
    if mode == "--remove":
        pre = s.get("hooks", {}).get("PreToolUse", [])
        s.setdefault("hooks", {})["PreToolUse"] = [e for e in pre if not any(h.get("command") == CMD for h in e.get("hooks", []))]
        shutil.copy(SETTINGS, f"{SETTINGS}.bak-{int(time.time())}")
        json.dump(s, open(SETTINGS, "w"), indent=2)
        print("Hook removed from settings.json (files left in place). Restart Claude Code.")
        return
    print("Would copy:")
    print(f"  guard/readonly_guard.py, guard/lock.py  ->  {HOOK_DIR}/")
    print(f"  skill/what-claude-really-finds/, audit/mac_audit.py  ->  {SKILL_DIR}/")
    if has_hook(s):
        print("settings.json: hook already present, no change")
    else:
        print("settings.json: add to hooks.PreToolUse:")
        print("  " + json.dumps(ENTRY))
    if mode != "--apply":
        print("\nNothing changed. Run with --apply to install.")
        return
    os.makedirs(HOOK_DIR, exist_ok=True)
    for f in ("readonly_guard.py", "lock.py"):
        shutil.copy(os.path.join(HERE, "guard", f), HOOK_DIR)
    shutil.copytree(os.path.join(HERE, "skill", "what-claude-really-finds"), SKILL_DIR, dirs_exist_ok=True)
    shutil.copy(os.path.join(HERE, "audit", "mac_audit.py"), SKILL_DIR)
    if not has_hook(s):
        if os.path.exists(SETTINGS):
            shutil.copy(SETTINGS, f"{SETTINGS}.bak-{int(time.time())}")
        s.setdefault("hooks", {}).setdefault("PreToolUse", []).append(ENTRY)
        json.dump(s, open(SETTINGS, "w"), indent=2)
    print("\nInstalled. Restart Claude Code, then ask it: \"run what-claude-really-finds\".")


if __name__ == "__main__":
    main()
