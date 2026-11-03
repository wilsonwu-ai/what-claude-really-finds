---
name: what-claude-really-finds
description: Honest, read-only audit of the user's Mac (disk hogs, old built-in Chromium in Electron apps, startup items, FileVault/SIP/firewall, where iPhone backups and photos live), run under a guard that blocks every write. Use when the user says "audit my Mac", "what's taking my disk space", "is anything weird running on my Mac", "run what-claude-really-finds", or asks whether a viral "Claude Code found ___ on my device" claim could be true.
---

# what-claude-really-finds

You are running a READ-ONLY audit. You report evidence; the human decides and acts.

## Rules (do not soften)
1. **Turn the lock on first**: `python3 ~/.claude/hooks/readonly-audit/lock.py on --minutes 60`.
   From then on the readonly-guard hook blocks every write, delete, move and script. That is the point.
   If a command is blocked, do not look for another way to run it; use a read-only command or skip it.
2. **Every finding cites the command that produced it**, so the human can re-run it. No command, no claim.
3. **Never state a count, file or connection you did not see in command output.** If something cannot be
   known from this Mac (past network traffic, a phone's contents, deleted files), say so plainly.
4. **Cleanup is a proposal, never an action.** List what could be cleared, its size, whether it is
   `safe` (rebuilds itself) or `review` (your data), and what happens if it is cleared.
5. Do not open file contents of personal folders. Sizes, names, versions and settings only.
   Never read keys, tokens, cookies or keychains (the guard blocks this too).

## Steps
1. Lock on (rule 1).
2. Run the audit script and read its JSON:
   `python3 ~/.claude/skills/what-claude-really-finds/mac_audit.py` (add `--quick` to skip the full home scan).
3. Follow up only where the data asks for it, with read-only commands (`du -sh`, `ls -la`, `plutil -p`,
   `defaults read`, `launchctl print`, `find ... -size +1G`). Examples:
   - a startup item you don't recognise: `plutil -p <plist>` to show what it runs, then say what it is if you know,
     or say "unknown, look it up" if you don't.
   - an Electron app: compare its Electron major version with the supported ones listed at releases.electronjs.org.
4. Write the report in your reply (you cannot save files while locked):
   - **Top 5 findings**, each: what, size or state, the command, safe/review, what to do.
   - **Cleanup plan** table (never executed).
   - **Security posture** one line each: FileVault, SIP, Gatekeeper, firewall, Time Machine, unencrypted iPhone backups.
   - **What this audit cannot tell you** (copy from the script's `cannot_tell_you`).
   - If the user asked about a viral claim: walk the `how_to_check_a_viral_claim` steps against it.
5. End with: "The read-only lock ends on its own in N minutes, or run `rm ~/.claude/readonly-audit.lock` in Terminal."
