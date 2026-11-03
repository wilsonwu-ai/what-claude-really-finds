#!/usr/bin/env python3
"""lock.py: turn the read-only audit lock on, or check it.

  python3 guard/lock.py on [--minutes 60]   start a read-only window (the guard wakes up)
  python3 guard/lock.py status              is it on, and until when

There is deliberately no `off` command an agent could run: once the lock is on, the
guard blocks python and rm. It ends by itself when the time runs out, or a human ends it
early from a normal Terminal window:   rm ~/.claude/readonly-audit.lock
"""
import json
import os
import sys
import time

LOCK = os.environ.get("READONLY_AUDIT_LOCK_PATH", os.path.expanduser("~/.claude/readonly-audit.lock"))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("on", "status"):
        sys.exit(__doc__)
    if sys.argv[1] == "status":
        try:
            exp = json.load(open(LOCK))["expires_at"]
            left = exp - time.time()
            print(f"ON, {left / 60:.0f} min left" if left > 0 else "OFF (expired)")
        except FileNotFoundError:
            print("OFF")
        return
    minutes = 60
    if "--minutes" in sys.argv:
        minutes = max(5, min(240, int(sys.argv[sys.argv.index("--minutes") + 1])))
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    with open(LOCK, "w") as f:
        json.dump({"started_at": time.time(), "expires_at": time.time() + minutes * 60}, f)
    print(f"Read-only audit lock ON for {minutes} min. To end early, a human runs: rm {LOCK}")


if __name__ == "__main__":
    main()
