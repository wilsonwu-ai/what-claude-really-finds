#!/usr/bin/env python3
"""readonly_guard.py: a Claude Code PreToolUse hook that makes an audit READ-ONLY.

Dormant unless the lock file exists:  ~/.claude/readonly-audit.lock
While the lock exists (and has not expired), every tool call is checked:

  Bash      allowed only if EVERY command segment is on a read-only allowlist
  Write / Edit / MultiEdit / NotebookEdit   always blocked
  Read / Grep / Glob    blocked for secret locations (~/.ssh, ~/.aws, keychains, .env ...)
  anything else (MCP tools, WebFetch, ...)  blocked: an audit does not need them

Design (borrowed ideas, original code):
  * allowlist, not denylist: an unknown command is blocked, not waved through
  * fail closed: input we cannot parse is blocked
  * parse before judging: split on ; && || | & and newlines, unwrap sudo/env/time/
    nice/command, strip /usr/bin/ paths, look inside $(...) and bash -c '...'
  * text inside quotes is data: `grep "rm -rf" notes.txt` is fine
  * block = exit code 2 + a message on stderr naming the rule and a read-only alternative
  * no bypass variable. The lock expires on its own; a human can delete it from a
    normal terminal. The agent cannot, because rm and writes are blocked and the lock
    path itself is protected.

This is a floor, not a sandbox. It checks what the agent asks to run. For kernel-level
enforcement, run the agent under macOS sandbox-exec or anthropics/sandbox-runtime.
"""
import json
import os
import re
import shlex
import sys
import time

HOME = os.path.expanduser("~")
LOCK = os.environ.get("READONLY_AUDIT_LOCK_PATH", os.path.join(HOME, ".claude", "readonly-audit.lock"))

# verb -> None (always fine) or a checker(args) returning an error string or None
def _no_flags(*bad):
    def check(args):
        for a in args:
            for b in bad:
                if a == b or (b.endswith("=") and a.startswith(b)) or (len(b) == 2 and b.startswith("-") and a.startswith("-") and not a.startswith("--") and b[1] in a[1:]):
                    return f"flag {a} can change files"
        return None
    return check

def _find(args):
    bad = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
    for a in args:
        if a in bad:
            return f"find {a} can run or delete things; list the matches first, then decide by hand"
    return None

def _sed(args):
    for a in args:
        if a.startswith("-i") or a == "--in-place" or a.startswith("--in-place="):
            return "sed -i edits files in place"
    # a sed program containing a w (write) or e (execute) command
    for a in args:
        if not a.startswith("-") and re.search(r"(^|[;\s}])[we]\s*\S", a):
            return "sed w/e commands write files or run commands"
    return None

def _awk(args):
    for a in args:
        if not a.startswith("-") and re.search(r"system\s*\(|\|\s*\"|>\s*\"|print[^;]*>", a):
            return "awk program writes files or runs commands"
    return None

def _sub(allowed):
    def check(args):
        sub = next((a for a in args if not a.startswith("-")), None)
        if sub is None or sub in allowed:
            return None
        return f"subcommand '{sub}' is not read-only here (allowed: {', '.join(sorted(allowed))})"
    return check

def _defaults(args):
    sub = next((a for a in args if not a.startswith("-")), None)
    return None if sub in ("read", "read-type", "domains", "find") else "only `defaults read` is allowed"

def _sqlite(args):
    if "-readonly" not in args:
        return "sqlite3 needs -readonly during an audit"
    if any(re.search(r"\b(insert|update|delete|drop|alter|create|attach|vacuum|pragma\s+\w+\s*=|\.output|\.once|\.save|\.backup|\.shell|\.system)\b", a, re.I) for a in args):
        return "SQL that writes is blocked"
    return None

def _xargs(args):
    # xargs is only allowed in front of a read-only verb with a simple checker
    rest = [a for a in args if not a.startswith("-")]
    if not rest:
        return "xargs needs an explicit read-only command"
    return _check_simple([rest[0]] + rest[1:], via="xargs")

def _git(args):
    # drop global options that take a value (-C <dir>, -c k=v) before finding the subcommand
    rest, k = [], 0
    while k < len(args):
        if args[k] in ("-C", "-c", "--git-dir", "--work-tree"):
            k += 2; continue
        rest.append(args[k]); k += 1
    err = _sub({"status", "log", "show", "diff", "branch", "remote", "rev-parse", "ls-files", "describe",
                "config", "count-objects", "shortlog", "blame"})(rest)
    if err:
        return err
    sub = next((a for a in rest if not a.startswith("-")), None)
    if any(a == "--output" or a.startswith("--output=") or a in ("-o",) for a in rest):
        return "git --output writes a file"
    if sub == "config" and not any(a in ("--get", "--get-all", "--list", "-l", "--get-regexp") for a in rest):
        return "git config without --get/--list can write"
    if sub in ("branch", "remote") and any(a in ("-d", "-D", "--delete", "-m", "-M", "rm", "remove", "add", "rename", "set-url") for a in rest):
        return f"git {sub} with that option changes the repo"
    return None

def _sysctl(args):
    return "sysctl -w changes kernel settings" if any(a == "-w" or "=" in a for a in args) else None

def _date(args):
    return "date can set the clock" if any(re.fullmatch(r"\d{4,}", a) or a.startswith("-s") for a in args) else None

READONLY = {
    # files and disk
    "ls": None, "du": None, "df": None, "stat": None, "file": None, "find": _find, "wc": None,
    "cat": None, "head": None, "tail": None, "less": None, "more": None, "grep": None, "egrep": None, "fgrep": None,
    "rg": _no_flags("--pre"), "sort": _no_flags("-o", "--output="), "uniq": None, "cut": None, "tr": None, "column": None,
    "awk": _awk, "sed": _sed, "jq": None, "shasum": None, "md5": None, "cmp": None, "diff": None,
    "realpath": None, "readlink": None, "basename": None, "dirname": None, "pwd": None, "cd": None, "tree": _no_flags("-o"),
    "mdls": None, "mdfind": None, "mdutil": _no_flags("-i", "-E", "-a", "-d", "-X"), "xattr": _no_flags("-w", "-d", "-c", "-r"),
    "otool": None, "codesign": _no_flags("-s", "--sign", "--remove-signature", "-f", "--force"), "spctl": _no_flags("--add", "--remove", "--enable", "--disable", "--master-enable", "--master-disable", "--global-enable", "--global-disable"),
    "plutil": _no_flags("-convert", "-insert", "-replace", "-remove", "-extract", "-o", "-create", "-s"),
    "defaults": _defaults, "sqlite3": _sqlite, "xargs": _xargs, "printf": None, "echo": None,
    # system facts
    "sw_vers": None, "uname": None, "hostname": _no_flags("-s"), "whoami": None, "id": None, "date": _date, "uptime": None,
    "system_profiler": None, "ioreg": None, "sysctl": _sysctl, "vm_stat": None, "top": None, "ps": None, "lsof": None,
    "pkgutil": _sub({"--pkgs", "--pkg-info", "--files", "--file-info", "--pkg-info-plist", "--packages", "--group-pkgs", "--groups"}) if False else _no_flags("--forget", "--expand", "--flatten", "--learn", "--unlink"),
    "launchctl": _sub({"list", "print", "print-disabled", "blame", "dumpstate", "managername", "procinfo", "version", "help"}),
    "diskutil": _sub({"list", "info", "apfs", "activity", "listFilesystems"}) , "tmutil": _sub({"listbackups", "destinationinfo", "latestbackup", "machinedirectory", "status", "version", "listlocalsnapshots", "listlocalsnapshotdates", "calculatedrift", "uniquesize", "isexcluded"}),
    "fdesetup": _sub({"status", "isactive", "list", "haspersonalrecoverykey", "hasinstitutionalrecoverykey", "showdeferralinfo"}),
    "csrutil": _sub({"status"}), "brctl": _sub({"status", "log", "dump", "quota"}),
    "networksetup": lambda args: None if all(a.startswith("-list") or a.startswith("-get") or not a.startswith("-") for a in args) else "only networksetup -list*/-get* is allowed",
    "scutil": _no_flags("--set"), "ifconfig": lambda args: None if len([a for a in args if not a.startswith("-")]) <= 1 else "ifconfig with settings changes the network",
    "socketfilterfw": _no_flags("--setglobalstate", "--setblockall", "--add", "--remove", "--setallowsigned", "--setallowsignedapp", "--setstealthmode", "--setloggingmode", "--unblockapp", "--blockapp"),
    "git": _git, "which": None, "type": None, "command": None, "true": None, "false": None, "test": None, "[": None,
    "brew": _sub({"list", "info", "outdated", "config", "doctor", "--prefix", "--cellar", "--version", "leaves", "deps", "uses", "search", "desc"}),
    "npm": _sub({"ls", "list", "outdated", "view", "config", "root", "prefix", "--version", "-v"}),
    "pip": _sub({"list", "show", "freeze", "--version"}), "pip3": _sub({"list", "show", "freeze", "--version"}),
    "uv": _sub({"cache", "--version", "pip"}) if False else (lambda args: None if args[:2] in (["cache", "dir"], ["--version"], ["pip", "list"]) or args[:1] == ["--version"] else "only `uv cache dir` / `uv pip list` are allowed"),
    "docker": _sub({"ps", "images", "system", "info", "version", "volume", "inspect"}) if False else (lambda args: None if args[:1] in (["ps"], ["images"], ["info"], ["version"], ["inspect"]) or args[:2] in (["system", "df"], ["volume", "ls"], ["image", "ls"]) else "only read-only docker commands (ps, images, system df, volume ls) are allowed"),
    "sleep": None,
}

WRAPPERS = {"sudo", "env", "time", "nice", "nohup", "caffeinate", "command", "builtin", "exec"}
SECRET_RE = re.compile(
    r"(/\.ssh(/|$)|/\.aws(/|$)|/\.gnupg(/|$)|/\.config/gh(/|$)|/\.netrc$|/\.npmrc$|/\.pypirc$|/\.docker/config\.json$|"
    r"/Library/Keychains(/|$)|/Library/Cookies(/|$)|/\.env(\.|$)|/\.claude/secrets(/|$)|/\.claude/\.credentials|"
    r"/Login Data$|/Cookies$|id_rsa|id_ed25519|\.pem$|\.p12$|\.key$)")
PROTECTED_RE = re.compile(re.escape(LOCK) + r"|/\.claude/settings(\.local)?\.json|/\.claude/hooks(/|$)|readonly_guard\.py")


class Block(Exception):
    pass


def lock_active():
    try:
        with open(LOCK) as f:
            data = json.load(f)
        return time.time() < float(data.get("expires_at", 0))
    except FileNotFoundError:
        return False
    except Exception:
        return True  # a lock we cannot read still means "audit in progress": fail closed


def split_segments(cmd):
    """Split a shell string on control operators outside quotes. Raises Block on anything we will not judge."""
    segs, cur, i, q = [], [], 0, None
    while i < len(cmd):
        c = cmd[i]
        if q:
            if c == "\\" and q == '"' and i + 1 < len(cmd):
                cur.append(cmd[i:i + 2]); i += 2; continue
            # inside double quotes the shell still runs $(...) and `...`: judge them too
            if q == '"' and c == "`":
                raise Block("backtick command substitution is not allowed; run the inner command on its own")
            if q == '"' and c == "$" and cmd[i + 1:i + 2] == "(":
                depth, j = 1, i + 2
                while j < len(cmd) and depth:
                    depth += {"(": 1, ")": -1}.get(cmd[j], 0); j += 1
                if depth:
                    raise Block("unbalanced $(...)")
                inner = cmd[i + 2:j - 1]
                if inner.startswith("("):
                    raise Block("arithmetic expansion is not allowed")
                check_command(inner)
                cur.append("SUBST"); i = j; continue
            if c == q:
                q = None
            cur.append(c); i += 1; continue
        if c in "'\"":
            q = c; cur.append(c); i += 1; continue
        if c == "\\" and i + 1 < len(cmd):
            if cmd[i + 1] == "\n":
                i += 2; continue  # line continuation
            cur.append(cmd[i:i + 2]); i += 2; continue
        if c == "`":
            raise Block("backtick command substitution is not allowed; run the inner command on its own")
        if c == "$" and cmd[i + 1:i + 2] == "(":
            depth, j = 1, i + 2
            while j < len(cmd) and depth:
                depth += {"(": 1, ")": -1}.get(cmd[j], 0); j += 1
            if depth:
                raise Block("unbalanced $(...)")
            inner = cmd[i + 2:j - 1]
            if inner.startswith("("):
                raise Block("arithmetic expansion is not allowed")
            check_command(inner)  # the inner command must be read-only too
            cur.append("SUBST"); i = j; continue
        if c in "<>" and cmd[i + 1:i + 2] == "(":
            raise Block("process substitution is not allowed")
        if c in ";&|\n":
            two = cmd[i:i + 2]
            if c == "&" and cmd[i + 1:i + 2] == ">":
                cur.append(c); i += 1; continue
            segs.append("".join(cur)); cur = []
            i += 2 if two in ("&&", "||", ";;", "|&") else 1
            continue
        cur.append(c); i += 1
    if q:
        raise Block("unclosed quote")
    segs.append("".join(cur))
    return [s.strip() for s in segs if s.strip()]


SAFE_REDIRECT = re.compile(r"^(\d?|&)>>?\s*/dev/null$|^\d?>&\d$|^\d?<.*$")


def check_simple(seg):
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError as e:
        raise Block(f"cannot parse command ({e})")
    # redirections: only to /dev/null or fd duplication
    clean, k = [], 0
    while k < len(toks):
        t = toks[k]
        m = re.match(r"^(\d?|&)(>>?|<)(.*)$", t)
        if m:
            target = m.group(3) or (toks[k + 1] if k + 1 < len(toks) else "")
            if m.group(2) == "<":
                k += 1 if m.group(3) else 2; continue
            if target != "/dev/null" and not re.fullmatch(r"&\d", target):
                raise Block(f"output redirection to '{target}' writes a file; print to the screen instead")
            k += 1 if m.group(3) else 2; continue
        if t in (">", ">>"):
            raise Block("output redirection writes a file; print to the screen instead")
        clean.append(t); k += 1
    toks = clean
    # strip leading VAR=value assignments and wrappers
    while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]) or os.path.basename(toks[0]) in WRAPPERS):
        w = os.path.basename(toks.pop(0))
        if w == "sudo":
            while toks and toks[0].startswith("-"):
                toks.pop(0)
        if w in ("nice",) and toks and toks[0].startswith("-"):
            toks.pop(0)
    if not toks:
        return
    _check_simple(toks)


def _check_simple(toks, via=None):
    verb = os.path.basename(toks[0])
    args = toks[1:]
    if verb in ("bash", "sh", "zsh", "dash", "ksh"):
        if len(args) >= 2 and args[0] in ("-c", "-lc", "-ic"):
            check_command(args[1]); return None
        raise Block(f"{verb} running a script file is not allowed during an audit")
    if verb in ("python", "python3", "node", "ruby", "perl", "osascript", "swift", "php", "lua", "deno", "bun"):
        raise Block(f"{verb} can run arbitrary code; use a listed read-only command instead")
    if verb not in READONLY:
        raise Block(f"'{verb}' is not on the read-only list. Allowed examples: du, ls, find (no -delete/-exec), stat, mdls, defaults read, system_profiler")
    for a in args:
        if PROTECTED_RE.search(os.path.expanduser(a)) and verb not in ("ls", "stat", "test", "["):
            raise Block("the audit lock, Claude settings and the guard itself are off limits")
        if SECRET_RE.search(os.path.expanduser(a)) and verb in ("cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "awk", "sed", "jq", "sqlite3", "strings", "xxd", "plutil", "defaults", "cut", "sort"):
            raise Block("reading secret files (keys, tokens, cookies, keychains) is not part of an audit; list or size them instead")
    checker = READONLY[verb]
    if checker:
        err = checker(args)
        if err:
            raise Block(err)
    return None


def check_command(cmd):
    if len(cmd) > 20000:
        raise Block("command too long to check")
    for seg in split_segments(cmd):
        if seg.startswith("("):
            check_command(seg.strip("() "))
            continue
        if re.match(r"^(if|then|else|elif|fi|for|while|until|do|done|case|esac|function)\b", seg):
            raise Block("shell control flow is not allowed; run single read-only commands")
        if re.match(r"^\w+\s*\(\)", seg):
            raise Block("defining shell functions is not allowed")
        check_simple(seg)


def decide(event):
    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}
    if tool == "Bash":
        check_command(inp.get("command", ""))
        return
    if tool in ("Read", "Grep", "Glob", "LS"):
        p = os.path.expanduser(str(inp.get("file_path") or inp.get("path") or ""))
        if SECRET_RE.search(p):
            raise Block("reading secret files is not part of an audit")
        return
    if tool in ("TodoWrite", "TaskCreate", "TaskUpdate", "TaskList"):
        return
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        raise Block(f"{tool} is blocked while the read-only audit lock is on. Put findings in your reply; the human saves the report")
    raise Block(f"{tool} is blocked during a read-only audit")


def main():
    if not lock_active():
        sys.exit(0)
    try:
        event = json.load(sys.stdin)
    except Exception:
        print("readonly-guard: could not read the tool call, blocking (fail closed)", file=sys.stderr)
        sys.exit(2)
    try:
        decide(event)
    except Block as b:
        print(f"readonly-guard BLOCKED: {b}. (Read-only audit lock is on: {LOCK}. Only a human can remove it.)", file=sys.stderr)
        sys.exit(2)
    except Exception as e:  # any bug in the guard blocks rather than allows
        print(f"readonly-guard: internal error ({e.__class__.__name__}), blocking (fail closed)", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
