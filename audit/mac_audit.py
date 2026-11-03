#!/usr/bin/env python3
"""mac_audit.py: an honest, read-only audit of your Mac. No AI needed; Claude reads the output.

Every finding prints the exact command that produced it, so anyone can re-run it.
It never deletes, moves, changes or uploads anything, and it never opens file contents:
it reads sizes, versions, settings and lists. The only thing it writes is its own report,
and only when you pass --out.

usage: python3 mac_audit.py [--quick] [--out report.json] [--top 15]
"""
import argparse
import datetime as dt
import glob
import json
import os
import plistlib
import re
import subprocess
import sys

HOME = os.path.expanduser("~")
EVIDENCE = []


def sh(cmd, timeout=300):
    """Run one read-only command (list form, no shell) and keep it as evidence."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = p.stdout
    except Exception as e:
        out = f"(failed: {e.__class__.__name__})"
    EVIDENCE.append({"cmd": " ".join(cmd), "lines": len(out.splitlines())})
    return out


def human(kb):
    b = kb * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or unit == "TB":
            return f"{b:.0f} {unit}" if unit in ("B", "KB") else f"{b:.1f} {unit}"
        b /= 1024


def du_kb(path, timeout=600):
    out = sh(["du", "-skx", path], timeout=timeout)
    m = re.match(r"(\d+)", out.strip())
    return int(m.group(1)) if m else None


# Known space hogs: (label, path, safe_to_clear, what happens if you clear it)
KNOWN = [
    ("uv cache", "~/.cache/uv", "safe", "re-downloads Python packages on next install; close apps using uv first"),
    ("pip cache", "~/Library/Caches/pip", "safe", "re-downloads packages"),
    ("npm cache", "~/.npm", "safe", "re-downloads packages"),
    ("Hugging Face models", "~/.cache/huggingface", "review", "models must be downloaded again (can be many GB)"),
    ("Ollama models", "~/.ollama/models", "review", "local models must be pulled again"),
    ("LM Studio models", "~/.lmstudio/models", "review", "local models must be downloaded again"),
    ("Codex sessions", "~/.codex", "review", "old agent chat history is lost"),
    ("Claude Code projects", "~/.claude/projects", "review", "old session transcripts are lost"),
    ("Xcode DerivedData", "~/Library/Developer/Xcode/DerivedData", "safe", "Xcode rebuilds on next build"),
    ("iOS simulators", "~/Library/Developer/CoreSimulator", "review", "simulators and their apps are removed"),
    ("iPhone backups", "~/Library/Application Support/MobileSync/Backup", "review", "your only copy of an old phone may be here"),
    ("Messages attachments", "~/Library/Messages/Attachments", "review", "photos and files people sent you"),
    ("Docker data", "~/Library/Containers/com.docker.docker", "review", "images and volumes (databases) are lost"),
    ("Playwright browsers", "~/Library/Caches/ms-playwright", "safe", "re-downloaded by `npx playwright install`"),
    ("Puppeteer browsers", "~/.cache/puppeteer", "safe", "re-downloaded on next install"),
    ("Homebrew cache", "~/Library/Caches/Homebrew", "safe", "old bottles; `brew cleanup` manages this"),
    ("Cargo registry", "~/.cargo/registry", "safe", "re-downloads crates"),
    ("Gradle cache", "~/.gradle/caches", "safe", "re-downloads dependencies"),
    ("Trash", "~/.Trash", "safe", "already deleted by you"),
    ("Downloads folder", "~/Downloads", "review", "your files; sort by size and decide"),
    ("Photos library", "~/Pictures/Photos Library.photoslibrary", "review", "your photos: check iCloud Photos before touching"),
]


def disk(top, quick):
    out = {"volume": {}, "known": [], "home_top": []}
    df = sh(["df", "-k", "/System/Volumes/Data"]).splitlines()
    if len(df) > 1:
        f = df[1].split()
        out["volume"] = {"size": human(int(f[1])), "used": human(int(f[2])), "free": human(int(f[3])), "cmd": "df -k /System/Volumes/Data"}
    for label, p, safety, consequence in KNOWN:
        path = os.path.expanduser(p)
        if os.path.exists(path):
            kb = du_kb(path)
            if kb and kb > 200 * 1024:
                out["known"].append({"what": label, "path": p, "size": human(kb), "kb": kb, "safety": safety,
                                     "if_cleared": consequence, "cmd": f"du -skx {p}"})
    out["known"].sort(key=lambda r: -r["kb"])
    if not quick:
        rows = []
        for entry in sorted(os.listdir(HOME)):
            path = os.path.join(HOME, entry)
            if os.path.islink(path) or entry in ("Library",):
                continue
            kb = du_kb(path)
            if kb:
                rows.append((kb, "~/" + entry))
        lib = os.path.join(HOME, "Library")
        for entry in sorted(os.listdir(lib)):
            path = os.path.join(lib, entry)
            if os.path.islink(path):
                continue
            kb = du_kb(path)
            if kb:
                rows.append((kb, "~/Library/" + entry))
        rows.sort(reverse=True)
        out["home_top"] = [{"path": p, "size": human(kb), "cmd": f"du -skx '{p}'"} for kb, p in rows[:top]]
    return out


def bundle_version(app_path):
    try:
        with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as f:
            info = plistlib.load(f)
        return info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    except Exception:
        return None


UA_RE = re.compile(rb"Chrome/(\d+\.\d+\.\d+\.\d+) Electron/(\d+\.\d+\.\d+)")


def binary_versions(path):
    """Find the 'Chrome/x Electron/y' user-agent string inside the framework binary (read in 8 MB chunks)."""
    try:
        with open(path, "rb") as f:
            tail = b""
            while True:
                chunk = f.read(8 << 20)
                if not chunk:
                    break
                m = UA_RE.search(tail + chunk)
                if m:
                    EVIDENCE.append({"cmd": f"strings '{path}' | grep Electron/", "lines": 1})
                    return m.group(2).decode(), m.group(1).decode(), "binary user-agent string"
                tail = chunk[-200:]
    except Exception:
        pass
    return None, None, None


def browsers():
    """Embedded Chromium engines: Electron apps and test-automation browser caches."""
    out = {"electron_apps": [], "automation_browsers": []}
    apps = glob.glob("/Applications/*.app") + glob.glob(os.path.join(HOME, "Applications", "*.app"))
    for app in sorted(apps):
        fw = os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework")
        if os.path.isdir(fw):
            # Trust the binary, not the plist: some apps stamp their own version into the
            # framework's Info.plist (seen: Kiro reports 1.4.26, its binary says Electron 44).
            ver, chrome, source = binary_versions(os.path.join(fw, "Electron Framework"))
            if not ver:
                for plist in glob.glob(os.path.join(fw, "Versions", "*", "Resources", "Info.plist")):
                    try:
                        with open(plist, "rb") as f:
                            ver = plistlib.load(f).get("CFBundleVersion")
                        source = "Info.plist (may be the app's own version)"
                        break
                    except Exception:
                        pass
            out["electron_apps"].append({"app": os.path.basename(app), "app_version": bundle_version(app),
                                         "electron": ver, "chrome": chrome, "source": source,
                                         "cmd": f"strings '{fw}/Electron Framework' | grep -m1 -E 'Chrome/[0-9.]+ Electron/'"})
    for root in ("~/Library/Caches/ms-playwright", "~/.cache/puppeteer", "~/.cache/ms-playwright"):
        r = os.path.expanduser(root)
        if os.path.isdir(r):
            for d in sorted(os.listdir(r)):
                if d.startswith(("chromium", "chrome", "firefox", "webkit")):
                    out["automation_browsers"].append({"path": f"{root}/{d}", "cmd": f"ls {root}"})
    majors = [int(e["electron"].split(".")[0]) for e in out["electron_apps"] if e["electron"] and e["electron"].split(".")[0].isdigit()]
    out["note"] = ("Compare each Electron version with the currently supported releases at "
                   "https://releases.electronjs.org (Electron supports the latest 3 major versions). "
                   "An old Electron means an old built-in Chromium; update the app, do not delete its files.")
    out["oldest_electron_major"] = min(majors) if majors else None
    return out


def startup():
    out = {"user_agents": [], "system_agents": [], "system_daemons": [], "running_non_apple": 0}
    for key, d in (("user_agents", "~/Library/LaunchAgents"), ("system_agents", "/Library/LaunchAgents"), ("system_daemons", "/Library/LaunchDaemons")):
        p = os.path.expanduser(d)
        if os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                if f.endswith(".plist"):
                    prog = None
                    try:
                        with open(os.path.join(p, f), "rb") as fh:
                            pl = plistlib.load(fh)
                        prog = pl.get("Program") or (pl.get("ProgramArguments") or [None])[0]
                    except Exception:
                        pass
                    out[key].append({"label": f[:-6], "runs": prog, "cmd": f"plutil -p '{d}/{f}'"})
    lst = sh(["launchctl", "list"]).splitlines()[1:]
    out["running_non_apple"] = sum(1 for l in lst if l.split() and not l.split()[-1].startswith("com.apple."))
    out["running_cmd"] = "launchctl list | grep -v com.apple"
    return out


def security():
    def first(cmd):
        return sh(cmd).strip().splitlines()[0] if sh(cmd).strip() else "(no output)"
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    return {
        "macos": first(["sw_vers", "-productVersion"]),
        "filevault": first(["fdesetup", "status"]),
        "sip": first(["csrutil", "status"]),
        "gatekeeper": first(["spctl", "--status"]),
        "firewall": first([fw, "--getglobalstate"]) if os.path.exists(fw) else "(not found)",
        "time_machine": (sh(["tmutil", "destinationinfo"]).strip().splitlines() or ["(no destination)"])[0],
        "cmds": ["sw_vers -productVersion", "fdesetup status", "csrutil status", "spctl --status",
                 f"{fw} --getglobalstate", "tmutil destinationinfo"],
    }


def where_things_live():
    out = {}
    bk = os.path.expanduser("~/Library/Application Support/MobileSync/Backup")
    if os.path.isdir(bk):
        rows = []
        for d in sorted(os.listdir(bk)):
            p = os.path.join(bk, d)
            info = os.path.join(p, "Info.plist")
            name, date, enc = None, None, None
            try:
                with open(info, "rb") as f:
                    pl = plistlib.load(f)
                name, date = pl.get("Device Name"), str(pl.get("Last Backup Date"))[:10]
            except Exception:
                pass
            try:
                with open(os.path.join(p, "Manifest.plist"), "rb") as f:
                    enc = plistlib.load(f).get("IsEncrypted")
            except Exception:
                pass
            rows.append({"device": name, "last_backup": date, "encrypted": enc, "size": human(du_kb(p) or 0)})
        out["iphone_backups"] = {"rows": rows, "cmd": "ls ~/Library/Application\\ Support/MobileSync/Backup",
                                 "why": "an unencrypted backup holds a full copy of a phone; encrypt it in Finder or remove old ones"}
    lib = os.path.expanduser("~/Pictures/Photos Library.photoslibrary")
    if os.path.exists(lib):
        out["photos_library"] = {"path": "~/Pictures/Photos Library.photoslibrary", "size": human(du_kb(lib) or 0),
                                 "cmd": "du -skx ~/Pictures/Photos\\ Library.photoslibrary"}
    return out


CANNOT = [
    "It cannot see what an app sent over the network in the past. macOS keeps no such log by default; "
    "a claim like 'it found 17,000 photos on a server' needs a network capture made at the time.",
    "It cannot read your iPhone. A phone is only visible through a backup or a tool like libimobiledevice, "
    "and iOS apps are sandboxed from each other's files.",
    "It cannot recover deleted files: APFS and iOS encrypt per file, so 'deleted' data without a backup copy is gone.",
    "It does not judge whether a startup item is malicious. It lists them with what they run, so you can look each one up.",
]

VERIFY_A_VIRAL_CLAIM = [
    "1. Ask for the output. A real audit has a terminal screenshot with the command visible.",
    "2. Ask for the mechanism. What file, log or API held the evidence? Does that log exist on that OS?",
    "3. Run it yourself. If the prompt is not in the post, the result cannot be checked.",
    "4. Check the count. Exact huge numbers with no listing are a storytelling device, not data.",
    "5. Ask why it needed an AI. Most real findings come from one built-in command (du, launchctl list, fdesetup status).",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="skip the full home-folder size scan")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--out", help="also save the JSON report here")
    a = ap.parse_args()
    if sys.platform != "darwin":
        sys.exit("mac_audit.py runs on macOS only")
    t0 = dt.datetime.now()
    report = {
        "generated": t0.isoformat(timespec="seconds"),
        "read_only": True,
        "disk": disk(a.top, a.quick),
        "embedded_browsers": browsers(),
        "startup_items": startup(),
        "security": security(),
        "where_things_live": where_things_live(),
        "cannot_tell_you": CANNOT,
        "how_to_check_a_viral_claim": VERIFY_A_VIRAL_CLAIM,
    }
    report["seconds"] = round((dt.datetime.now() - t0).total_seconds(), 1)
    report["commands_run"] = len(EVIDENCE)
    s = json.dumps(report, indent=1, default=str)
    if a.out:
        with open(a.out, "w") as f:
            f.write(s)
    print(s)


if __name__ == "__main__":
    main()
