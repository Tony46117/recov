#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
opt.py - one-shot system auto-detect, clean and optimize tool.

Auto-detects hardware and software, scans fixed drives and any connected
USB drives for junk files, duplicate files and suspicious executables,
then cleans and optimizes - WITHOUT breaking anything.

Safety model:
  * Nothing is deleted until the plan is approved (opt.py -y auto-approves
    the safe plan: junk + redundant duplicates only).
  * Only well-known regenerable locations are proposed as junk.
  * User documents / media / code / configs / databases are never touched.
  * Suspicious executables are QUARANTINED (reversible), never deleted.
  * A full session log is written to opt_log_<timestamp>.txt.

Usage:
  sudo python3 opt.py            # full interactive run (recommended)
  python3 opt.py -y              # auto-approve the safe plan
  python3 opt.py --scan-only     # detect + scan, change nothing
  python3 opt.py --no-anim       # skip the intro animation
"""

import argparse
import ctypes
import hashlib
import os
import platform
import re
import shutil
import socket
import stat
import string
import subprocess
import sys
import tempfile
import time

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
VERSION = "1.0.0"
START_TS = time.time()
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

CLR = (os.environ.get("TERM", "") != "dumb") and sys.stdout.isatty()
if CLR:
    G, R, Y, C, M, B, D, N = (
        "\033[92m", "\033[91m", "\033[93m", "\033[96m",
        "\033[95m", "\033[1m", "\033[2m", "\033[0m",
    )
else:
    G = R = Y = C = M = B = D = N = ""

MAX_FILE_SIZE = 512 * 1024 * 1024   # never open files bigger than 512 MB
DUP_MIN_SIZE = 4 * 1024             # duplicate detection only above 4 KB
HASH_CHUNK = 1024 * 1024            # 1 MB read chunks
WALK_TIMEOUT = 180                  # seconds per drive walk
DUP_TIME_BUDGET = 45                # seconds for the duplicate hashing phase

LOG_LINES = []


# ----------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------
def is_admin():
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return "{:,.1f} {}".format(n, u)
        n /= 1024.0
    return "{:,.1f} PB".format(n)


def log(msg=""):
    print(msg, flush=True)
    LOG_LINES.append(re.sub(r"\033\[[0-9;?]*[A-Za-z]", "", msg))


def run(cmd, timeout=90):
    """Run a command, return (ok, stdout). Never raises."""
    try:
        p = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout,
        )
        return (p.returncode == 0, p.stdout or "")
    except Exception:
        return (False, "")


def safe_read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def enable_windows_ansi():
    if IS_WINDOWS and CLR:
        try:
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Intro animation (fastfetch-style)
# ----------------------------------------------------------------------------
LOGO = [
    "        -ooo-        ",
    "      +osssso+      ",
    "    +osssssssso+    ",
    "   .osssssso+       ",
    "  .osssso+          ",
    " +osssso            ",
    "+osssso             ",
    "ossss+              ",
    "+osssso             ",
    " .osssso+           ",
    "   .osssssso+       ",
    "     +osssso+      ",
    "        -ooo-        ",
]
LOGO_W = 21

INFO_LINES = []


def render_info_lines():
    info = detect_info()
    lines = []
    for k, v in info.items():
        lines.append("{}{:>7}{}{}  {}{}".format(C, k, N, D, B, v, N))
    return lines


def intro():
    """fastfetch-like animated header."""
    if not CLR or os.environ.get("OPT_NO_ANIM"):
        print_info_block()
        return
    sys.stdout.write("\033[?25l")
    try:
        sys.stdout.write("\033[H\033[2J")
        rows = len(LOGO)
        for i in range(rows + 3):
            sys.stdout.write("\033[H")
            for r in range(rows):
                art = LOGO[r]
                n = int(i * 2.2) - r * 2
                shown = art[:n] if n > 0 else ""
                tail = LOGO[r][n:] if 0 < n < len(art) else ""
                line = "   {}{}{}{}{}".format(G, shown, D, tail, N)
                if i >= rows and r < len(INFO_LINES):
                    line = "   {}{}  {}".format(art[:5], D + "." * 5 + N, INFO_LINES[r])
                sys.stdout.write(line + "\033[K\n")
            if i >= rows and rows < len(INFO_LINES):
                for r in range(rows, len(INFO_LINES)):
                    sys.stdout.write("   " + " " * LOGO_W + INFO_LINES[r] + "\033[K\n")
            sys.stdout.write("\033[K\n" + "{}        opt.py v{} - scanning system...{}\033[K\n"
                             .format(D, VERSION, N))
            sys.stdout.flush()
            time.sleep(0.035)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def print_info_block():
    art_h = len(LOGO)
    for r in range(max(art_h, len(INFO_LINES))):
        art = LOGO[r] if r < art_h else " " * LOGO_W
        info = INFO_LINES[r] if r < len(INFO_LINES) else ""
        log("   {}{}{}  {}".format(G, art, N, info))


# ----------------------------------------------------------------------------
# System / hardware / software detection
# ----------------------------------------------------------------------------
def detect_info():
    info = {}
    info["OS"] = "{} {}".format(platform.system(), platform.release())
    info["Host"] = platform.node() or socket.gethostname() or "?"
    info["Kernel"] = _trunc(platform.version(), 44)
    info["Uptime"] = _uptime()
    info["Shell"] = os.path.basename(
        os.environ.get("SHELL", "python" if not IS_WINDOWS else "cmd"))
    info["Admin"] = "yes" if is_admin() else "no"
    info["CPU"] = _trunc(_cpu(), 54)
    info["GPU"] = _trunc(_gpu(), 54)
    info["RAM"] = _ram()
    info["Disks"] = _disks_summary()
    return info


def _trunc(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _fmt_uptime(secs):
    m, s = divmod(int(secs), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return "{}d {}h {}m".format(d, h, m)
    if h:
        return "{}h {}m".format(h, m)
    return "{}m {}s".format(m, s)


def _uptime():
    try:
        if IS_LINUX:
            with open("/proc/uptime") as f:
                return _fmt_uptime(float(f.read().split()[0]))
        if IS_MACOS:
            ok, out = run(["sysctl", "-n", "kern.boottime"])
            m = re.search(r"sec\s*=\s*(\d+)", out)
            if ok and m:
                return _fmt_uptime(time.time() - int(m.group(1)))
        if IS_WINDOWS:
            ok, out = run(["net", "stats", "srv"])
            m = re.search(r"Statistics since (.+)", out)
            if ok and m:
                return m.group(1).strip()
    except Exception:
        pass
    return "unknown"


def _cpu():
    try:
        if IS_LINUX and os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        return _with_threads(line.split(":", 1)[1].strip())
        if IS_WINDOWS:
            ok, out = run(["wmic", "cpu", "get", "name"])
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if ok and len(lines) > 1:
                return _with_threads(lines[1])
        if IS_MACOS:
            ok, out = run(["sysctl", "-n", "machdep.cpu.brand_string"])
            if ok and out.strip():
                return _with_threads(out.strip())
        return _with_threads(platform.processor() or platform.machine())
    except Exception:
        return "unknown"


def _with_threads(cpu):
    n = os.cpu_count() or 0
    return "{} ({} threads)".format(cpu, n) if n else cpu


def _ram():
    try:
        if IS_LINUX:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        return human(int(line.split()[1]) * 1024)
        if IS_WINDOWS:
            ok, out = run(["wmic", "computersystem", "get", "TotalPhysicalMemory"])
            v = re.findall(r"\d+", out)
            if ok and v:
                return human(int(v[0]))
        if IS_MACOS:
            ok, out = run(["sysctl", "hw.memsize"])
            v = re.findall(r"\d+", out)
            if ok and v:
                return human(int(v[0]))
    except Exception:
        pass
    return "unknown"


def _gpu():
    try:
        if IS_LINUX:
            ok, out = run("lspci 2>/dev/null | grep -iE 'vga|3d' | head -1")
            if ok and out.strip():
                return out.split(":", 2)[-1].strip()
            if os.path.exists("/proc/fb"):
                first = safe_read("/proc/fb").splitlines()
                if first and first[0].strip():
                    return "fb: " + first[0].strip()
            return "integrated / unknown"
        if IS_WINDOWS:
            ok, out = run(["wmic", "path", "win32_VideoController", "get", "name"])
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if ok and len(lines) > 1:
                return lines[1]
            return "unknown"
        if IS_MACOS:
            ok, out = run(["system_profiler", "SPDisplaysDataType"])
            m = re.search(r"Chipset Model: (.+)", out)
            if ok and m:
                return m.group(1).strip()
            return "unknown"
    except Exception:
        pass
    return "unknown"


def _list_mounts():
    """Return list of dicts: device, mountpoint, fstype, opts."""
    out = []
    try:
        if IS_WINDOWS:
            for letter in string.ascii_uppercase:
                root = "{}:\\".format(letter)
                if os.path.exists(root):
                    out.append({"device": letter + ":", "mountpoint": root,
                                "fstype": "", "opts": ""})
            return out
        candidates = ["/", "/Volumes"] if IS_MACOS else None
        if IS_MACOS:
            seen = set()
            for base in candidates:
                if os.path.isdir(base):
                    for name in sorted(os.listdir(base)):
                        mp = os.path.join(base, name)
                        if os.path.ismount(mp) and mp not in seen:
                            seen.add(mp)
                            out.append({"device": name, "mountpoint": mp,
                                        "fstype": "", "opts": ""})
            return out
        with open("/proc/self/mounts") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3:
                    out.append({"device": p[0], "mountpoint": p[1],
                                "fstype": p[2], "opts": p[3] if len(p) > 3 else ""})
    except Exception:
        pass
    return out


def _disks_summary():
    parts, seen = [], set()
    for p in _list_mounts():
        mp, dev = p["mountpoint"], p["device"]
        if mp in seen:
            continue
        seen.add(mp)
        try:
            u = shutil.disk_usage(mp)
            parts.append("{} {} {}".format(dev, human(u.used), human(u.total)))
        except Exception:
            parts.append(dev)
    return _trunc(", ".join(parts) or "none", 56)


# ----------------------------------------------------------------------------
# Drive discovery (fixed + USB)
# ----------------------------------------------------------------------------
LINUX_IGNORED_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "squashfs", "cgroup",
    "cgroup2", "overlay", "mqueue", "hugetlbfs", "tracefs", "debugfs", "bpf",
    "configfs", "fusectl", "securityfs", "pstore", "efivarfs", "ramfs",
    "autofs", "binfmt_misc", "fuse.gvfsd-fuse", "swap",
}
LINUX_IGNORED_MP = ("/proc", "/sys", "/dev", "/run", "/boot/efi", "/snap",
                    "/var/lib/docker", "/var/lib/containers")


def find_drives():
    """Return {'fixed': [mountpoints], 'usb': [mountpoints]}."""
    fixed, usb = [], []
    try:
        if IS_LINUX:
            removable = {}
            import glob as _g
            for f in _g.glob("/sys/block/*/removable"):
                dev = os.path.basename(os.path.dirname(f))
                removable[dev] = safe_read(f).strip() == "1"
            for p in _list_mounts():
                dev, mp, fs = p["device"], p["mountpoint"], p["fstype"]
                if fs in LINUX_IGNORED_FS:
                    continue
                if mp.startswith(LINUX_IGNORED_MP) or mp == "/boot":
                    continue
                real = os.path.realpath(dev)
                short = os.path.basename(real)
                is_rem = False
                for k, v in removable.items():
                    if short == k or short.startswith(k) or real.startswith("/dev/" + k):
                        is_rem = v
                if is_rem:
                    usb.append(mp)
                else:
                    fixed.append(mp)
        elif IS_WINDOWS:
            DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3
            for letter in string.ascii_uppercase:
                root = "{}:\\".format(letter)
                if not os.path.exists(root):
                    continue
                try:
                    t = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
                except Exception:
                    continue
                if t == DRIVE_REMOVABLE:
                    usb.append(root)
                elif t == DRIVE_FIXED:
                    fixed.append(root)
        elif IS_MACOS:
            for p in _list_mounts():
                if p["mountpoint"] != "/":
                    usb.append(p["mountpoint"])
                else:
                    fixed.append(p["mountpoint"])
    except Exception:
        pass

    # Drop bind-mounted single files (e.g. /etc/hosts in containers) and
    # mounts nested inside already-listed mounts.
    def _is_dir(mp):
        return os.path.isdir(mp)

    fixed = [mp for mp in fixed if _is_dir(mp)]
    usb = [mp for mp in usb if _is_dir(mp)]

    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {"fixed": uniq(fixed), "usb": uniq(usb)}


def _nested_under(root, roots):
    for r in roots:
        if r == root:
            continue
        try:
            if os.path.commonpath([os.path.abspath(r), os.path.abspath(root)]) \
                    == os.path.abspath(r):
                return True
        except Exception:
            pass
    return False


# ----------------------------------------------------------------------------
# Scanning: junk files, duplicates, suspicious executables
# ----------------------------------------------------------------------------
JUNK_EXT = {
    ".tmp", ".temp", ".bak", ".old", ".cache", ".crdownload", ".part",
    ".dmp", ".log", ".etl", ".evtx", ".dump", ".swp", ".swo", ".vmem",
}
JUNK_EXT_TUPLE = tuple(JUNK_EXT)

SUSPICIOUS_NAMES = re.compile(
    r"^(svchost|csrss|lsass|services|smss|winlogon|explorer|taskhost"
    r"|rundll32|regsvr32|dwm|conhost)\.exe$", re.IGNORECASE)

MALWARE_HINTS = re.compile(
    r"(keygen|crack|patched?\.exe|keygen|nuker|trojan|rat\.exe|stealer"
    r"|miner|xmrig|coinhive|kms[-_]?pico|hwid|autokms|removewat"
    r"|dlm|loader\.exe)", re.IGNORECASE)

SKIP_DIR_NAMES = {
    # speed: dependency / vcs dirs are not user data
    "node_modules", "__pycache__", ".git", ".svn", ".hg", ".tox", ".venv",
    "venv", ".m2", ".gradle", ".cargo", ".rustup", ".nvm",
    # system heavyweights (system junk handled by targeted cleaners)
    "Windows", "Program Files", "Program Files (x86)", "ProgramData",
    "$Recycle.Bin", "System Volume Information", "Windows.old",
    "proc", "sys", "dev", "run", "snap", "boot", "usr", "lib", "lib64",
    "lib32", "bin", "sbin", "etc", "opt", "srv", "var", "Applications",
    "Library", "private",
}

SUSPECT_QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), ".opt_quarantine")


def classify(path, st):
    """Classify a regular file: 'junk', 'suspect' or ''."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    size = st.st_size
    if size > MAX_FILE_SIZE:
        return ""
    pp = path.lower()
    parent = os.path.basename(os.path.dirname(path)).lower()
    if ext in JUNK_EXT and parent in ("tmp", "temp", "cache", "prefetch"):
        return "junk"
    if ext in JUNK_EXT and ("/tmp/" in pp or "\\temp\\" in pp
                            or "/.cache/" in pp or "\\cache\\" in pp):
        return "junk"
    if ext in (".crdownload", ".part") and "download" in pp:
        return "junk"
    if ext == ".exe":
        if MALWARE_HINTS.search(name):
            return "suspect"
        if SUSPICIOUS_NAMES.search(name) and not _in_system_bin_dir(path):
            return "suspect"
    if ext in (".scr", ".pif") and size < 50 * 1024 * 1024:
        return "suspect"
    return ""


def _in_system_bin_dir(path):
    lp = path.lower()
    return lp.startswith(("c:\\windows\\", "c:\\program files",
                          "/system/", "/usr/"))


def walk_drive(root, files_by_size, junk, suspects, progress=None):
    """Walk one root, filling files_by_size / junk / suspects. Returns count."""
    t0 = time.time()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True,
                                                onerror=lambda e: None):
        if time.time() - t0 > WALK_TIMEOUT:
            log("  {}   (walk time limit reached on {}){}".format(D, root, N))
            break
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        dirnames.sort()
        for fn in filenames:
            count += 1
            if progress and count % 4096 == 0:
                progress(count)
            p = os.path.join(dirpath, fn)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            tag = classify(p, st)
            if tag == "junk":
                junk.append(p)
            elif tag == "suspect":
                suspects.append(p)
            if DUP_MIN_SIZE <= st.st_size <= MAX_FILE_SIZE:
                files_by_size.setdefault(st.st_size, []).append(p)
    return count


def _partial_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read(64 * 1024))
        return h.hexdigest()
    except Exception:
        return None


def _full_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def find_duplicates(files_by_size):
    """Return (groups, redundant_count, wasted_bytes).

    groups = [(size, [paths...]), ...] - identical-content file sets.
    """
    groups, redundant, wasted = [], 0, 0
    t0 = time.time()
    sizes = sorted((s for s, ps in files_by_size.items() if len(ps) > 1),
                   reverse=True)
    for size in sizes:
        if time.time() - t0 > DUP_TIME_BUDGET:
            log("  {}   (duplicate scan hit its time budget){}".format(D, N))
            break
        paths = files_by_size[size]
        partial = {}
        for p in paths:
            h = _partial_hash(p)
            if h:
                partial.setdefault(h, []).append(p)
        for cand in partial.values():
            if len(cand) < 2:
                continue
            full = {}
            for p in cand:
                fh = _full_hash(p)
                if fh:
                    full.setdefault(fh, []).append(p)
            for grp in full.values():
                if len(grp) >= 2:
                    grp.sort(key=lambda p: (os.path.getmtime(p), p))
                    groups.append((size, grp))
                    redundant += len(grp) - 1
                    wasted += (len(grp) - 1) * size
    return groups, redundant, wasted


# ----------------------------------------------------------------------------
# Safe deletion
# ----------------------------------------------------------------------------
PROTECTED_EXT = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
                 ".txt", ".md", ".py", ".js", ".ts", ".tsx", ".jsx", ".c",
                 ".cpp", ".h", ".hpp", ".java", ".go", ".rs", ".sh", ".sql",
                 ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
                 ".env", ".db", ".sqlite", ".sqlite3", ".wallet", ".key",
                 ".pem", ".csv", ".ods", ".odt")

USER_DIRS = ("documents", "desktop", "pictures", "music", "videos", "photos")


def _looks_important(path):
    """Last-line defense: refuse to delete user data."""
    lp = path.lower()
    name = os.path.basename(lp)
    if name.endswith(PROTECTED_EXT):
        return True
    if ".git" in lp or "wallet" in lp or "keystore" in lp:
        return True
    for d in USER_DIRS:
        if "/{}/".format(d) in lp or "\\{}\\".format(d) in lp:
            if not name.endswith(JUNK_EXT_TUPLE):
                return True
    return False


def safe_delete(path):
    """Delete one regular file defensively. Returns (ok, bytes_freed)."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            return (False, 0)
        if _looks_important(path):
            return (False, 0)
        os.remove(path)
        return (True, st.st_size)
    except Exception:
        return (False, 0)


def delete_approved(path):
    """Delete a user-approved duplicate (bypasses _looks_important on purpose,
    but still refuses anything that is not a plain regular file)."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            return (False, 0)
        os.remove(path)
        return (True, st.st_size)
    except Exception:
        return (False, 0)


def quarantine(path):
    """Move a suspect file into ~/.opt_quarantine (reversible)."""
    try:
        os.makedirs(SUSPECT_QUARANTINE_DIR, exist_ok=True)
        dest = os.path.join(
            SUSPECT_QUARANTINE_DIR,
            hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:10]
            + "_" + os.path.basename(path))
        if os.path.exists(dest):
            return False
        shutil.move(path, dest)
        with open(dest + ".meta", "w") as f:
            f.write(path)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------------
# Optimization steps
# ----------------------------------------------------------------------------
TEMP_AGE_SECS = 72 * 3600  # shared tmp dirs: only remove entries older than this


def _tmp_dirs():
    dirs = {tempfile.gettempdir()}
    if IS_LINUX:
        dirs.update(["/var/tmp", "/var/crash"])
    elif IS_WINDOWS:
        windir = os.environ.get("SystemRoot", "C:\\Windows")
        dirs.update([os.path.join(windir, "Temp"),
                     os.path.join(windir, "SoftwareDistribution", "Download")])
    elif IS_MACOS:
        dirs.add("/private/var/tmp")
    return [d for d in dirs if os.path.isdir(d)]


def clear_temp_dirs():
    n, b = 0, 0
    for d in _tmp_dirs():
        try:
            entries = os.listdir(d)
        except Exception:
            continue
        now = time.time()
        for entry in entries:
            p = os.path.join(d, entry)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            # Live system tmp dirs carry sockets/locks of running apps.
            # Only touch entries that have been idle for TEMP_AGE_SECS.
            if now - getattr(st, "st_mtime", now) < TEMP_AGE_SECS:
                continue
            try:
                if stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(p, ignore_errors=True)
                    n += 1
                elif stat.S_ISREG(st.st_mode):
                    ok, sz = safe_delete(p)
                    if ok:
                        n += 1
                        b += sz
            except Exception:
                continue
    return n, b


def clear_pkg_caches():
    n, b = 0, 0
    home = os.path.expanduser("~")
    targets = [os.path.join(home, ".cache", "pip"),
               os.path.join(home, ".npm", "_cacache"),
               os.path.join(home, ".cache", "yarn"),
               os.path.join(home, "AppData", "Local", "pip", "cache"),
               os.path.join(home, "AppData", "Local", "npm-cache")]
    for t in targets:
        if not os.path.isdir(t):
            continue
        for dirpath, dirnames, filenames in os.walk(t, onerror=lambda e: None):
            for fn in filenames:
                ok, sz = safe_delete(os.path.join(dirpath, fn))
                if ok:
                    n += 1
                    b += sz
    return n, b


def optimize_wifi():
    if IS_LINUX:
        if shutil.which("nmcli"):
            run("nmcli networking connectivity check", timeout=20)
            run("ip route flush cache", timeout=15)
            return "nmcli connectivity checked, route cache flushed"
        return "no wifi tool found (skipped)"
    if IS_WINDOWS:
        run(["ipconfig", "/flushdns"])
        run("netsh int tcp set global autotuninglevel=normal")
        return "dns cache flushed, tcp autotuning set to normal"
    if IS_MACOS:
        run("networksetup -setv6off Wi-Fi", timeout=20)
        return "wifi checked (ipv6 off for snappier dns)"
    return "unsupported platform"


def optimize_os():
    msgs = []
    if IS_LINUX:
        if is_admin():
            if shutil.which("journalctl"):
                run("journalctl --vacuum-time=7d", timeout=30)
                msgs.append("journald vacuumed to 7d")
            if shutil.which("fstrim"):
                ok, _ = run("fstrim -av", timeout=120)
                if ok:
                    msgs.append("ssd trim run")
        run("sync")
        msgs.append("fs sync flushed")
        if not is_admin():
            msgs.append("(run with sudo for journal vacuum + ssd trim)")
    elif IS_WINDOWS:
        run(["ipconfig", "/flushdns"])
        msgs.append("dns flushed")
        if is_admin():
            msgs.append("admin: run 'defrag C: /O' occasionally for hdd, trim is automatic on ssd")
        else:
            msgs.append("(admin tips: defrag hdd, disable startup bloat in task manager)")
    elif IS_MACOS:
        run("purge", timeout=60)
        msgs.append("memory purge attempted")
    return "; ".join(msgs)


def list_startup():
    items = []
    try:
        if IS_LINUX:
            d = os.path.join(os.path.expanduser("~"), ".config", "autostart")
            if os.path.isdir(d):
                items = [f[:-8] for f in os.listdir(d) if f.endswith(".desktop")]
        elif IS_WINDOWS:
            ok, out = run(["reg", "query",
                           r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])
            if ok:
                items = [l.split("    ")[0].strip() for l in out.splitlines()
                         if "    " in l and "REG_" in l]
        elif IS_MACOS:
            d = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")
            if os.path.isdir(d):
                items = os.listdir(d)
    except Exception:
        pass
    return items


# ----------------------------------------------------------------------------
# Reporting + plan approval + execution
# ----------------------------------------------------------------------------
def progress_cb(count):
    sys.stdout.write("\r  {}files seen: {:>8}{}".format(D, count, N))
    sys.stdout.flush()


def report(drives, junk, suspects, dup_groups, dup_redundant, dup_wasted):
    log()
    log("{}================ SCAN RESULTS ================{}".format(B, N))
    log("  Drives scanned : {} fixed, {} usb".format(
        len(drives["fixed"]), len(drives["usb"])))
    log("  Junk files     : {}{}{} ({})".format(
        G, len(junk), N, human(sum(_size_of(p) for p in junk))))
    log("  Suspect files  : {}{}{}".format(R, len(suspects), N))
    log("  Duplicate sets : {} ({} redundant files, {})".format(
        len(dup_groups), dup_redundant, human(dup_wasted)))
    for p in suspects[:8]:
        log("    {}!{} {}".format(R, N, p))
    if len(suspects) > 8:
        log("    ... and {} more".format(len(suspects) - 8))
    for size, grp in dup_groups[:5]:
        log("    {}~{} {} x {}: {}".format(Y, N, len(grp), human(size), grp[0]))
    if len(dup_groups) > 5:
        log("    ... and {} more sets".format(len(dup_groups) - 5))
    log()


def _size_of(path):
    try:
        return os.lstat(path).st_size
    except Exception:
        return 0


def approve(junk, suspects, dup_groups):
    """Return plan dict {junk, dups, quarantine}."""
    plan = {"junk": [], "dups": [], "quarantine": []}
    if not junk and not suspects and not dup_groups:
        log("{}  Nothing to clean - system looks tidy!{}".format(G, N))
        return plan
    if AUTO_APPROVE:
        log("{}  Auto-approved safe plan: junk + redundant duplicates."
            "{}".format(Y, N))
        if suspects:
            log("  {}{} suspect file(s) listed above; rerun interactively and "
                "pick option 3 to quarantine them.{}".format(Y, len(suspects), N))
        plan["junk"] = list(junk)
        plan["dups"] = [p for _, grp in dup_groups for p in grp[1:]]
        if FORCE_QUARANTINE:
            plan["quarantine"] = list(suspects)
        return plan
    log("{}Proposed actions:{}".format(B, N))
    log("  [1] Delete {} junk file(s) ({})".format(
        len(junk), human(sum(_size_of(p) for p in junk))))
    log("  [2] Remove redundant duplicates, keep the oldest copy of each set")
    log("  [3] QUARANTINE {} suspect file(s) into {} (reversible)".format(
        len(suspects), SUSPECT_QUARANTINE_DIR))
    log("  [4] Skip everything (scan-only)")
    try:
        choice = input("  Choose (1/2/3/4, combos like 12, Enter=1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "4"
    if choice == "":
        choice = "1"
    if "4" in choice:
        log("  Scan-only: nothing will be changed.")
        return plan
    if "1" in choice:
        plan["junk"] = list(junk)
    if "2" in choice:
        plan["dups"] = [p for _, grp in dup_groups for p in grp[1:]]
    if "3" in choice:
        plan["quarantine"] = list(suspects)
    return plan


def execute_plan(plan):
    freed = 0
    n_junk = n_dup = n_q = 0
    if plan["junk"]:
        log("{}[clean] removing junk files...{}".format(B, N))
        for p in plan["junk"]:
            ok, sz = safe_delete(p)
            if ok:
                n_junk += 1
                freed += sz
        log("  removed {}/{} junk files, {} freed".format(
            n_junk, len(plan["junk"]), human(freed)))
    if plan["dups"]:
        log("{}[clean] removing redundant duplicates...{}".format(B, N))
        d_freed = 0
        for p in plan["dups"]:
            ok, sz = delete_approved(p)
            if ok:
                n_dup += 1
                d_freed += sz
        freed += d_freed
        log("  removed {}/{} duplicates, {} freed".format(
            n_dup, len(plan["dups"]), human(d_freed)))
    if plan["quarantine"]:
        log("{}[clean] quarantining suspects (reversible)...{}".format(B, N))
        for p in plan["quarantine"]:
            if quarantine(p):
                n_q += 1
        log("  quarantined {}/{} files to {}".format(
            n_q, len(plan["quarantine"]), SUSPECT_QUARANTINE_DIR))
        if n_q:
            log("  {}to restore: move files back from {} (.meta files hold "
                "the original paths){}".format(D, SUSPECT_QUARANTINE_DIR, N))
    return freed, n_junk, n_dup, n_q


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
AUTO_APPROVE = False
SCAN_ONLY = False
FORCE_QUARANTINE = False


def main():
    global AUTO_APPROVE, SCAN_ONLY, FORCE_QUARANTINE
    ap = argparse.ArgumentParser(prog="opt.py", add_help=True,
                                 description="auto-detect, clean and optimize")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="auto-approve the safe plan")
    ap.add_argument("--scan-only", action="store_true",
                    help="detect + scan, change nothing")
    ap.add_argument("--no-anim", action="store_true",
                    help="skip the intro animation")
    ap.add_argument("--quarantine", action="store_true",
                    help="with -y: also quarantine suspects")
    # OPT_ROOTS env var overrides drive discovery (testing / containers)
    args = ap.parse_args()
    AUTO_APPROVE = args.yes
    SCAN_ONLY = args.scan_only
    FORCE_QUARANTINE = args.quarantine

    enable_windows_ansi()

    global INFO_LINES
    INFO_LINES = render_info_lines()
    if args.no_anim:
        print_info_block()
    else:
        intro()

    log()
    log("{}opt.py{} {}v{}{} - auto-detect, clean & optimize".format(
        B, N, D, VERSION, N))
    log("{}  warning: heuristic scanner, not a substitute for a real "
        "antivirus{}".format(D, N))

    drives = find_drives()
    # Debug/testing hook: OPT_ROOTS="/path/a:/path/b" overrides drive discovery
    env_roots = [os.path.abspath(p) for p in
                 os.environ.get("OPT_ROOTS", "").split(os.pathsep) if p.strip()]
    if env_roots:
        drives = {"fixed": env_roots, "usb": []}
        log("  {}OPT_ROOTS override active: {}{}".format(
            Y, ", ".join(env_roots), N))
    all_mp = drives["fixed"] + drives["usb"]
    log("  Drives: {}{}{}".format(G, ", ".join(all_mp) or "none found", N))
    if drives["usb"]:
        log("  {}USB detected: {}{}".format(Y, ", ".join(drives["usb"]), N))
    if not all_mp:
        log("{}  No scannable drives found.{}".format(R, N))
        return 1

    junk, suspects = [], []
    files_by_size = {}
    scanned = []

    log()
    log("{}[1/5] Scanning fixed drives...{}".format(B, N))
    for mp in drives["fixed"]:
        if _nested_under(mp, scanned):
            log("  {}»{} {} {} (already covered by another mount){}".format(
                C, N, B, mp, N))
            continue
        log("  {}»{} walking {}{}{} ...".format(C, N, B, mp, N))
        walk_drive(mp, files_by_size, junk, suspects, progress=progress_cb)
        sys.stdout.write("\r\033[K")
        scanned.append(mp)

    if drives["usb"]:
        log()
        log("{}[2/5] Scanning USB drives...{}".format(B, N))
        for mp in drives["usb"]:
            if _nested_under(mp, scanned):
                log("  {}»{} {} {} (already covered){}".format(C, N, B, mp, N))
                continue
            log("  {}»{} walking USB {}{}{} ...".format(C, N, B, mp, N))
            walk_drive(mp, files_by_size, junk, suspects, progress=progress_cb)
            sys.stdout.write("\r\033[K")
            scanned.append(mp)

    log()
    log("{}[3/5] Finding duplicates (size -> partial hash -> full "
        "hash)...{}".format(B, N))
    dup_groups, dup_redundant, dup_wasted = find_duplicates(files_by_size)
    log("  done: {} sets, {} redundant".format(len(dup_groups), dup_redundant))

    report(drives, junk, suspects, dup_groups, dup_redundant, dup_wasted)

    freed = n_junk = n_dup = n_q = 0
    if SCAN_ONLY:
        log("{}[4/5] Scan-only mode: no changes made.{}".format(B, N))
    else:
        log("{}[4/5] Cleaning (with your approval)...{}".format(B, N))
        plan = approve(junk, suspects, dup_groups)
        freed, n_junk, n_dup, n_q = execute_plan(plan)

    log()
    log("{}[5/5] Optimizing...{}".format(B, N))
    n_tmp, b_tmp = clear_temp_dirs()
    log("  temp dirs : removed {} items, {} freed".format(n_tmp, human(b_tmp)))
    n_pkg, b_pkg = clear_pkg_caches()
    log("  pkg caches: removed {} items, {} freed".format(n_pkg, human(b_pkg)))
    if not SCAN_ONLY or True:
        log("  wifi      : " + optimize_wifi())
        log("  os        : " + optimize_os())
    startup = list_startup()
    if startup:
        log("  startup ({} autostart items, review for snappiness): {}".format(
            len(startup), _trunc(", ".join(startup), 70)))

    log()
    log("{}================ SUMMARY ================{}".format(B, N))
    log("  junk removed    : {}".format(n_junk))
    log("  dups removed    : {}".format(n_dup))
    log("  quarantined     : {}".format(n_q))
    log("  total freed     : {}{}".format(G, human(
        freed + b_tmp + b_pkg + dup_wasted * 0), N))
    log("  elapsed         : {:.1f}s".format(time.time() - START_TS))
    log_file = write_session_log()
    log("  log saved to    : {}".format(log_file))
    return 0


def write_session_log():
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = "opt_log_{}.txt".format(stamp)
    path = os.path.join(os.getcwd() if os.access(os.getcwd(), os.W_OK)
                        else os.path.expanduser("~"), base)
    try:
        with open(path, "w") as f:
            f.write("opt.py v{} - {}\n".format(
                VERSION, time.strftime("%Y-%m-%d %H:%M:%S")))
            f.write("\n".join(LOG_LINES) + "\n")
        return path
    except Exception:
        return "<log write failed>"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n{}Interrupted.{}".format(Y, N))
        log("  log saved to: {}".format(write_session_log()))
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        log("{}Fatal: {}{}".format(R, e, N))
        sys.exit(1)
