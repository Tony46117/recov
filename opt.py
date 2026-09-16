#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "2.0.0"
START_TS = time.time()
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

_TTY = os.environ.get("TERM", "") != "dumb" and sys.stdout.isatty()
if _TTY:
    G, R, Y, CY, MG, B, D, N = (
        "\033[92m", "\033[91m", "\033[93m", "\033[96m",
        "\033[95m", "\033[1m", "\033[2m", "\033[0m",
    )
else:
    G = R = Y = CY = MG = B = D = N = ""

MAX_FILE_SIZE = 512 * 1024 * 1024
DUP_MIN_SIZE = 4 * 1024
HASH_CHUNK = 1024 * 1024
WALK_TIMEOUT = 180
DUP_TIME_BUDGET = 45
PRUNE_EVERY = 65536
TEMP_AGE_SECS = 72 * 3600
QUARANTINE_DIR = str(Path.home() / ".opt_quarantine")

ANSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")
LOG_LINES: list[str] = []


def out(msg: str = "") -> None:
    print(msg, flush=True)
    LOG_LINES.append(ANSI_RE.sub("", msg))


def run(cmd, timeout: int = 90) -> tuple[bool, str]:
    try:
        p = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout,
        )
        return (p.returncode == 0, p.stdout or "")
    except Exception:
        return (False, "")


def human(n) -> str:
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {u}"
        n /= 1024.0
    return f"{n:,.1f} PB"


def trunc(s, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def enable_windows_ansi() -> None:
    if IS_WINDOWS and _TTY:
        try:
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


@dataclass
class ScanResult:
    junk: list[str] = field(default_factory=list)
    suspects: list[str] = field(default_factory=list)
    files_by_size: dict[int, list[str]] = field(default_factory=dict)
    file_count: int = 0


@dataclass
class DupGroup:
    size: int
    paths: list[str]


@dataclass
class Plan:
    junk: list[str] = field(default_factory=list)
    dups: list[str] = field(default_factory=list)
    quarantine: list[str] = field(default_factory=list)


JUNK_EXT = {
    ".tmp", ".temp", ".bak", ".old", ".cache", ".crdownload", ".part",
    ".dmp", ".log", ".etl", ".evtx", ".dump", ".swp", ".swo", ".vmem",
}
JUNK_EXT_TUPLE = tuple(JUNK_EXT)
JUNK_PARENTS = {"tmp", "temp", "cache", "prefetch"}
JUNK_PATH_SEGS = ("/tmp/", "\\temp\\", "/.cache/", "\\cache\\")

SUSPICIOUS_NAMES = re.compile(
    r"^(svchost|csrss|lsass|services|smss|winlogon|explorer|taskhost"
    r"|rundll32|regsvr32|dwm|conhost)\.exe$", re.IGNORECASE)

MALWARE_HINTS = re.compile(
    r"(keygen|crack|patched?\.exe|nuker|trojan|rat\.exe|stealer"
    r"|miner|xmrig|coinhive|kms[-_]?pico|hwid|autokms|removewat|loader\.exe)",
    re.IGNORECASE)

DOUBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|ppt|pptx)\.(exe|scr|pif)$",
    re.IGNORECASE)

SYSTEM_BIN_PREFIXES = ("c:\\windows\\", "c:\\program files",
                       "/system/", "/usr/", "/bin/", "/sbin/")

RISKY_DIR_SEGS = ("/downloads/", "\\downloads\\", "/tmp/", "\\temp\\",
                  "/desktop/", "\\desktop\\")

SKIP_DIR_NAMES = {
    "node_modules", "__pycache__", ".git", ".svn", ".hg", ".tox", ".venv",
    "venv", ".m2", ".gradle", ".cargo", ".rustup", ".nvm",
    "Windows", "Program Files", "Program Files (x86)", "ProgramData",
    "$Recycle.Bin", "System Volume Information", "Windows.old",
    "proc", "sys", "dev", "run", "snap", "boot", "usr", "lib", "lib64",
    "lib32", "bin", "sbin", "etc", "opt", "srv", "var", "Applications",
    "Library", "private",
}

LINUX_IGNORED_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "squashfs", "cgroup",
    "cgroup2", "overlay", "mqueue", "hugetlbfs", "tracefs", "debugfs", "bpf",
    "configfs", "fusectl", "securityfs", "pstore", "efivarfs", "ramfs",
    "autofs", "binfmt_misc", "fuse.gvfsd-fuse", "swap",
}
LINUX_IGNORED_MP = ("/proc", "/sys", "/dev", "/run", "/boot/efi", "/snap",
                    "/var/lib/docker", "/var/lib/containers")

PROTECTED_EXT = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
                 ".txt", ".md", ".py", ".js", ".ts", ".tsx", ".jsx", ".c",
                 ".cpp", ".h", ".hpp", ".java", ".go", ".rs", ".sh", ".sql",
                 ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
                 ".env", ".db", ".sqlite", ".sqlite3", ".wallet", ".key",
                 ".pem", ".csv", ".ods", ".odt")

USER_DIRS = ("documents", "desktop", "pictures", "music", "videos", "photos")

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
INFO_LINES: list[str] = []


def render_info_lines() -> list[str]:
    info = detect_info()
    return [f"{CY}{k:>7}{N}{D}  {B}{v}{N}" for k, v in info.items()]


def intro() -> None:
    if not _TTY or os.environ.get("OPT_NO_ANIM"):
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
                tail = art[n:] if 0 < n < len(art) else ""
                line = f"   {G}{shown}{D}{tail}{N}"
                if i >= rows and r < len(INFO_LINES):
                    line = f"   {art[:5]}{D}.....{N} {INFO_LINES[r]}"
                sys.stdout.write(line + "\033[K\n")
            if i >= rows:
                for r in range(rows, len(INFO_LINES)):
                    sys.stdout.write("   " + " " * LOGO_W + INFO_LINES[r] + "\033[K\n")
            sys.stdout.write("\033[K\n" + f"{D}        opt.py v{VERSION} - scanning system...{N}\033[K\n")
            sys.stdout.flush()
            time.sleep(0.035)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def print_info_block() -> None:
    art_h = len(LOGO)
    for r in range(max(art_h, len(INFO_LINES))):
        art = LOGO[r] if r < art_h else " " * LOGO_W
        info = INFO_LINES[r] if r < len(INFO_LINES) else ""
        out(f"   {G}{art}{N}  {info}")


def detect_info() -> dict[str, str]:
    info: dict[str, str] = {}
    info["OS"] = f"{platform.system()} {platform.release()}"
    info["Host"] = platform.node() or "?"
    info["Kernel"] = trunc(platform.version(), 44)
    info["Uptime"] = uptime()
    info["Shell"] = os.path.basename(
        os.environ.get("SHELL", "cmd" if IS_WINDOWS else "python"))
    info["Admin"] = "yes" if is_admin() else "no"
    info["CPU"] = trunc(cpu(), 54)
    info["GPU"] = trunc(gpu(), 54)
    info["RAM"] = ram()
    info["Disks"] = disks_summary()
    return info


def fmt_uptime(secs) -> str:
    m, s = divmod(int(secs), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


def uptime() -> str:
    try:
        if IS_LINUX:
            with open("/proc/uptime") as f:
                return fmt_uptime(float(f.read().split()[0]))
        if IS_MACOS:
            ok, o = run(["sysctl", "-n", "kern.boottime"])
            m = re.search(r"sec\s*=\s*(\d+)", o)
            if ok and m:
                return fmt_uptime(time.time() - int(m.group(1)))
        if IS_WINDOWS:
            ok, o = run(["net", "stats", "srv"])
            m = re.search(r"Statistics since (.+)", o)
            if ok and m:
                return m.group(1).strip()
    except Exception:
        pass
    return "unknown"


def with_threads(cpu: str) -> str:
    n = os.cpu_count() or 0
    return f"{cpu} ({n} threads)" if n else cpu


def cpu() -> str:
    try:
        if IS_LINUX and os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        return with_threads(line.split(":", 1)[1].strip())
        if IS_WINDOWS:
            ok, o = run(["wmic", "cpu", "get", "name"])
            lines = [l.strip() for l in o.splitlines() if l.strip()]
            if ok and len(lines) > 1:
                return with_threads(lines[1])
        if IS_MACOS:
            ok, o = run(["sysctl", "-n", "machdep.cpu.brand_string"])
            if ok and o.strip():
                return with_threads(o.strip())
        return with_threads(platform.processor() or platform.machine())
    except Exception:
        return "unknown"


def ram() -> str:
    try:
        if IS_LINUX:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        return human(int(line.split()[1]) * 1024)
        if IS_WINDOWS:
            ok, o = run(["wmic", "computersystem", "get", "TotalPhysicalMemory"])
            v = re.findall(r"\d+", o)
            if ok and v:
                return human(int(v[0]))
        if IS_MACOS:
            ok, o = run(["sysctl", "hw.memsize"])
            v = re.findall(r"\d+", o)
            if ok and v:
                return human(int(v[0]))
    except Exception:
        pass
    return "unknown"


def gpu() -> str:
    try:
        if IS_LINUX:
            ok, o = run("lspci 2>/dev/null | grep -iE 'vga|3d' | head -1")
            if ok and o.strip():
                return o.split(":", 2)[-1].strip()
            fb = safe_read("/proc/fb").splitlines()
            if fb and fb[0].strip():
                return "fb: " + fb[0].strip()
            return "integrated / unknown"
        if IS_WINDOWS:
            ok, o = run(["wmic", "path", "win32_VideoController", "get", "name"])
            lines = [l.strip() for l in o.splitlines() if l.strip()]
            if ok and len(lines) > 1:
                return lines[1]
            return "unknown"
        if IS_MACOS:
            ok, o = run(["system_profiler", "SPDisplaysDataType"])
            m = re.search(r"Chipset Model: (.+)", o)
            if ok and m:
                return m.group(1).strip()
            return "unknown"
    except Exception:
        pass
    return "unknown"


def safe_read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def list_mounts() -> list[dict[str, str]]:
    mounts: list[dict[str, str]] = []
    try:
        if IS_WINDOWS:
            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if os.path.exists(root):
                    mounts.append({"device": letter + ":", "mountpoint": root,
                                   "fstype": "", "opts": ""})
            return mounts
        if IS_MACOS:
            seen: set[str] = set()
            for base in ("/", "/Volumes"):
                if not os.path.isdir(base):
                    continue
                for name in sorted(os.listdir(base)):
                    mp = os.path.join(base, name)
                    if os.path.ismount(mp) and mp not in seen:
                        seen.add(mp)
                        mounts.append({"device": name, "mountpoint": mp,
                                       "fstype": "", "opts": ""})
            return mounts
        with open("/proc/self/mounts") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3:
                    mounts.append({"device": p[0], "mountpoint": p[1],
                                   "fstype": p[2], "opts": p[3] if len(p) > 3 else ""})
    except Exception:
        pass
    return mounts


def disks_summary() -> str:
    parts, seen = [], set()
    for p in list_mounts():
        mp, dev = p["mountpoint"], p["device"]
        if mp in seen:
            continue
        seen.add(mp)
        try:
            u = shutil.disk_usage(mp)
            parts.append(f"{dev} {human(u.used)} {human(u.total)}")
        except Exception:
            parts.append(dev)
    return trunc(", ".join(parts) or "none", 56)


def find_drives() -> dict[str, list[str]]:
    fixed: list[str] = []
    usb: list[str] = []
    try:
        if IS_LINUX:
            removable: dict[str, bool] = {}
            for f in Path("/sys/block").glob("*/removable"):
                dev = f.parent.name
                removable[dev] = f.read_text().strip() == "1"
            for p in list_mounts():
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
                (usb if is_rem else fixed).append(mp)
        elif IS_WINDOWS:
            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if not os.path.exists(root):
                    continue
                try:
                    t = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
                except Exception:
                    continue
                if t == 2:
                    usb.append(root)
                elif t == 3:
                    fixed.append(root)
        elif IS_MACOS:
            for p in list_mounts():
                (usb if p["mountpoint"] != "/" else fixed).append(p["mountpoint"])
    except Exception:
        pass
    fixed = [mp for mp in fixed if os.path.isdir(mp)]
    usb = [mp for mp in usb if os.path.isdir(mp)]

    def uniq(seq):
        seen, o = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                o.append(x)
        return o

    return {"fixed": uniq(fixed), "usb": uniq(usb)}


def nested_under(root: str, roots: list[str]) -> bool:
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


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def entropy_sample(path: str) -> float:
    try:
        with open(path, "rb") as f:
            return entropy(f.read(64 * 1024))
    except Exception:
        return 0.0


def classify(path: str, size: int) -> str:
    if size > MAX_FILE_SIZE:
        return ""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    pp = path.lower()
    parent = os.path.basename(os.path.dirname(pp))
    if ext in JUNK_EXT_TUPLE and parent in JUNK_PARENTS:
        return "junk"
    if ext in JUNK_EXT_TUPLE and any(seg in pp for seg in JUNK_PATH_SEGS):
        return "junk"
    if ext in (".crdownload", ".part") and "download" in pp:
        return "junk"
    if ext in (".exe", ".scr", ".pif"):
        if MALWARE_HINTS.search(name):
            return "suspect"
        if DOUBLE_EXT.search(name):
            return "suspect"
        if ext == ".exe" and SUSPICIOUS_NAMES.search(name) \
                and not pp.startswith(SYSTEM_BIN_PREFIXES):
            return "suspect"
        if ext in (".scr", ".pif") and size < 50 * 1024 * 1024:
            return "suspect"
        if ext == ".exe" and any(seg in pp for seg in RISKY_DIR_SEGS) \
                and 100 * 1024 < size < 20 * 1024 * 1024 \
                and entropy_sample(path) > 7.3:
            return "suspect"
    return ""


def walk_root(root: str, result: ScanResult, progress=None) -> int:
    t0 = time.time()
    deadline = t0 + WALK_TIMEOUT
    stack = [root]
    seen_since_prune = 0
    while stack and time.time() < deadline:
        try:
            scanner = os.scandir(stack.pop())
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in SKIP_DIR_NAMES \
                                and not entry.name.startswith("."):
                            stack.append(entry.path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                result.file_count += 1
                seen_since_prune += 1
                if progress and result.file_count % 4096 == 0:
                    progress(result.file_count)
                tag = classify(entry.path, st.st_size)
                if tag == "junk":
                    result.junk.append(entry.path)
                elif tag == "suspect":
                    result.suspects.append(entry.path)
                if DUP_MIN_SIZE <= st.st_size <= MAX_FILE_SIZE:
                    result.files_by_size.setdefault(st.st_size, []).append(entry.path)
                if seen_since_prune >= PRUNE_EVERY:
                    seen_since_prune = 0
                    for sz in [s for s, ps in result.files_by_size.items()
                               if len(ps) < 2]:
                        del result.files_by_size[sz]
    if stack:
        out(f"  {D}   (walk time limit reached on {root}){N}")
    return result.file_count


def partial_hash(path: str) -> str | None:
    try:
        h = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as f:
            h.update(f.read(64 * 1024))
        return h.hexdigest()
    except Exception:
        return None


def full_hash(path: str) -> str | None:
    try:
        h = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def mtime_of(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except Exception:
        return 0.0


def find_duplicates(files_by_size: dict[int, list[str]]) -> list[DupGroup]:
    groups: list[DupGroup] = []
    t0 = time.time()
    sizes = sorted((s for s, ps in files_by_size.items() if len(ps) > 1),
                   reverse=True)
    workers = min(8, (os.cpu_count() or 2) * 2)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for size in sizes:
            if time.time() - t0 > DUP_TIME_BUDGET:
                out(f"  {D}   (duplicate scan hit its time budget){N}")
                break
            paths = files_by_size[size]
            buckets: dict[str, list[str]] = {}
            for p, h in zip(paths, ex.map(partial_hash, paths)):
                if h:
                    buckets.setdefault(h, []).append(p)
            cand = [ps for ps in buckets.values() if len(ps) > 1]
            if not cand:
                continue
            flat = [p for ps in cand for p in ps]
            full: dict[str, list[str]] = {}
            for p, h in zip(flat, ex.map(full_hash, flat)):
                if h:
                    full.setdefault(h, []).append(p)
            for grp in full.values():
                if len(grp) > 1:
                    grp.sort(key=lambda p: (mtime_of(p), p))
                    groups.append(DupGroup(size=size, paths=grp))
    return groups


def looks_important(path: str) -> bool:
    lp = path.lower()
    name = os.path.basename(lp)
    if name.endswith(PROTECTED_EXT):
        return True
    if ".git" in lp or "wallet" in lp or "keystore" in lp:
        return True
    for d in USER_DIRS:
        if f"/{d}/" in lp or f"\\{d}\\" in lp:
            if not name.endswith(JUNK_EXT_TUPLE):
                return True
    return False


def safe_delete(path: str) -> tuple[bool, int]:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            return (False, 0)
        if looks_important(path):
            return (False, 0)
        os.remove(path)
        return (True, st.st_size)
    except Exception:
        return (False, 0)


def delete_approved(path: str) -> tuple[bool, int]:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            return (False, 0)
        os.remove(path)
        return (True, st.st_size)
    except Exception:
        return (False, 0)


def quarantine(path: str) -> bool:
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        dest = os.path.join(
            QUARANTINE_DIR,
            hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:10]
            + "_" + os.path.basename(path))
        if os.path.exists(dest):
            return False
        shutil.move(path, dest)
        with open(dest + ".meta", "w") as f:
            json.dump({"path": path, "time": time.strftime("%Y-%m-%d %H:%M:%S")}, f)
        return True
    except Exception:
        return False


def restore_quarantined() -> int:
    qdir = Path(QUARANTINE_DIR)
    if not qdir.is_dir():
        out(f"  {Y}no quarantine directory found{N}")
        return 0
    restored = 0
    for meta in sorted(qdir.glob("*.meta")):
        payload = str(meta)[:-len(".meta")]
        try:
            raw = meta.read_text(encoding="utf-8", errors="replace").strip()
            try:
                original = json.loads(raw)["path"]
            except Exception:
                original = raw.splitlines()[0] if raw else ""
            if not original or not os.path.exists(payload):
                continue
            parent = os.path.dirname(original)
            if not os.path.isdir(parent):
                out(f"  {Y}skipped {os.path.basename(payload)}: missing dir {parent}{N}")
                continue
            if os.path.exists(original):
                continue
            shutil.move(payload, original)
            meta.unlink()
            restored += 1
        except Exception:
            continue
    out(f"  restored {restored} file(s) from {QUARANTINE_DIR}")
    return restored


def temp_dirs() -> list[str]:
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


def clear_temp_dirs() -> tuple[int, int]:
    n, b = 0, 0
    now = time.time()
    for d in temp_dirs():
        try:
            entries = os.listdir(d)
        except Exception:
            continue
        for entry in entries:
            p = os.path.join(d, entry)
            try:
                st = os.lstat(p)
            except OSError:
                continue
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


def clear_pkg_caches() -> tuple[int, int]:
    n, b = 0, 0
    home = os.path.expanduser("~")
    targets = [os.path.join(home, ".cache", "pip"),
               os.path.join(home, ".npm", "_cacache"),
               os.path.join(home, ".cache", "yarn"),
               os.path.join(home, ".cache", "uv"),
               os.path.join(home, ".cache", "go-build"),
               os.path.join(home, "AppData", "Local", "pip", "cache"),
               os.path.join(home, "AppData", "Local", "npm-cache"),
               os.path.join(home, "Library", "Caches", "pip")]
    for t in targets:
        if not os.path.isdir(t):
            continue
        for dirpath, _dirnames, filenames in os.walk(t, onerror=lambda e: None):
            for fn in filenames:
                ok, sz = safe_delete(os.path.join(dirpath, fn))
                if ok:
                    n += 1
                    b += sz
    return n, b


def optimize_wifi() -> str:
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


def optimize_os() -> str:
    msgs: list[str] = []
    if IS_LINUX:
        if is_admin():
            if shutil.which("journalctl"):
                run("journalctl --vacuum-time=7d", timeout=30)
                msgs.append("journald vacuumed to 7d")
            if shutil.which("fstrim"):
                ok, _ = run("fstrim -av", timeout=120)
                if ok:
                    msgs.append("ssd trim run")
            if os.path.exists("/proc/sys/vm/drop_caches"):
                ok, _ = run("sysctl -w vm.drop_caches=3", timeout=20)
                if ok:
                    msgs.append("page cache dropped")
        run("sync")
        msgs.append("fs sync flushed")
        if not is_admin():
            msgs.append("(run with sudo for journal vacuum + ssd trim + cache drop)")
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


def list_startup() -> list[str]:
    items: list[str] = []
    try:
        if IS_LINUX:
            d = os.path.join(os.path.expanduser("~"), ".config", "autostart")
            if os.path.isdir(d):
                items = [f[:-8] for f in os.listdir(d) if f.endswith(".desktop")]
        elif IS_WINDOWS:
            ok, o = run(["reg", "query",
                         r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])
            if ok:
                items = [l.split("    ")[0].strip() for l in o.splitlines()
                         if "    " in l and "REG_" in l]
        elif IS_MACOS:
            d = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")
            if os.path.isdir(d):
                items = os.listdir(d)
    except Exception:
        pass
    return items


def size_of(path: str) -> int:
    try:
        return os.lstat(path).st_size
    except Exception:
        return 0


def progress_cb(count: int) -> None:
    sys.stdout.write(f"\r  {D}files seen: {count:>8}{N}")
    sys.stdout.flush()


def report(drives, result: ScanResult, dups: list[DupGroup]) -> None:
    redundant = sum(len(g.paths) - 1 for g in dups)
    wasted = sum((len(g.paths) - 1) * g.size for g in dups)
    out()
    out(f"{B}================ SCAN RESULTS ================{N}")
    out(f"  Files seen      : {result.file_count}")
    out(f"  Drives scanned  : {len(drives['fixed'])} fixed, {len(drives['usb'])} usb")
    out(f"  Junk files      : {G}{len(result.junk)}{N} ({human(sum(size_of(p) for p in result.junk))})")
    out(f"  Suspect files   : {R}{len(result.suspects)}{N}")
    out(f"  Duplicate sets  : {len(dups)} ({redundant} redundant files, {human(wasted)})")
    for p in result.suspects[:8]:
        out(f"    {R}!{N} {p}")
    if len(result.suspects) > 8:
        out(f"    ... and {len(result.suspects) - 8} more")
    for g in dups[:5]:
        out(f"    {Y}~{N} {len(g.paths)} x {human(g.size)}: {g.paths[0]}")
    if len(dups) > 5:
        out(f"    ... and {len(dups) - 5} more sets")
    out()


def approve(result: ScanResult, dups: list[DupGroup], auto: bool,
            force_quarantine: bool) -> Plan:
    plan = Plan()
    if not result.junk and not result.suspects and not dups:
        out(f"{G}  Nothing to clean - system looks tidy!{N}")
        return plan
    if auto:
        out(f"{Y}  Auto-approved safe plan: junk + redundant duplicates.{N}")
        if result.suspects and not force_quarantine:
            out(f"  {Y}{len(result.suspects)} suspect file(s) listed above; rerun interactively"
                f" and pick option 3, or use --quarantine, to isolate them.{N}")
        plan.junk = list(result.junk)
        plan.dups = [p for g in dups for p in g.paths[1:]]
        if force_quarantine:
            plan.quarantine = list(result.suspects)
        return plan
    out(f"{B}Proposed actions:{N}")
    out(f"  [1] Delete {len(result.junk)} junk file(s) ({human(sum(size_of(p) for p in result.junk))})")
    out("  [2] Remove redundant duplicates, keep the oldest copy of each set")
    out(f"  [3] QUARANTINE {len(result.suspects)} suspect file(s) into {QUARANTINE_DIR} (reversible)")
    out("  [4] Skip everything (scan-only)")
    try:
        choice = input("  Choose (1/2/3/4, combos like 12, Enter=1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "4"
    if choice == "":
        choice = "1"
    if "4" in choice:
        out("  Scan-only: nothing will be changed.")
        return plan
    if "1" in choice:
        plan.junk = list(result.junk)
    if "2" in choice:
        plan.dups = [p for g in dups for p in g.paths[1:]]
    if "3" in choice:
        plan.quarantine = list(result.suspects)
    return plan


def execute_plan(plan: Plan) -> tuple[int, int, int, int]:
    freed = 0
    n_junk = n_dup = n_q = 0
    if plan.junk:
        out(f"{B}[clean] removing junk files...{N}")
        for p in plan.junk:
            ok, sz = safe_delete(p)
            if ok:
                n_junk += 1
                freed += sz
        out(f"  removed {n_junk}/{len(plan.junk)} junk files, {human(freed)} freed")
    if plan.dups:
        out(f"{B}[clean] removing redundant duplicates...{N}")
        d_freed = 0
        for p in plan.dups:
            ok, sz = delete_approved(p)
            if ok:
                n_dup += 1
                d_freed += sz
        freed += d_freed
        out(f"  removed {n_dup}/{len(plan.dups)} duplicates, {human(d_freed)} freed")
    if plan.quarantine:
        out(f"{B}[clean] quarantining suspects (reversible)...{N}")
        for p in plan.quarantine:
            if quarantine(p):
                n_q += 1
        out(f"  quarantined {n_q}/{len(plan.quarantine)} files to {QUARANTINE_DIR}")
        if n_q:
            out(f"  {D}to restore: python3 opt.py --restore{N}")
    return freed, n_junk, n_dup, n_q


def write_session_log() -> str:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = f"opt_log_{stamp}.txt"
    path = os.path.join(os.getcwd() if os.access(os.getcwd(), os.W_OK)
                        else os.path.expanduser("~"), base)
    try:
        with open(path, "w") as f:
            f.write(f"opt.py v{VERSION} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n".join(LOG_LINES) + "\n")
        return path
    except Exception:
        return "<log write failed>"


def main() -> int:
    global INFO_LINES
    ap = argparse.ArgumentParser(prog="opt.py",
                                 description="auto-detect, clean and optimize")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="auto-approve the safe plan")
    ap.add_argument("--scan-only", action="store_true",
                    help="detect + scan, change nothing")
    ap.add_argument("--no-anim", action="store_true",
                    help="skip the intro animation")
    ap.add_argument("--quarantine", action="store_true",
                    help="with -y: also quarantine suspects")
    ap.add_argument("--restore", action="store_true",
                    help="restore files from quarantine and exit")
    ap.add_argument("--roots", nargs="*", default=None,
                    help="override drive discovery with these paths")
    args = ap.parse_args()

    enable_windows_ansi()

    if args.restore:
        out(f"{B}opt.py{N} {D}v{VERSION}{N} - quarantine restore")
        restore_quarantined()
        return 0

    INFO_LINES = render_info_lines()
    if args.no_anim:
        print_info_block()
    else:
        intro()

    out()
    out(f"{B}opt.py{N} {D}v{VERSION}{N} - auto-detect, clean & optimize")
    out(f"{D}  warning: heuristic scanner, not a substitute for a real antivirus{N}")

    drives = find_drives()
    if args.roots:
        drives = {"fixed": [os.path.abspath(p) for p in args.roots], "usb": []}
    else:
        env_roots = [os.path.abspath(p) for p in
                     os.environ.get("OPT_ROOTS", "").split(os.pathsep) if p.strip()]
        if env_roots:
            drives = {"fixed": env_roots, "usb": []}
            out(f"  {Y}OPT_ROOTS override active: {', '.join(env_roots)}{N}")

    all_mp = drives["fixed"] + drives["usb"]
    out(f"  Drives: {G}{', '.join(all_mp) or 'none found'}{N}")
    if drives["usb"]:
        out(f"  {Y}USB detected: {', '.join(drives['usb'])}{N}")
    if not all_mp:
        out(f"{R}  No scannable drives found.{N}")
        return 1

    result = ScanResult()
    scanned: list[str] = []

    out()
    out(f"{B}[1/5] Scanning fixed drives...{N}")
    for mp in drives["fixed"]:
        if nested_under(mp, scanned):
            out(f"  {CY}»{N} {B}{mp}{N} (already covered by another mount)")
            continue
        out(f"  {CY}»{N} walking {B}{mp}{N} ...")
        walk_root(mp, result, progress=progress_cb)
        sys.stdout.write("\r\033[K")
        scanned.append(mp)

    if drives["usb"]:
        out()
        out(f"{B}[2/5] Scanning USB drives...{N}")
        for mp in drives["usb"]:
            if nested_under(mp, scanned):
                out(f"  {CY}»{N} {B}{mp}{N} (already covered)")
                continue
            out(f"  {CY}»{N} walking USB {B}{mp}{N} ...")
            walk_root(mp, result, progress=progress_cb)
            sys.stdout.write("\r\033[K")
            scanned.append(mp)
            autorun = os.path.join(mp, "autorun.inf")
            if os.path.isfile(autorun) and os.path.getsize(autorun) > 0:
                result.suspects.append(autorun)

    out()
    out(f"{B}[3/5] Finding duplicates (size -> partial hash -> full hash, parallel)...{N}")
    dups = find_duplicates(result.files_by_size)
    out(f"  done: {len(dups)} sets, {sum(len(g.paths) - 1 for g in dups)} redundant")

    report(drives, result, dups)

    freed = n_junk = n_dup = n_q = 0
    if args.scan_only:
        out(f"{B}[4/5] Scan-only mode: no changes made.{N}")
    else:
        out(f"{B}[4/5] Cleaning (with your approval)...{N}")
        plan = approve(result, dups, auto=args.yes,
                       force_quarantine=args.quarantine)
        freed, n_junk, n_dup, n_q = execute_plan(plan)
    if args.scan_only:
        out()
        out(f"{B}[5/5] Scan-only mode: optimization steps skipped.{N}")
        out()
        out(f"{B}================ SUMMARY ================{N}")
        out(f"  junk found      : {len(result.junk)}")
        out(f"  suspects found  : {len(result.suspects)}")
        out(f"  redundant dups  : {sum(len(g.paths) - 1 for g in dups)} ({human(sum((len(g.paths) - 1) * g.size for g in dups))})")
        out(f"  elapsed         : {time.time() - START_TS:.1f}s")
        log_file = write_session_log()
        out(f"  log saved to    : {log_file}")
        return 0

    out()
    out(f"{B}[5/5] Optimizing...{N}")
    n_tmp, b_tmp = clear_temp_dirs()
    out(f"  temp dirs : removed {n_tmp} items, {human(b_tmp)} freed")
    n_pkg, b_pkg = clear_pkg_caches()
    out(f"  pkg caches: removed {n_pkg} items, {human(b_pkg)} freed")
    out("  wifi      : " + optimize_wifi())
    out("  os        : " + optimize_os())
    startup = list_startup()
    if startup:
        out(f"  startup ({len(startup)} autostart items, review for snappiness): "
            f"{trunc(', '.join(startup), 70)}")

    out()
    out(f"{B}================ SUMMARY ================{N}")
    out(f"  junk removed    : {n_junk}")
    out(f"  dups removed    : {n_dup}")
    out(f"  quarantined     : {n_q}")
    out(f"  total freed     : {G}{human(freed + b_tmp + b_pkg)}{N}")
    out(f"  elapsed         : {time.time() - START_TS:.1f}s")
    log_file = write_session_log()
    out(f"  log saved to    : {log_file}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out(f"\n{Y}Interrupted.{N}")
        out(f"  log saved to: {write_session_log()}")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        out(f"{R}Fatal: {e}{N}")
        sys.exit(1)
