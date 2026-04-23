#!/usr/bin/env python3
"""
Tool installer for Security AI Assistant.

Checks for required security tools and installs any that are missing.
Supports macOS (brew + go) and Linux (apt + go).

Usage:
    python3 scripts/install_tools.py            # install missing tools
    python3 scripts/install_tools.py --check    # check only, no install
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Tool definitions
# Each entry: (binary_name, install_method, install_arg, description)
#   install_method: "go" | "brew" | "apt" | "pip" | "binary_macos" | "binary_linux"
#   install_arg:    the package/url/module name for that method
# ---------------------------------------------------------------------------

GO_TOOLS: List[Tuple[str, str, str]] = [
    ("gobuster",    "go",   "github.com/OJ/gobuster/v3@latest"),
    ("dalfox",      "go",   "github.com/hahwul/dalfox/v2@latest"),
    ("hakrawler",   "go",   "github.com/hakluke/hakrawler@latest"),
    ("gau",         "go",   "github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls", "go",   "github.com/tomnomnom/waybackurls@latest"),
    ("subfinder",   "go",   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx",       "go",   "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("nuclei",      "go",   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("ffuf",        "go",   "github.com/ffuf/ffuf/v2@latest"),
    ("katana",      "go",   "github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("tlsx",        "go",   "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
]

PIP_TOOLS: List[Tuple[str, str]] = [
    ("sqlmap",   "sqlmap"),
    ("wafw00f",  "wafw00f"),
    ("arjun",    "arjun"),
    ("dirsearch","dirsearch"),
]

BREW_TOOLS: List[Tuple[str, str]] = [
    ("nikto",       "nikto"),
    ("wpscan",      "wpscanteam/tap/wpscan"),
    ("feroxbuster", "epi052/feroxbuster/feroxbuster"),
]

APT_TOOLS: List[Tuple[str, str]] = [
    ("nikto",   "nikto"),
    ("wpscan",  "wpscan"),
    ("sqlmap",  "sqlmap"),
]

# Pre-built binaries for macOS/Linux when brew/apt aren't available
BINARY_TOOLS = {
    "feroxbuster": {
        "darwin_x86_64":  "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-macos-feroxbuster.tar.gz",
        "darwin_arm64":   "https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-macos-feroxbuster.tar.gz",
        "linux_x86_64":   "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz",
        "linux_arm64":    "https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-linux-feroxbuster.tar.gz",
    },
}

# All tools that must be present before a scan runs
REQUIRED_TOOLS = [
    "nuclei", "httpx", "ffuf", "gobuster", "feroxbuster",
    "dirsearch", "hakrawler", "gau", "waybackurls", "dalfox",
    "sqlmap", "wafw00f", "arjun", "wpscan", "nikto", "subfinder",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run(cmd: List[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    kwargs = {"check": check}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(cmd, **kwargs)


def _go_bin_dir() -> Path:
    """Return the GOPATH/bin directory."""
    gopath = os.environ.get("GOPATH")
    if not gopath:
        try:
            result = subprocess.run(
                ["go", "env", "GOPATH"],
                capture_output=True, text=True, check=True
            )
            gopath = result.stdout.strip()
        except Exception:
            gopath = str(Path.home() / "go")
    return Path(gopath) / "bin"


def _ensure_go_bin_in_path() -> None:
    """Add GOPATH/bin to PATH for the current process so installed tools are found."""
    go_bin = str(_go_bin_dir())
    path = os.environ.get("PATH", "")
    if go_bin not in path:
        os.environ["PATH"] = go_bin + os.pathsep + path


def _symlink_to_usr_local_bin(binary: str) -> None:
    """Symlink a binary from GOPATH/bin into /usr/local/bin if writable."""
    src = _go_bin_dir() / binary
    dst = Path("/usr/local/bin") / binary
    if src.exists() and not dst.exists():
        try:
            dst.symlink_to(src)
        except (OSError, PermissionError):
            pass  # Not writable — PATH update is sufficient


def _detect_platform() -> Tuple[str, str]:
    """Return (os_name, arch): os_name is 'darwin' or 'linux', arch is 'x86_64' or 'arm64'."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64"
    return system, arch


def _has_brew() -> bool:
    return bool(_which("brew"))


def _has_apt() -> bool:
    return bool(_which("apt-get"))


def _has_go() -> bool:
    return bool(_which("go"))


def _can_write_usr_local_bin() -> bool:
    return os.access("/usr/local/bin", os.W_OK)


# ---------------------------------------------------------------------------
# Install methods
# ---------------------------------------------------------------------------

def _install_via_go(package: str, binary: str) -> bool:
    if not _has_go():
        print(f"  [SKIP] go not found — cannot install {binary}")
        return False
    try:
        env = dict(os.environ)
        env["GOPATH"] = str(_go_bin_dir().parent)
        _run(["go", "install", package], check=True)
        _symlink_to_usr_local_bin(binary)
        _ensure_go_bin_in_path()
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [FAIL] go install {package}: {e}")
        return False


def _install_via_brew(package: str, binary: str) -> bool:
    if not _has_brew():
        return False
    try:
        _run(["brew", "install", package], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [FAIL] brew install {package}: {e}")
        return False


def _install_via_apt(package: str, binary: str) -> bool:
    if not _has_apt():
        return False
    try:
        _run(["sudo", "apt-get", "install", "-y", package], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [FAIL] apt-get install {package}: {e}")
        return False


def _install_via_pip(module: str, binary: str) -> bool:
    pip = _which("pip3") or _which("pip")
    if not pip:
        print(f"  [SKIP] pip not found — cannot install {binary}")
        return False
    # Try --user install first (no sudo needed)
    for args in [["--user"], []]:
        try:
            _run([pip, "install", module] + args, check=True)
            # Ensure user site-packages bin is in PATH
            user_bin = Path(
                subprocess.check_output(
                    [sys.executable, "-m", "site", "--user-base"],
                    text=True
                ).strip()
            ) / "bin"
            path = os.environ.get("PATH", "")
            if str(user_bin) not in path:
                os.environ["PATH"] = str(user_bin) + os.pathsep + path
            # Symlink if found
            located = _which(binary)
            if located:
                _symlink_to_usr_local_bin(binary)
            return True
        except subprocess.CalledProcessError:
            continue
    print(f"  [FAIL] pip install {module}")
    return False


def _install_binary(binary: str, os_name: str, arch: str) -> bool:
    """Download a pre-built binary directly."""
    urls = BINARY_TOOLS.get(binary, {})
    key = f"{os_name}_{arch}"
    url = urls.get(key)
    if not url:
        print(f"  [SKIP] No pre-built binary for {binary} on {key}")
        return False

    dest = Path("/usr/local/bin") / binary
    if not _can_write_usr_local_bin():
        dest = _go_bin_dir() / binary
        dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "download.tar.gz"
            print(f"  Downloading {url} ...")
            urllib.request.urlretrieve(url, archive)
            _run(["tar", "-xzf", str(archive), "-C", tmp], check=True)
            extracted = next(Path(tmp).rglob(binary), None)
            if not extracted:
                print(f"  [FAIL] {binary} binary not found in archive")
                return False
            shutil.copy2(str(extracted), str(dest))
            dest.chmod(0o755)
        return True
    except Exception as e:
        print(f"  [FAIL] Binary download for {binary}: {e}")
        return False


# ---------------------------------------------------------------------------
# Core check / install logic
# ---------------------------------------------------------------------------

def check_tools(tools: List[str]) -> Tuple[List[str], List[str]]:
    """Return (present, missing) lists."""
    _ensure_go_bin_in_path()
    present = [t for t in tools if _which(t)]
    missing = [t for t in tools if not _which(t)]
    return present, missing


def install_missing(missing: List[str], os_name: str, arch: str) -> Tuple[List[str], List[str]]:
    """
    Try to install each missing tool. Returns (installed, failed).
    """
    installed: List[str] = []
    failed: List[str] = []

    # Build lookup maps
    go_map = {binary: pkg for binary, _, pkg in GO_TOOLS}
    pip_map = {binary: module for binary, module in PIP_TOOLS}
    brew_map = {binary: pkg for binary, pkg in BREW_TOOLS}
    apt_map = {binary: pkg for binary, pkg in APT_TOOLS}

    for binary in missing:
        print(f"\nInstalling: {binary}")
        ok = False

        if binary in BINARY_TOOLS:
            ok = _install_binary(binary, os_name, arch)

        if not ok and binary in go_map:
            ok = _install_via_go(go_map[binary], binary)

        if not ok and os_name == "darwin" and binary in brew_map:
            ok = _install_via_brew(brew_map[binary], binary)

        if not ok and os_name == "linux" and binary in apt_map:
            ok = _install_via_apt(apt_map[binary], binary)

        if not ok and binary in pip_map:
            ok = _install_via_pip(pip_map[binary], binary)

        if ok and _which(binary):
            print(f"  [OK] {binary} installed")
            installed.append(binary)
        else:
            print(f"  [FAIL] {binary} could not be installed automatically")
            failed.append(binary)

    return installed, failed


# ---------------------------------------------------------------------------
# Public entry point (used by security_assistant.py)
# ---------------------------------------------------------------------------

def ensure_tools(tools: Optional[List[str]] = None, auto_install: bool = True) -> bool:
    """
    Check required tools are present. Installs any missing ones if auto_install=True.

    Returns True if all tools are available after the check/install cycle.
    """
    _ensure_go_bin_in_path()
    tools = tools or REQUIRED_TOOLS
    os_name, arch = _detect_platform()

    present, missing = check_tools(tools)

    if not missing:
        return True

    print(f"\n[tool-check] Missing tools ({len(missing)}): {', '.join(missing)}")

    if not auto_install:
        print("[tool-check] Run `python3 scripts/install_tools.py` to install them.")
        return False

    print(f"[tool-check] Auto-installing on {os_name}/{arch}...\n")
    installed, failed = install_missing(missing, os_name, arch)

    if installed:
        print(f"\n[tool-check] Installed: {', '.join(installed)}")
    if failed:
        print(f"[tool-check] Could not install: {', '.join(failed)}")
        print("[tool-check] You may need to install these manually. See README for instructions.")

    # Re-check after install attempts
    _, still_missing = check_tools(tools)
    return len(still_missing) == 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Install required security tools")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check tool availability only, do not install",
    )
    parser.add_argument(
        "--tools",
        default=None,
        help="Comma-separated list of tools to check/install (default: all required)",
    )
    args = parser.parse_args()

    _ensure_go_bin_in_path()
    os_name, arch = _detect_platform()
    tools = [t.strip() for t in args.tools.split(",")] if args.tools else REQUIRED_TOOLS

    print(f"Platform: {os_name}/{arch}")
    print(f"Checking {len(tools)} tools...\n")

    present, missing = check_tools(tools)

    print(f"Present ({len(present)}): {', '.join(present) or 'none'}")
    print(f"Missing ({len(missing)}): {', '.join(missing) or 'none'}")

    if not missing:
        print("\nAll tools are installed.")
        return 0

    if args.check:
        return 1

    installed, failed = install_missing(missing, os_name, arch)

    print("\n--- Summary ---")
    if installed:
        print(f"Installed: {', '.join(installed)}")
    if failed:
        print(f"Failed:    {', '.join(failed)}")
        print("\nFor failed tools, install manually:")
        print("  macOS:  brew install <tool>  OR  go install <pkg>@latest")
        print("  Linux:  sudo apt-get install <tool>  OR  go install <pkg>@latest")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
