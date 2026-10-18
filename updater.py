"""
Kyberon GitHub Auto-Updater (Supply-Chain Hardened)
Queries GitHub Releases API over verified TLS to detect new releases,
enforces strict repository path pinning, full Windows PE header verification,
and mandatory SHA-256 cryptographic digest validation (V-10).
"""

import json
import struct
import hmac
import urllib.request
import urllib.parse
import ssl
import hashlib
import os
import sys
import re
import subprocess
import webbrowser
from typing import Tuple, Optional

CURRENT_VERSION = "4.1.0"
DEFAULT_REPO = "yiitpepek/Kyberon"
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}

_PINNED_RELEASE_DIGESTS: dict = {}


def parse_semver(version_str: str) -> Tuple[int, ...]:
    """Parses a version string into a comparable tuple of integers (e.g. 'v4.1.0' -> (4, 1, 0))."""
    clean = re.sub(r"[^\d.]", "", version_str.lstrip("v"))
    parts = []
    for p in clean.split("."):
        if p.isdigit():
            parts.append(int(p))
    return tuple(parts) if parts else (0,)


def _validate_repo_slug(repo_slug: str) -> str:
    """Prevents URL path injection by validating owner/repo format."""
    slug = repo_slug.strip()
    if not re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", slug):
        return DEFAULT_REPO
    return slug


def _is_trusted_https_url(url: str, expected_repo: str = DEFAULT_REPO) -> bool:
    """
    Enforces HTTPS scheme, strict GitHub domain allowlist, and repository path binding (V-10)
    so arbitrary third-party GitHub repositories cannot serve executables.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https":
            return False
        host = (parsed.hostname or "").lower()
        if host == "github.com":
            safe_slug = _validate_repo_slug(expected_repo).lower()
            return parsed.path.lower().startswith(f"/{safe_slug}/releases/download/")
        return host in ALLOWED_DOWNLOAD_HOSTS or host.endswith(".githubusercontent.com")
    except Exception:
        return False


def _is_valid_windows_pe(binary_data: bytes) -> bool:
    """
    Validates DOS 'MZ' magic, minimum 1 MB size, e_lfanew pointer bounds,
    and the 4-byte 'PE\\x00\\x00' NT header signature (V-10).
    """
    if len(binary_data) < 1024 * 1024 or not binary_data.startswith(b"MZ"):
        return False
    try:
        e_lfanew = struct.unpack("<I", binary_data[0x3C:0x40])[0]
        if e_lfanew < 0x40 or e_lfanew > len(binary_data) - 4:
            return False
        return binary_data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    except Exception:
        return False


def get_pinned_release_sha256(download_url: str) -> Optional[str]:
    """Returns the SHA-256 digest discovered from GitHub Releases metadata for a download URL."""
    return _PINNED_RELEASE_DIGESTS.get(download_url)


def open_github_releases_page(repo_slug: str = DEFAULT_REPO):
    """Opens the GitHub Releases creation/view page in the default web browser."""
    safe_slug = _validate_repo_slug(repo_slug)
    webbrowser.open(f"https://github.com/{safe_slug}/releases")


def check_for_github_update(repo_slug: str = DEFAULT_REPO) -> Tuple[bool, str, str, str]:
    """
    Check GitHub Releases API for a newer application version and extract its SHA-256 digest.
    
    Returns:
        (has_update: bool, latest_version: str, download_url: str, release_notes: str)
    """
    safe_slug = _validate_repo_slug(repo_slug)
    url = f"https://api.github.com/repos/{safe_slug}/releases/latest"
    tls_ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Kyberon-Updater/4.1"}
        )
        with urllib.request.urlopen(req, timeout=4.0, context=tls_ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                tag_name = data.get("tag_name", "").lstrip("v")
                body = data.get("body", "New features and security patches.") or ""

                # Extract SHA-256 from release notes if published (e.g. "SHA256: <64-hex>")
                body_sha_match = re.search(r"\b([a-fA-F0-9]{64})\b", body)
                extracted_sha256 = body_sha_match.group(1).lower() if body_sha_match else None

                download_url = ""
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    candidate_url = asset.get("browser_download_url", "")
                    if name.endswith(".exe") and _is_trusted_https_url(candidate_url, safe_slug):
                        download_url = candidate_url
                        asset_digest = str(asset.get("digest", ""))
                        if asset_digest.lower().startswith("sha256:"):
                            cand_hex = asset_digest.split(":", 1)[1].strip().lower()
                            if re.match(r"^[0-9a-f]{64}$", cand_hex):
                                extracted_sha256 = cand_hex
                        break

                if download_url and extracted_sha256:
                    _PINNED_RELEASE_DIGESTS[download_url] = extracted_sha256

                if tag_name and parse_semver(tag_name) > parse_semver(CURRENT_VERSION) and download_url:
                    return True, tag_name, download_url, body
                return False, tag_name or CURRENT_VERSION, "", f"En güncel sürümü kullanıyorsunuz (v{CURRENT_VERSION})."
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (
                False,
                CURRENT_VERSION,
                "",
                f"GitHub deponuz erişilebilir ancak henüz bir 'Release' (Sürüm) paketi yayınlanmadı.\n\nGitHub üzerinde 'Create a new release' butonuna basarak v{CURRENT_VERSION} etiketini ve derlenen Kyberon.exe dosyasını yayınlayabilirsiniz."
            )
        return False, CURRENT_VERSION, "", f"GitHub bağlantı hatası (HTTP {e.code}): {e.reason}"
    except Exception as e:
        return False, CURRENT_VERSION, "", f"GitHub kontrolü yapılamadı (Çevrimdışı veya ağ hatası): {e}"

    return False, CURRENT_VERSION, "", "Güncelleme bulunamadı."


def apply_executable_update(download_url: str, expected_sha256: Optional[str] = None) -> bool:
    """
    Download the updated Kyberon.exe over verified HTTPS, enforce mandatory 64-hex
    SHA-256 verification and full Windows PE ('MZ' + 'PE\\0\\0') header validation (V-10),
    and atomically replace the running binary.
    Refuses execution (returns False) if expected_sha256 is missing or invalid.
    """
    if not _is_trusted_https_url(download_url):
        return False

    if not expected_sha256:
        expected_sha256 = get_pinned_release_sha256(download_url)

    # V-10: Mandatory SHA-256 verification (never execute unsigned/unverified binaries)
    if not isinstance(expected_sha256, str) or not re.match(r"^[0-9a-fA-F]{64}$", expected_sha256.strip()):
        return False

    expected_clean = expected_sha256.strip().lower()
    tls_ctx = ssl.create_default_context()
    try:
        temp_exe = "Kyberon_update.exe"
        req = urllib.request.Request(download_url, headers={"User-Agent": "Kyberon-Updater/4.1"})
        with urllib.request.urlopen(req, timeout=20.0, context=tls_ctx) as resp:
            if not _is_trusted_https_url(resp.geturl()):
                return False
            binary_data = resp.read()

        # Verify full Windows PE executable structure ('MZ' + e_lfanew -> 'PE\x00\x00')
        if not _is_valid_windows_pe(binary_data):
            return False

        # Constant-time SHA-256 digest verification
        actual_sha256 = hashlib.sha256(binary_data).hexdigest().lower()
        if not hmac.compare_digest(actual_sha256, expected_clean):
            return False

        with open(temp_exe, "wb") as f:
            f.write(binary_data)

        is_frozen = bool(sys.__dict__.get("frozen", False))
        if is_frozen:
            target_exe = sys.executable
        else:
            target_exe = os.path.abspath("Kyberon.exe")

        raw_name = os.path.basename(target_exe)
        safe_target_name = re.sub(r'[^a-zA-Z0-9_.-]', '', raw_name) or "Kyberon.exe"

        batch_script = f"""@echo off
timeout /t 2 /nobreak > nul
move /y "{temp_exe}" "{safe_target_name}"
start "" "{safe_target_name}"
del "%~f0"
"""
        with open("update_installer.bat", "w", encoding="ascii") as f:
            f.write(batch_script)

        subprocess.Popen(["cmd.exe", "/c", "update_installer.bat"], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
    except Exception:
        return False


