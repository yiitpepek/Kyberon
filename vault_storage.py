"""
Vault Storage Manager (Multi-User Profiles, Dual-Slot Deniable Encryption & Hardware Binding)
Features:
- Multi-User Profile Management (Independent vault and credentials per user/machine)
- Hardware-Bound Profiles (Multi-source machine fingerprint + local installation token)
- Indistinguishable Dual-Slot Duress Vault (Both primary and decoy capsules reside in a single .mvat file)
- Constant-Work Authentication (Constant KDF evaluation count across Master, Duress, and Invalid passwords)
- Fail-Closed HMAC Security State & Anti-Brute-Force Rate Limiting
"""

import os
import json
import secrets
import string
import uuid
import time
import hmac
import platform
import hashlib
import base64
import unicodedata
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from military_vault import MilitaryVault, VaultSecurityError

PROFILES_DIR = "profiles"
DEFAULT_VAULT_FILE = "vault_data.mvat"
DEFAULT_DECOY_FILE = "vault_decoy.mvat"
SECURITY_STATE_FILE = os.path.join(PROFILES_DIR, ".security_state.json")

# Per-profile in-memory counters (V-03: strict profile isolation, no cross-profile leakage)
_profile_failed_attempts: Dict[str, int] = {}
_profile_last_failed_time: Dict[str, float] = {}
_SEALED_STATE_DIGESTS: Dict[str, str] = {}

# Legacy module attribute kept only for backward inspection; never shared across profiles
_failed_attempts = 0
_last_failed_time = 0.0


def _get_user_secret_dir() -> str:
    """Returns a user-scoped directory outside the workspace for storing local cryptographic secrets."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    secret_dir = os.path.join(base, ".kyberon_secrets")
    legacy_dir = os.path.join(base, ".aegisvault_secrets")
    try:
        if os.path.exists(legacy_dir) and not os.path.exists(secret_dir):
            try:
                os.rename(legacy_dir, secret_dir)
            except Exception:
                secret_dir = legacy_dir
        os.makedirs(secret_dir, exist_ok=True)
        return secret_dir
    except Exception:
        return os.path.expanduser("~")


def _get_or_create_secret_file(filename: str) -> bytes:
    """Reads or initializes a 256-bit CSPRNG secret file in the user's protected profile directory."""
    path = os.path.join(_get_user_secret_dir(), filename)
    try:
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read(64)
            if len(raw) >= 32:
                return raw[:32]
        secret_bytes = os.urandom(32)
        with open(path, "wb") as f:
            f.write(secret_bytes)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return secret_bytes
    except Exception:
        # Fallback per-process ephemeral key if filesystem is completely read-only
        return hashlib.sha256(f"AEGIS-FALLBACK-{os.getpid()}-{uuid.getnode()}".encode("utf-8")).digest()


def _read_os_machine_id() -> str:
    """Attempts to read a non-trivial OS-level machine UUID/GUID (V-13)."""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                if val:
                    return str(val).strip()
        except Exception:
            pass
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                pass
    return ""


def get_hardware_fingerprint() -> str:
    """
    Generates a hardened hardware-bound SHA-256 fingerprint combining OS machine GUID,
    MAC hardware node, CPU architecture, and a persistent 256-bit local installation secret (V-13).
    """
    install_secret = _get_or_create_secret_file(".machine_install_key").hex()
    os_guid = _read_os_machine_id()
    mac_node = str(uuid.getnode())
    raw = f"{platform.node()}|{platform.machine()}|{platform.processor()}|{mac_node}|{os_guid}|{install_secret}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _get_state_hmac_key() -> bytes:
    """
    Returns a 256-bit secret HMAC key for authenticating .security_state.json (V-02).
    Uses a CSPRNG secret key stored outside the workspace so attackers knowing
    get_hardware_fingerprint() cannot forge .security_state.json HMAC tags.
    """
    secret_seed = _get_or_create_secret_file(".state_hmac_key")
    hw_fp = get_hardware_fingerprint().encode("utf-8")
    return hmac.new(secret_seed, b"AEGIS-STATE-HMAC-v2:" + hw_fp, hashlib.sha256).digest()


def generate_keyfile(filepath: str) -> str:
    """
    Generates a high-entropy 512-bit (64-byte) CSPRNG 2FA cryptographic keyfile (.akey)
    for USB token / hardware two-factor authentication.
    Returns the 32-char SHA3-256 fingerprint of the keyfile.
    """
    raw_entropy = os.urandom(64)
    token_obj = {
        "header": "AEGIS-KEYFILE-2FA-v1",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "entropy_b64": base64.b64encode(raw_entropy).decode("ascii"),
        "checksum": hashlib.sha3_256(raw_entropy).hexdigest()
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(token_obj, f, indent=2)
    return compute_keyfile_digest(filepath)


def compute_keyfile_digest(filepath: str) -> str:
    """Computes a deterministic 256-bit SHA3-256 digest (32-hex prefix) of any 2FA keyfile."""
    if not filepath or not os.path.exists(filepath):
        raise VaultSecurityError("Selected 2FA Keyfile does not exist or USB drive is unplugged.")
    with open(filepath, "rb") as f:
        raw_bytes = f.read(50 * 1024 * 1024)  # Cap at 50 MB
    if not raw_bytes:
        raise VaultSecurityError("Selected 2FA Keyfile is empty.")
    return hashlib.sha3_256(raw_bytes).hexdigest()[:32]


def _has_any_vault_files() -> bool:
    """Returns True if any .mvat file currently exists in PROFILES_DIR or root."""
    if os.path.exists(DEFAULT_VAULT_FILE):
        return True
    if os.path.exists(PROFILES_DIR):
        for fname in os.listdir(PROFILES_DIR):
            if fname.endswith(".mvat"):
                return True
    return False


def _load_security_state() -> Dict[str, Any]:
    """
    Loads the HMAC-authenticated persistent security state (Dead-Man's Switch & Brute-Force counters).
    Enforces FAIL-CLOSED verification (V-02): any HMAC mismatch, malformed JSON, or unauthorized
    state file deletion raises VaultSecurityError immediately instead of accepting tampered values.
    """
    ensure_profiles_dir()
    abs_state_path = os.path.abspath(SECURITY_STATE_FILE)

    if not os.path.exists(SECURITY_STATE_FILE):
        if abs_state_path in _SEALED_STATE_DIGESTS and _has_any_vault_files():
            try:
                from military_audit import CryptographicAuditTrail
                CryptographicAuditTrail.record_event(
                    "SECURITY_STATE_TAMPER",
                    "SYSTEM",
                    "Unauthorized deletion of .security_state.json detected.",
                    "CRITICAL"
                )
            except Exception:
                pass
            raise VaultSecurityError(
                "CRITICAL SECURITY VIOLATION: .security_state.json is missing or was illegally deleted!"
            )
        return {"profiles": {}}

    try:
        with open(SECURITY_STATE_FILE, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
    except Exception as e:
        try:
            from military_audit import CryptographicAuditTrail
            CryptographicAuditTrail.record_event(
                "SECURITY_STATE_TAMPER",
                "SYSTEM",
                "Corrupted or malformed .security_state.json detected.",
                "CRITICAL"
            )
        except Exception:
            pass
        raise VaultSecurityError(
            "CRITICAL SECURITY VIOLATION: .security_state.json is corrupted or tampered!"
        ) from e

    if not isinstance(wrapper, dict) or not isinstance(wrapper.get("state"), dict):
        raise VaultSecurityError("CRITICAL SECURITY VIOLATION: Invalid .security_state.json structure!")

    state = wrapper["state"]
    tag = str(wrapper.get("hmac", ""))
    secret_key = _get_state_hmac_key()
    expected = hmac.new(secret_key, json.dumps(state, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(tag, expected):
        try:
            from military_audit import CryptographicAuditTrail
            CryptographicAuditTrail.record_event(
                "SECURITY_STATE_TAMPER",
                "SYSTEM",
                "HMAC mismatch on .security_state.json detected.",
                "CRITICAL"
            )
        except Exception:
            pass
        raise VaultSecurityError(
            "CRITICAL SECURITY VIOLATION: HMAC mismatch on .security_state.json! State tampering blocked."
        )

    _SEALED_STATE_DIGESTS[abs_state_path] = tag
    return state


def _save_security_state(state: Dict[str, Any]) -> None:
    """Saves the persistent security state sealed with a secret HMAC-SHA256 tag (V-02)."""
    ensure_profiles_dir()
    secret_key = _get_state_hmac_key()
    tag = hmac.new(secret_key, json.dumps(state, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
    wrapper = {"state": state, "hmac": tag}
    tmp = SECURITY_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2)
    try:
        os.replace(tmp, SECURITY_STATE_FILE)
    except OSError:
        if os.path.exists(SECURITY_STATE_FILE):
            os.remove(SECURITY_STATE_FILE)
        os.rename(tmp, SECURITY_STATE_FILE)
    _SEALED_STATE_DIGESTS[os.path.abspath(SECURITY_STATE_FILE)] = tag


def get_profile_security_policy(profile_name: str) -> Dict[str, Any]:
    """Returns the Dead-Man's Switch & Brute-Force policy for a given profile."""
    state = _load_security_state()
    prof = state.setdefault("profiles", {}).get(profile_name, {})
    return {
        "dms_days": int(prof.get("dms_days", 0)),
        "max_failed_wipe": int(prof.get("max_failed_wipe", 0)),
        "failed_attempts": int(prof.get("failed_attempts", 0)),
        "last_checkin_epoch": float(prof.get("last_checkin_epoch", time.time())),
    }


def configure_profile_security_policy(profile_name: str, dms_days: int, max_failed_wipe: int) -> None:
    """Updates Dead-Man's Switch (inactivity days) and Scorched-Earth Brute-Force Wipe threshold."""
    state = _load_security_state()
    prof = state.setdefault("profiles", {}).setdefault(profile_name, {})
    prof["dms_days"] = max(0, int(dms_days))
    prof["max_failed_wipe"] = max(0, int(max_failed_wipe))
    prof["last_checkin_epoch"] = time.time()
    _save_security_state(state)
    try:
        from military_audit import CryptographicAuditTrail
        CryptographicAuditTrail.record_event(
            "SECURITY_POLICY_UPDATE",
            profile_name,
            f"Dead-Man's Switch={dms_days}d | Scorched-Earth Brute-Force Limit={max_failed_wipe}",
            "INFO"
        )
    except Exception:
        pass


def check_dead_mans_switch(profile_name: str) -> Tuple[bool, str]:
    """
    Evaluates whether the Dead-Man's Switch inactivity timer has expired for a profile.
    Enforces FAIL-CLOSED evaluation (V-09): if dms_days > 0 and last_checkin_epoch is <= 0,
    missing, or tampered into the future, the switch triggers immediately instead of being skipped.
    Returns: (triggered: bool, message: str)
    """
    state = _load_security_state()
    prof = state.get("profiles", {}).get(profile_name, {})
    dms_days = int(prof.get("dms_days", 0))
    last_checkin_raw = prof.get("last_checkin_epoch", 0)
    try:
        last_checkin = float(last_checkin_raw)
    except (TypeError, ValueError):
        last_checkin = 0.0

    if dms_days > 0:
        now = time.time()
        # V-09: Fail-closed if last_checkin <= 0 or set in the future (> 5 min clock skew)
        if last_checkin <= 0.0 or last_checkin > (now + 300.0):
            expired = True
        else:
            elapsed_days = (now - last_checkin) / 86400.0
            expired = elapsed_days >= dms_days

        if expired:
            v_file, _ = get_profile_files(profile_name)
            if os.path.exists(v_file):
                from military_audit import emergency_zeroize_vault, CryptographicAuditTrail
                emergency_zeroize_vault(profile_name)
                CryptographicAuditTrail.record_event(
                    "DEAD_MANS_SWITCH_TRIGGERED",
                    profile_name,
                    f"Inactivity threshold ({dms_days} days) exceeded or invalid check-in epoch. Vault automatically zeroized.",
                    "CRITICAL"
                )
                prof["dms_days"] = 0
                _save_security_state(state)
                return True, f"DEAD-MAN'S SWITCH TRIGGERED: Profile '{profile_name}' exceeded {dms_days} days of inactivity and was cryptographically shredded (DoD 5220.22-M)."
    return False, ""


def ensure_profiles_dir():
    """Ensures the profiles storage directory exists."""
    if not os.path.exists(PROFILES_DIR):
        os.makedirs(PROFILES_DIR, exist_ok=True)


def list_profiles() -> List[str]:
    """Lists all registered vault profile names."""
    ensure_profiles_dir()
    profiles = []
    
    # Check legacy root vault
    if os.path.exists(DEFAULT_VAULT_FILE):
        profiles.append("Varsayılan")

    for f in os.listdir(PROFILES_DIR):
        if f.endswith(".mvat") and not f.endswith("_decoy.mvat"):
            name = f[:-5]
            if name not in profiles:
                profiles.append(name)

    return profiles if profiles else ["Varsayılan"]


def _validate_and_normalize_profile_name(profile_name: str) -> str:
    """
    Validates profile_name against path traversal and homoglyph/punctuation collisions (V-08, V-19).
    Returns a canonical, collision-free filename stem inside PROFILES_DIR.
    """
    if not isinstance(profile_name, str) or not profile_name.strip():
        raise VaultSecurityError("Profile name must be a non-empty string.")
    if ".." in profile_name or "/" in profile_name or "\\" in profile_name or "\x00" in profile_name:
        raise VaultSecurityError(f"Unsafe profile name rejected (path traversal attempt): {profile_name!r}")

    normalized = unicodedata.normalize("NFKC", profile_name.strip())
    if normalized in ("Varsayılan", "Default"):
        return "Varsayılan"

    # Strict ASCII alphanumeric + hyphen/underscore check
    clean_ascii = "".join(c for c in normalized if c.isascii() and (c.isalnum() or c in ("-", "_"))).strip()
    if not clean_ascii:
        clean_ascii = "Profile"

    # V-19: If any character was stripped or non-ASCII (e.g. 'a.b' vs 'ab', or Cyrillic homoglyphs),
    # append a deterministic 8-hex SHA-256 tag of the original UTF-8 name so distinct names NEVER collide.
    if clean_ascii != profile_name:
        collision_tag = hashlib.sha256(profile_name.encode("utf-8")).hexdigest()[:8]
        return f"{clean_ascii}_{collision_tag}"

    return clean_ascii


def get_profile_files(profile_name: str) -> Tuple[str, str]:
    """
    Returns filesystem paths for a profile's vault container (V-14, V-19).
    Note: Since v4.1.0, both primary and decoy capsules are stored inside the single `<name>.mvat`
    file to eliminate `_decoy.mvat` filesystem metadata leakage (V-14). The second path in the tuple
    is returned only for legacy migration/cleanup compatibility.
    """
    ensure_profiles_dir()
    safe_name = _validate_and_normalize_profile_name(profile_name)
    if safe_name == "Varsayılan":
        if os.path.exists(DEFAULT_VAULT_FILE):
            return DEFAULT_VAULT_FILE, DEFAULT_DECOY_FILE
        return os.path.join(PROFILES_DIR, "Varsayılan.mvat"), os.path.join(PROFILES_DIR, "Varsayılan_decoy.mvat")

    v_path = os.path.join(PROFILES_DIR, f"{safe_name}.mvat")
    d_path = os.path.join(PROFILES_DIR, f"{safe_name}_decoy.mvat")
    return v_path, d_path


def profile_exists(profile_name: str) -> bool:
    """Checks whether a given profile vault file exists on disk."""
    v_file, _ = get_profile_files(profile_name)
    return os.path.exists(v_file)


def generate_secure_password(length: int = 32, use_symbols: bool = True) -> str:
    """Generates a high-entropy CSPRNG password."""
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()-_=+"))

    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))

    # Cryptographically shuffle so the first 4 character classes are not in predictable positions
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]

    return "".join(password)


def _build_default_decoy_payload(profile_name: str, lang: str, bind_to_hardware: bool, has_keyfile: bool) -> Dict[str, Any]:
    """Constructs a realistic decoy vault dictionary for Slot 1."""
    return {
        "version": 4,
        "profile_name": profile_name,
        "is_decoy": True,
        "hardware_bound": bind_to_hardware,
        "keyfile_bound": has_keyfile,
        "settings": {"language": lang},
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "items": [
            {
                "id": str(uuid.uuid4()),
                "title": "Old Email Account",
                "category": "User Password",
                "secret": "MyNormalPass2022!",
                "notes": "Low priority personal email",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ],
        "portfolio": []
    }


def init_vault(
    master_password: str,
    duress_password: Optional[str] = None,
    lang: str = "tr",
    profile_name: str = "Varsayılan",
    bind_to_hardware: bool = False,
    keyfile_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Initializes and encrypts a new user vault with optional Hardware Binding and 2FA Keyfile.
    V-14 Fix: Always writes a unified 2-slot `.mvat` container (Slot 0 = Primary, Slot 1 = Decoy or
    indistinguishable CSPRNG dummy capsule) and NEVER creates a separate `*_decoy.mvat` file on disk.
    """
    v_file, d_file = get_profile_files(profile_name)

    if duress_password and duress_password.strip() == master_password:
        raise VaultSecurityError("Duress password must be distinct from the Master password.")

    hw_id = get_hardware_fingerprint() if bind_to_hardware else None
    kf_id = compute_keyfile_digest(keyfile_path) if (keyfile_path and keyfile_path.strip()) else None

    effective_password = master_password
    if hw_id:
        effective_password += f"|HW:{hw_id}"
    if kf_id:
        effective_password += f"|KF:{kf_id}"

    vault_data = {
        "version": 4,
        "profile_name": profile_name,
        "is_decoy": False,
        "hardware_bound": bind_to_hardware,
        "hardware_id": hw_id,
        "keyfile_bound": bool(kf_id),
        "settings": {"language": lang},
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "items": [],
        "portfolio": [
            {
                "id": str(uuid.uuid4()),
                "coin": "BTC",
                "label": "Cold Storage 1 (Ledger)",
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "amount": 0.45,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ]
    }

    # Prepare Slot 1 (Decoy capsule or indistinguishable CSPRNG chaff capsule)
    decoy_data = _build_default_decoy_payload(profile_name, lang, bind_to_hardware, bool(kf_id))
    if duress_password and duress_password.strip():
        eff_duress = duress_password.strip()
        if hw_id:
            eff_duress += f"|HW:{hw_id}"
        if kf_id:
            eff_duress += f"|KF:{kf_id}"
    else:
        # Indistinguishable chaff key so every .mvat file has two identical-format slots on disk
        eff_duress = secrets.token_hex(32)

    slot0_armored = MilitaryVault.encrypt(json.dumps(vault_data, indent=2, ensure_ascii=False), effective_password)
    slot1_armored = MilitaryVault.encrypt(json.dumps(decoy_data, indent=2, ensure_ascii=False), eff_duress)

    temp_file = v_file + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(f"{slot0_armored}\n{slot1_armored}\n")
    try:
        os.replace(temp_file, v_file)
    except OSError:
        if os.path.exists(v_file):
            os.remove(v_file)
        os.rename(temp_file, v_file)

    # Remove any legacy _decoy.mvat file if present
    if os.path.exists(d_file):
        try:
            os.remove(d_file)
        except OSError:
            pass

    # Record initial Dead-Man's Switch check-in & reset per-profile failed attempts
    try:
        state = _load_security_state()
    except VaultSecurityError:
        state = {"profiles": {}}
    prof_state = state.setdefault("profiles", {}).setdefault(profile_name, {})
    prof_state["last_checkin_epoch"] = time.time()
    prof_state["failed_attempts"] = 0
    _profile_failed_attempts[profile_name] = 0
    _profile_last_failed_time[profile_name] = 0.0
    _save_security_state(state)

    return vault_data


def save_vault(password: str, vault_data: Dict[str, Any], target_file: Optional[str] = None, is_decoy: bool = False) -> None:
    """
    Encrypts and safely writes vault data to the unified dual-slot `.mvat` container using atomic rename.
    Preserves the sibling slot (Slot 1 when saving primary; Slot 0 when saving decoy) so no separate
    `*_decoy.mvat` file is ever written to disk (V-14).
    """
    vault_data["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_json = json.dumps(vault_data, indent=2, ensure_ascii=False)
    armored = MilitaryVault.encrypt(raw_json, password)

    prof_name = vault_data.get("profile_name", "Varsayılan")
    v_file, d_file = get_profile_files(prof_name)

    if not target_file or target_file == d_file:
        if target_file == d_file:
            is_decoy = True
        target_file = v_file

    slot0_existing = None
    slot1_existing = None
    if os.path.exists(target_file):
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
            if len(lines) >= 1:
                slot0_existing = lines[0]
            if len(lines) >= 2:
                slot1_existing = lines[1]
        except Exception:
            pass

    if is_decoy:
        if not slot0_existing:
            chaff = _build_default_decoy_payload(prof_name, "tr", False, False)
            slot0_existing = MilitaryVault.encrypt(json.dumps(chaff), secrets.token_hex(32))
        final_content = f"{slot0_existing}\n{armored}\n"
    else:
        if not slot1_existing:
            chaff = _build_default_decoy_payload(prof_name, "tr", False, False)
            slot1_existing = MilitaryVault.encrypt(json.dumps(chaff), secrets.token_hex(32))
        final_content = f"{armored}\n{slot1_existing}\n"

    temp_file = target_file + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(final_content)

    try:
        os.replace(temp_file, target_file)
    except OSError:
        if os.path.exists(target_file):
            os.remove(target_file)
        os.rename(temp_file, target_file)


def unlock_vault(
    password: str,
    profile_name: str = "Varsayılan",
    keyfile_path: Optional[str] = None
) -> Tuple[Dict[str, Any], bool, str]:
    """
    Unlocks and decrypts the requested profile.
    Enforces:
    - Fail-closed Dead-Man's Switch & HMAC-verified security state (V-02, V-09)
    - Strict per-profile brute-force counters (V-03)
    - Constant-work evaluation across both primary and decoy slots to eliminate timing side-channels (V-07, V-14)
    Returns: (vault_data, is_decoy, effective_password)
    """
    global _failed_attempts, _last_failed_time

    # 0. Check Dead-Man's Switch Inactivity Timer prior to unlock
    dms_triggered, dms_msg = check_dead_mans_switch(profile_name)
    if dms_triggered:
        raise VaultSecurityError(dms_msg)

    state = _load_security_state()
    prof_state = state.setdefault("profiles", {}).setdefault(profile_name, {})
    mem_fails = _profile_failed_attempts.get(profile_name, 0)
    mem_last_ts = _profile_last_failed_time.get(profile_name, 0.0)
    persisted_fails = max(mem_fails, int(prof_state.get("failed_attempts", 0)))
    last_fail_ts = max(mem_last_ts, float(prof_state.get("last_failed_time", 0.0)))

    # 1. Anti-Brute-Force Exponential Rate Limiting (Persists across restarts, isolated per profile)
    if persisted_fails >= 5:
        penalty = min(60, 2 ** min(10, persisted_fails - 4))
        elapsed = time.time() - last_fail_ts
        if elapsed < penalty:
            remaining = int(penalty - elapsed) + 1
            raise VaultSecurityError(f"Too many failed unlock attempts ({persisted_fails})! Wait {remaining} seconds (Anti-Brute Force).")

    v_file, d_file = get_profile_files(profile_name)

    if not os.path.exists(v_file):
        raise FileNotFoundError(f"Vault file for profile '{profile_name}' not found.")

    hw_id = get_hardware_fingerprint()
    kf_id = compute_keyfile_digest(keyfile_path) if (keyfile_path and keyfile_path.strip()) else None

    base_candidates = [password, f"{password}|HW:{hw_id}"]
    if kf_id:
        candidate_passwords = [f"{c}|KF:{kf_id}" for c in base_candidates] + base_candidates
    else:
        candidate_passwords = base_candidates

    # 2. Load unified dual-slot container (with legacy fallback if a 1-slot file exists)
    with open(v_file, "r", encoding="utf-8") as f:
        raw_lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]

    if not raw_lines:
        raise VaultSecurityError("Vault file is empty or corrupted.")

    slot0_armored = raw_lines[0]
    if len(raw_lines) >= 2:
        slot1_armored = raw_lines[1]
    elif os.path.exists(d_file):
        with open(d_file, "r", encoding="utf-8") as f:
            slot1_armored = f.read().strip()
    else:
        slot1_armored = slot0_armored

    # 3. Constant-work decryption across BOTH Slot 0 and Slot 1 for ALL candidates (V-07)
    # Never early-return: always execute 2 * len(candidate_passwords) scrypt derivations.
    matched_result: Optional[Tuple[Dict[str, Any], bool, str]] = None

    for slot_idx, slot_payload in enumerate((slot0_armored, slot1_armored)):
        for cand in candidate_passwords:
            try:
                decrypted = MilitaryVault.decrypt(slot_payload, cand)
                parsed = json.loads(decrypted.decode("utf-8"))
                parsed.setdefault("portfolio", [])
                parsed.setdefault("settings", {"language": "tr"})
                parsed.setdefault("profile_name", profile_name)
                is_decoy_flag = (slot_idx == 1) or bool(parsed.get("is_decoy", False))
                if matched_result is None:
                    matched_result = (parsed, is_decoy_flag, cand)
            except Exception:
                continue

    if matched_result is not None:
        data_out, is_decoy_out, cand_out = matched_result
        _profile_failed_attempts[profile_name] = 0
        _profile_last_failed_time[profile_name] = 0.0
        _failed_attempts = 0
        prof_state["failed_attempts"] = 0
        prof_state["last_checkin_epoch"] = time.time()
        _save_security_state(state)
        return data_out, is_decoy_out, cand_out

    # 4. Handle Authentication Failure & Per-Profile Scorched-Earth Brute-Force Self-Destruct (V-03)
    new_fails = persisted_fails + 1
    now_ts = time.time()
    _profile_failed_attempts[profile_name] = new_fails
    _profile_last_failed_time[profile_name] = now_ts
    _failed_attempts = new_fails
    _last_failed_time = now_ts
    prof_state["failed_attempts"] = new_fails
    prof_state["last_failed_time"] = now_ts
    _save_security_state(state)

    max_wipe = int(prof_state.get("max_failed_wipe", 0))
    if max_wipe > 0 and new_fails >= max_wipe:
        from military_audit import emergency_zeroize_vault, CryptographicAuditTrail
        emergency_zeroize_vault(profile_name)
        CryptographicAuditTrail.record_event(
            "SCORCHED_EARTH_BRUTEFORCE_WIPE",
            profile_name,
            f"Failed attempts ({new_fails}) reached Scorched-Earth limit ({max_wipe}). Vault shredded.",
            "CRITICAL"
        )
        _profile_failed_attempts[profile_name] = 0
        prof_state["failed_attempts"] = 0
        _save_security_state(state)
        raise VaultSecurityError(
            f"SCORCHED-EARTH PROTOCOL TRIGGERED: {new_fails}/{max_wipe} failed attempts reached. Vault cryptographically zeroized (DoD 5220.22-M)."
        )

    raise VaultSecurityError("Incorrect Master Password, Missing 2FA Keyfile, or Hardware Mismatch!")


def add_secret_item(password: str, vault_data: Dict[str, Any], title: str, category: str, secret_value: str, notes: str = "") -> Dict[str, Any]:
    """Adds a new encrypted secret entry to the vault."""
    item = {
        "id": str(uuid.uuid4()),
        "title": title.strip(),
        "category": category,
        "secret": secret_value,
        "notes": notes.strip(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["items"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item


def add_file_item(
    password: str,
    vault_data: Dict[str, Any],
    title: str,
    file_name: str,
    file_bytes: bytes,
    notes: str = ""
) -> Dict[str, Any]:
    """Encodes and embeds an arbitrary binary file (PDF, key, doc) inside the encrypted vault."""
    vault_data.setdefault("items", [])
    safe_fname = os.path.basename(file_name).replace("\x00", "").strip() or "document.bin"
    b64_str = base64.b64encode(file_bytes).decode("ascii")
    item = {
        "id": str(uuid.uuid4()),
        "title": title.strip() or safe_fname,
        "category": "Şifreli Dosya / Belge",
        "is_file": True,
        "file_name": safe_fname,
        "file_size": len(file_bytes),
        "file_b64": b64_str,
        "secret": f"[ENCRYPTED FILE]: {safe_fname} ({len(file_bytes):,} Bytes)",
        "notes": notes.strip(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["items"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item



def delete_secret_item(password: str, vault_data: Dict[str, Any], item_id: str) -> bool:
    """Removes a secret or file entry from the vault by its UUID."""
    init_len = len(vault_data["items"])
    vault_data["items"] = [i for i in vault_data["items"] if i["id"] != item_id]
    if len(vault_data["items"]) < init_len:
        save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
        return True
    return False


def add_portfolio_item(password: str, vault_data: Dict[str, Any], coin: str, label: str, address: str, amount: float) -> Dict[str, Any]:
    """Adds a cold wallet address entry to the portfolio list."""
    vault_data.setdefault("portfolio", [])
    item = {
        "id": str(uuid.uuid4()),
        "coin": coin.upper(),
        "label": label.strip(),
        "address": address.strip(),
        "amount": amount,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["portfolio"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item


def delete_portfolio_item(password: str, vault_data: Dict[str, Any], item_id: str) -> bool:
    """Deletes a portfolio address entry by its UUID."""
    vault_data.setdefault("portfolio", [])
    init_len = len(vault_data["portfolio"])
    vault_data["portfolio"] = [i for i in vault_data["portfolio"] if i["id"] != item_id]
    if len(vault_data["portfolio"]) < init_len:
        save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
        return True
    return False
