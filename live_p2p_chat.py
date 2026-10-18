"""
Global Encrypted Chat Network (Worldwide Relay & P2P Architecture)
Key Capabilities:
- Worldwide connectivity without firewall port forwarding or IP exposure.
- TLS-encrypted client relay architecture via global MQTT broker (Port 8883).
- End-to-end AES-256-GCM encryption + Ed25519 sender authentication + TOFU key pinning (V-15).
- Authenticated Post-Quantum Hybrid KEM (X25519 + Ring-LWE FO-CCA2) session ratcheting (V-04).
- Memory-hard scrypt Zero-Knowledge Blinded Topic derivation against offline dictionary attacks (W-01).
"""

import os
import json
import ssl
import time
import uuid
import hmac
import secrets
import hashlib
import threading
from collections import deque
from datetime import datetime
from typing import Callable, Optional, Dict
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import crypto_chat
from crypto_utils import PQHybridKEM

DEFAULT_BROKER = "broker.hivemq.com"
DEFAULT_PORT = 8883  # W-01: Enforce TLS port 8883 instead of cleartext 1883
MAX_MQTT_PACKET_BYTES = 20 * 1024 * 1024  # 20 MB anti-DoS memory cap

# TOFU (Trust-On-First-Use) Peer Public Key Registry & Topic Cache
_PEER_PINNED_KEYS: Dict[str, str] = {}
_SEEN_PACKET_DIGESTS: deque = deque(maxlen=4096)


def _get_p2p_replay_file() -> str:
    try:
        from vault_storage import _get_user_secret_dir
        return os.path.join(_get_user_secret_dir(), ".p2p_replay_ledger.json")
    except Exception:
        return ".p2p_replay_ledger.json"


def _is_packet_replayed(username: str, token: str) -> bool:
    digest = hashlib.sha256(f"{username}:{token}".encode("utf-8")).hexdigest()
    if digest in _SEEN_PACKET_DIGESTS:
        return True
    ledger_file = _get_p2p_replay_file()
    if os.path.exists(ledger_file):
        try:
            with open(ledger_file, "r", encoding="utf-8") as f:
                items = json.load(f)
            if isinstance(items, list) and digest in items:
                _SEEN_PACKET_DIGESTS.append(digest)
                return True
        except Exception:
            pass
    return False


def _record_packet_seen(username: str, token: str) -> None:
    digest = hashlib.sha256(f"{username}:{token}".encode("utf-8")).hexdigest()
    if digest not in _SEEN_PACKET_DIGESTS:
        _SEEN_PACKET_DIGESTS.append(digest)
    ledger_file = _get_p2p_replay_file()
    try:
        with open(ledger_file, "w", encoding="utf-8") as f:
            json.dump(list(_SEEN_PACKET_DIGESTS)[-1024:], f)
    except Exception:
        pass


def derive_zk_topic(room_key: str, room_name: str) -> str:
    """
    Derives a Zero-Knowledge Blinded MQTT Topic using memory-hard scrypt (N=32768, r=8, p=1)
    followed by HMAC-SHA256 (W-01). Defeats high-speed offline dictionary attacks against
    observed MQTT topic strings.
    """
    clean_room = room_name.strip().lower() or "general-room"
    clean_key = room_key.strip()
    if not clean_key:
        raise ValueError("Room passkey cannot be empty.")

    topic_salt = hashlib.sha256(f"AEGIS-ZK-TOPIC-SALT-v4:{clean_room}".encode("utf-8")).digest()[:16]
    kdf = Scrypt(salt=topic_salt, length=32, n=32768, r=8, p=1)
    hardened_key = kdf.derive(clean_key.encode("utf-8"))
    blind_id = hmac.new(
        hardened_key,
        f"KYBERON-ZK-ROOM-v4:{clean_room}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:28]
    return f"kyberon/v4/zk/{blind_id}"


class GlobalEncryptedChatSession:
    """
    Worldwide end-to-end encrypted messaging session with scrypt-hardened ZK topics (W-01),
    Ed25519 sender authentication + TOFU key pinning (V-15), persistent anti-replay (V-15),
    and authenticated PQ-Hybrid KEM ratcheting (V-04).
    """

    def __init__(self, username: str, room_name: str, room_key: str, on_message: Callable, on_status: Callable):
        self.username = username.strip() or "Anonymous"
        self.room_name = room_name.strip().lower() or "general-room"
        self.base_room_key = room_key.strip()
        if not self.base_room_key:
            raise ValueError("Room encryption passkey cannot be empty (W-01).")
        self.room_key = self.base_room_key
        self.pq_active = False
        self._ephemeral_pq_sk: Optional[str] = None
        self._pending_syn_id: Optional[str] = None
        self.on_message = on_message
        self.on_status = on_status
        self.session_id = uuid.uuid4().hex[:8]
        self._seen_nonces = deque(maxlen=512)

        # V-15 & V-04: Per-user Ed25519 cryptographic identity keypair
        self._ed25519_sk = Ed25519PrivateKey.generate()
        self.ed25519_pub_hex = self._ed25519_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        _PEER_PINNED_KEYS.setdefault(self.username, self.ed25519_pub_hex)

        # W-01: Memory-hard scrypt Zero-Knowledge Blinded Topic
        self.topic = derive_zk_topic(self.base_room_key, self.room_name)
        self.client: Optional[mqtt.Client] = None
        self.is_connected = False

    def _sign_packet(self, body: str, extra_bind: str = "") -> Dict[str, str]:
        """Creates an Ed25519 signature binding session_id, username, room_name, and message body."""
        msg_to_sign = f"{self.session_id}|{self.username}|{self.room_name}|{body}|{extra_bind}".encode("utf-8")
        sig_hex = self._ed25519_sk.sign(msg_to_sign).hex()
        meta = {
            "ed25519_pub": self.ed25519_pub_hex,
            "ed25519_sig": sig_hex,
            "sender": self.username,
            "session_id": self.session_id,
        }
        if extra_bind:
            meta["extra_bind"] = extra_bind
        return meta

    def _verify_packet_signature(self, msg_sid: str, sender: str, body: str, meta: Optional[Dict]) -> bool:
        """
        Verifies the Ed25519 signature and enforces TOFU public-key pinning for the sender (V-04, V-15).
        Unsigned or forged packets are rejected immediately.
        """
        if not isinstance(meta, dict):
            return False
        pub_hex = meta.get("ed25519_pub", "")
        sig_hex = meta.get("ed25519_sig", "")
        extra_bind = meta.get("extra_bind", "")
        if not pub_hex or not sig_hex or meta.get("sender") != sender or meta.get("session_id") != msg_sid:
            return False

        # TOFU check: if sender username is already pinned to a different Ed25519 key, reject spoofing
        pinned_pub = _PEER_PINNED_KEYS.get(sender)
        if pinned_pub and pinned_pub != pub_hex:
            return False

        try:
            pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            msg_to_verify = f"{msg_sid}|{sender}|{self.room_name}|{body}|{extra_bind}".encode("utf-8")
            pub_key.verify(bytes.fromhex(sig_hex), msg_to_verify)
            _PEER_PINNED_KEYS.setdefault(sender, pub_hex)
            return True
        except Exception:
            return False

    def connect(self):
        """Connects to the global relay over TLS (port 8883) and begins encrypted message listening."""
        def worker():
            try:
                self.on_status(f"🟡 Connecting to global TLS relay for room '{self.room_name}'...")
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                self.client.on_connect = self._on_connect
                self.client.on_message = self._on_mqtt_message
                self.client.on_disconnect = self._on_disconnect

                try:
                    tls_ctx = ssl.create_default_context()
                    self.client.tls_set_context(tls_ctx)
                except Exception:
                    pass

                self.client.connect(DEFAULT_BROKER, DEFAULT_PORT, keepalive=45)
                self.client.loop_start()
            except Exception as e:
                self.on_status(f"❌ Connection error: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.is_connected = True
            client.subscribe(self.topic, qos=1)
            self.on_status(f"🟢 Connected to Room: '{self.room_name}' | TLS + Scrypt-ZK-Topic & Ed25519 Active!")
        else:
            self.on_status(f"❌ Broker refused connection (RC: {rc})")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code=None, properties=None):
        self.is_connected = False
        self.on_status("🔴 Disconnected from chat room.")

    def initiate_pq_handshake(self) -> bool:
        """
        Initiates an Ed25519-authenticated ephemeral Post-Quantum Hybrid KEM
        (X25519 + Ring-LWE FO-CCA2) key ratchet with room peers (V-04).
        """
        if not self.client or not self.is_connected:
            return False
        try:
            pub_k, priv_k = PQHybridKEM.generate_keypair()
            self._ephemeral_pq_sk = priv_k
            self._pending_syn_id = secrets.token_hex(16)
            body = f"[PQ-KEM-SYN]:{pub_k}"
            formatted = f"{self.session_id}:{self.username}: {body}"
            meta = self._sign_packet(body, extra_bind=self._pending_syn_id)
            meta["syn_id"] = self._pending_syn_id
            token = crypto_chat.encrypt_message(formatted, self.base_room_key, metadata=meta)
            _record_packet_seen(self.username, token)
            self.client.publish(self.topic, token, qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message("⚛️ PQ-KEM", "Broadcasting Authenticated X25519 + Ring-LWE (FO-CCA2) Public Key...", ts, True)
            return True
        except Exception:
            return False

    def _on_mqtt_message(self, client, userdata, msg):
        """
        Decrypts incoming cryptographic payload envelope and enforces:
        - Persistent & in-memory anti-replay deduplication across restarts (V-15)
        - Ed25519 sender signature & TOFU public-key pinning (V-15)
        - Authenticated PQ-KEM handshake confirmation bound to syn_id (V-04)
        """
        try:
            if not msg.payload or len(msg.payload) > MAX_MQTT_PACKET_BYTES:
                return

            token = msg.payload.decode("utf-8").strip()
            if _is_packet_replayed(self.username, token):
                return  # Drop replayed token even across session restarts (V-15)

            payload = None
            for candidate_key in ([self.room_key, self.base_room_key] if self.room_key != self.base_room_key else [self.room_key]):
                try:
                    payload = crypto_chat.decrypt_message(token, candidate_key, max_age_seconds=600.0, enforce_replay_cache=False)
                    break
                except Exception:
                    continue
            if payload is None:
                return

            _record_packet_seen(self.username, token)

            msg_nonce = payload.get("nonce")
            if msg_nonce:
                if msg_nonce in self._seen_nonces:
                    return
                self._seen_nonces.append(msg_nonce)

            msg_epoch = payload.get("epoch")
            if not isinstance(msg_epoch, (int, float)) or abs(time.time() - msg_epoch) > 600:
                return

            full_text = payload.get("text", "")
            ts = payload.get("timestamp", datetime.now().strftime("%H:%M:%S"))
            meta = payload.get("meta")

            parts = full_text.split(":", 2)
            if len(parts) == 3:
                msg_sid = parts[0]
                sender = parts[1]
                body = parts[2].lstrip()
            else:
                return

            if msg_sid == self.session_id:
                return

            # V-15 & V-04: Mandatory Ed25519 cryptographic signature & TOFU verification
            if not self._verify_packet_signature(msg_sid, sender, body, meta):
                return

            # Authenticated Post-Quantum Hybrid KEM Handshake SYN
            if body.startswith("[PQ-KEM-SYN]:"):
                syn_id = meta.get("syn_id", "") if isinstance(meta, dict) else ""
                if not syn_id:
                    return
                peer_pk = body[len("[PQ-KEM-SYN]:"):].strip()
                ct_armored, shared_hex = PQHybridKEM.encapsulate(peer_pk)
                next_room_key = hashlib.sha3_256(
                    f"{self.base_room_key}|PQ:{shared_hex}|SYN:{syn_id}".encode("utf-8")
                ).hexdigest()
                confirm_mac = hmac.new(
                    next_room_key.encode("utf-8"),
                    f"AEGIS-PQ-ACK-CONFIRM:{syn_id}:{ct_armored[:64]}".encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                self.room_key = next_room_key
                self.pq_active = True
                ack_body = f"[PQ-KEM-ACK]:{ct_armored}"
                reply_fmt = f"{self.session_id}:{self.username}: {ack_body}"
                ack_meta = self._sign_packet(ack_body, extra_bind=f"{syn_id}:{confirm_mac}")
                ack_meta["ack_syn_id"] = syn_id
                ack_meta["confirm_mac"] = confirm_mac
                reply_tok = crypto_chat.encrypt_message(reply_fmt, self.base_room_key, metadata=ack_meta)
                _record_packet_seen(self.username, reply_tok)
                self.client.publish(self.topic, reply_tok, qos=1)
                self.on_status(f"⚛️ Connected: '{self.room_name}' | PQ-HYBRID (ML-KEM-LWE + X25519 + Ed25519) ACTIVE!")
                self.on_message(
                    "⚛️ PQ-KEM",
                    f"Authenticated Quantum-Resistant Handshake with '{sender}' completed! Session ratcheted (ID: {shared_hex[:12]}...).",
                    ts,
                    False
                )
                return

            # Authenticated Post-Quantum Hybrid KEM Handshake ACK (V-04)
            if body.startswith("[PQ-KEM-ACK]:") and self._ephemeral_pq_sk and self._pending_syn_id:
                ack_syn_id = meta.get("ack_syn_id", "") if isinstance(meta, dict) else ""
                confirm_mac = meta.get("confirm_mac", "") if isinstance(meta, dict) else ""
                if not ack_syn_id or not hmac.compare_digest(ack_syn_id, self._pending_syn_id):
                    return

                ct_armored = body[len("[PQ-KEM-ACK]:"):].strip()
                shared_hex = PQHybridKEM.decapsulate(ct_armored, self._ephemeral_pq_sk)
                candidate_room_key = hashlib.sha3_256(
                    f"{self.base_room_key}|PQ:{shared_hex}|SYN:{self._pending_syn_id}".encode("utf-8")
                ).hexdigest()
                expected_mac = hmac.new(
                    candidate_room_key.encode("utf-8"),
                    f"AEGIS-PQ-ACK-CONFIRM:{self._pending_syn_id}:{ct_armored[:64]}".encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(confirm_mac, expected_mac):
                    return

                self._ephemeral_pq_sk = None
                self._pending_syn_id = None
                self.room_key = candidate_room_key
                self.pq_active = True
                self.on_status(f"⚛️ Connected: '{self.room_name}' | PQ-HYBRID (ML-KEM-LWE + X25519 + Ed25519) ACTIVE!")
                self.on_message(
                    "⚛️ PQ-KEM",
                    f"Authenticated Quantum-Resistant Handshake confirmed by '{sender}'! Forward-secret session ratcheted (ID: {shared_hex[:12]}...).",
                    ts,
                    False
                )
                return

            self.on_message(sender, body, ts, False)
        except Exception:
            pass

    def send_message(self, text: str) -> bool:
        """Armors message with AES-256-GCM + Ed25519 signature and transmits to the global channel."""
        if not self.client or not self.is_connected:
            return False

        try:
            body = text.strip()
            formatted = f"{self.session_id}:{self.username}: {body}"
            meta = self._sign_packet(body)
            token = crypto_chat.encrypt_message(formatted, self.room_key, metadata=meta)
            _record_packet_seen(self.username, token)
            self.client.publish(self.topic, token, qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message(self.username, body, ts, True)
            return True
        except Exception:
            return False

    def close(self):
        self.is_connected = False
        self._ephemeral_pq_sk = None
        self._pending_syn_id = None
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.client = None


