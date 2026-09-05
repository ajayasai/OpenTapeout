"""Domain-separated Ed25519 statements with an external, explicitly supplied trust store."""
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .util import TapeoutError, atomic_write, canonical, digest, ensure, identifier, read_json, timestamp

PREFIX = b"OpenTapeout signed statement v1\x00"


def key_id(public: str) -> str:
    return digest({"ed25519": public})[:32]


def generate_key(path: Path, *, password: bytes | None = None) -> dict:
    key = Ed25519PrivateKey.generate()
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    atomic_write(path, private, mode=0o600)
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return {"key_id": key_id(public), "public_key": public}


def load_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    ensure(path.is_file() and not path.is_symlink(), "Private key must be a regular nonsymlink file")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (ValueError, TypeError) as exc:
        raise TapeoutError("Cannot load private key; check format/password") from exc
    ensure(isinstance(key, Ed25519PrivateKey), "Only Ed25519 keys are supported")
    return key


def sign(payload: dict, key: Ed25519PrivateKey) -> dict:
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return {"payload": payload, "key_id": key_id(public),
            "signature": base64.b64encode(key.sign(PREFIX + canonical(payload))).decode()}


class Trust:
    def __init__(self, data: dict):
        ensure(isinstance(data, dict) and data.get("schema") == "opentapeout.trust/v1", "Invalid trust schema")
        ensure(isinstance(data.get("keys"), dict) and bool(data["keys"]), "Trust store has no keys")
        self.data, self.keys = data, data["keys"]
        for name, entry in self.keys.items():
            ensure(isinstance(entry, dict), "Invalid trust entry")
            try:
                raw = base64.b64decode(entry["public_key"], validate=True)
                Ed25519PublicKey.from_public_bytes(raw)
            except (ValueError, KeyError, TypeError) as exc:
                raise TapeoutError("Invalid Ed25519 public key") from exc
            ensure(key_id(entry["public_key"]) == name, "Trust key ID does not match public key")
            identifier(entry.get("principal", ""))
            roles = entry.get("roles")
            ensure(isinstance(roles, list) and bool(roles) and all(isinstance(x, str) for x in roles),
                   "Trust entry must list roles")
            ensure(type(entry.get("revoked", False)) is bool, "revoked must be a boolean")

    @classmethod
    def from_file(cls, path: Path) -> "Trust":
        return cls(read_json(path))

    @property
    def sha256(self) -> str:
        return digest(self.data)

    def verify(self, envelope: dict, *, role: str, statement_type: str) -> tuple[dict, str]:
        ensure(isinstance(envelope, dict) and set(envelope) == {"payload", "key_id", "signature"},
               "Malformed signature envelope")
        ensure(isinstance(envelope["payload"], dict), "Signed payload must be an object")
        try:
            entry = self.keys[envelope["key_id"]]
            payload = envelope["payload"]
            ensure(not entry.get("revoked", False), "Signing key has been revoked")
            ensure(role in entry["roles"], f"Signing key is not authorized for role {role}")
            ensure(payload.get("type") == statement_type, "Wrong signature domain/type")
            timestamp(payload["created_at"])
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"], validate=True))
            public.verify(base64.b64decode(envelope["signature"], validate=True), PREFIX + canonical(payload))
            return payload, entry["principal"]
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            if isinstance(exc, TapeoutError):
                raise
            raise TapeoutError("Untrusted key, malformed statement or invalid signature") from exc
