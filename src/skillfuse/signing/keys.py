"""Ed25519 key management for offline signing."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass(frozen=True, slots=True)
class KeyPair:
    private_pem: bytes
    public_pem: bytes
    key_id: str


def key_id_for(public_key: ed25519.Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:32]


def generate_keypair(passphrase: bytes | None = None) -> KeyPair:
    private = ed25519.Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return KeyPair(private_pem=private_pem, public_pem=public_pem, key_id=key_id_for(private.public_key()))


def write_keypair(pair: KeyPair, directory: Path, name: str = "skillfuse") -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    priv = directory / f"{name}.key"
    pub = directory / f"{name}.pub"
    priv.write_bytes(pair.private_pem)
    priv.chmod(0o600)
    pub.write_bytes(pair.public_pem)
    return priv, pub


def load_private_key(path: Path, passphrase: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        msg = f"{path}: not an Ed25519 private key"
        raise TypeError(msg)
    return key


def load_public_key(data: bytes | str) -> ed25519.Ed25519PublicKey:
    raw = data.encode("ascii") if isinstance(data, str) else data
    if b"-----BEGIN" not in raw:
        raw = base64.b64decode(raw)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        msg = "not an Ed25519 public key"
        raise TypeError(msg)
    return key


def public_pem(key: ed25519.Ed25519PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
