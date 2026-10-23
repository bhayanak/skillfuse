"""Hash-chained, append-only transparency log (Rekor-style ``hashedrekord`` entries).

The log is a JSONL file. Each entry commits to the previous entry's hash, so truncation or tampering
anywhere in the chain is detectable with :func:`verify_log`. Entries carry a Rekor-compatible
``hashedrekord`` body so they can be mirrored to a public Rekor instance when connectivity allows.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillchain.signing.attestation import canonical_json

GENESIS = "sha256:" + "0" * 64


@dataclass(slots=True)
class LogEntry:
    index: int
    timestamp: str
    subject_name: str
    subject_digest: str
    key_id: str
    signature_b64: str
    public_key_pem: str | None
    prev: str
    hash: str = ""
    body: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "subject": {"name": self.subject_name, "digest": self.subject_digest},
            "keyid": self.key_id,
            "signature": self.signature_b64,
            "publicKey": self.public_key_pem,
            "prev": self.prev,
            "body": self.body,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LogEntry:
        return cls(
            index=int(d["index"]),
            timestamp=str(d["timestamp"]),
            subject_name=str(d["subject"]["name"]),
            subject_digest=str(d["subject"]["digest"]),
            key_id=str(d["keyid"]),
            signature_b64=str(d["signature"]),
            public_key_pem=d.get("publicKey"),
            prev=str(d["prev"]),
            hash=str(d.get("hash", "")),
            body=dict(d.get("body") or {}),
        )


def _entry_hash(d: dict[str, Any]) -> str:
    payload = {k: v for k, v in d.items() if k != "hash"}
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


def _hashedrekord(digest: str, signature_b64: str, public_key_pem: str | None) -> dict[str, Any]:
    _, _, hexval = digest.partition(":")
    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": hexval}},
            "signature": {
                "content": signature_b64,
                "publicKey": {"content": base64.b64encode((public_key_pem or "").encode()).decode("ascii")},
            },
        },
    }


class TransparencyLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def entries(self) -> list[LogEntry]:
        if not self.path.exists():
            return []
        out: list[LogEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(LogEntry.from_dict(json.loads(line)))
        return out

    def head(self) -> str:
        entries = self.entries()
        return entries[-1].hash if entries else GENESIS

    def append(
        self,
        *,
        subject_name: str,
        subject_digest: str,
        key_id: str,
        signature_b64: str,
        public_key_pem: str | None,
    ) -> LogEntry:
        entries = self.entries()
        prev = entries[-1].hash if entries else GENESIS
        entry = LogEntry(
            index=len(entries),
            timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            subject_name=subject_name,
            subject_digest=subject_digest,
            key_id=key_id,
            signature_b64=signature_b64,
            public_key_pem=public_key_pem,
            prev=prev,
            body=_hashedrekord(subject_digest, signature_b64, public_key_pem),
        )
        entry.hash = _entry_hash(entry.to_dict())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = GENESIS
        for i, entry in enumerate(self.entries()):
            if entry.index != i:
                errors.append(f"entry {i}: index {entry.index} out of sequence")
            if entry.prev != prev:
                errors.append(f"entry {i}: prev {entry.prev[:20]}… does not match previous hash {prev[:20]}…")
            expected = _entry_hash(entry.to_dict())
            if entry.hash != expected:
                errors.append(f"entry {i}: hash mismatch (tampered)")
            prev = expected  # chain on recomputed hashes so a tampered entry also breaks its successor's link
        return not errors, errors

    def inclusion(self, subject_digest: str) -> list[LogEntry]:
        return [e for e in self.entries() if e.subject_digest == subject_digest]

    def inclusion_proof(self, index: int) -> dict[str, Any]:
        """A simple linear proof: the chain of hashes from the entry to the head."""
        entries = self.entries()
        if not 0 <= index < len(entries):
            msg = f"index {index} out of range"
            raise IndexError(msg)
        return {
            "index": index,
            "entry_hash": entries[index].hash,
            "head": entries[-1].hash,
            "chain": [e.hash for e in entries[index:]],
            "size": len(entries),
        }
