"""Sign and verify skill packages with local Ed25519 keys (DSSE envelope over an in-toto Statement)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from skillfuse.core.hashing import SIGNATURE_DIR, tree_digest
from skillfuse.core.models import PolicyVerdict, SkillScan
from skillfuse.formats.discovery import discover_packages
from skillfuse.signing.attestation import (
    PAYLOAD_TYPE,
    canonical_json,
    decode_envelope,
    envelope,
    pae,
    statement,
)
from skillfuse.signing.keys import key_id_for, load_public_key, public_pem

ATTESTATION_FILE = "attestation.dsse.json"
SUMMARY_FILE = "signature.json"


@dataclass(slots=True)
class SignResult:
    digest: str
    key_id: str
    attestation_path: Path
    summary_path: Path
    statement: dict[str, Any]


@dataclass(slots=True)
class VerifyResult:
    ok: bool
    digest: str
    expected_digest: str | None = None
    key_id: str | None = None
    publisher: str | None = None
    signer_known: bool | None = None  # None when no trusted keys were supplied
    errors: list[str] = field(default_factory=list)
    statement: dict[str, Any] | None = None

    @property
    def signed(self) -> bool:
        return self.ok


def sign_package(
    root: Path,
    private_key: ed25519.Ed25519PrivateKey,
    *,
    publisher: str | None = None,
    scan: SkillScan | None = None,
    verdict: PolicyVerdict | None = None,
    archive_digest: str | None = None,
    extra: dict[str, Any] | None = None,
) -> SignResult:
    root = root.resolve()
    pkgs = discover_packages(root)
    pkg = pkgs[0] if pkgs else None
    digest = tree_digest(root)
    pub = private_key.public_key()
    kid = key_id_for(pub)
    stmt = statement(
        name=pkg.name if pkg else root.name,
        digest=digest,
        publisher=publisher or (pkg.publisher if pkg else None),
        version=pkg.version if pkg else None,
        kind=pkg.kind.value if pkg else "unknown",
        entrypoint=pkg.entrypoint if pkg else "",
        scan=scan,
        verdict=verdict,
        archive_digest=archive_digest,
        extra=extra,
    )
    payload = canonical_json(stmt)
    sig = private_key.sign(pae(PAYLOAD_TYPE, payload))
    env = envelope(payload, [(kid, sig)])
    env["publicKey"] = public_pem(pub)
    sig_dir = root / SIGNATURE_DIR
    sig_dir.mkdir(exist_ok=True)
    att = sig_dir / ATTESTATION_FILE
    att.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    summary = sig_dir / SUMMARY_FILE
    summary.write_text(
        json.dumps(
            {
                "schema": "skillfuse/signature/v1",
                "digest": digest,
                "keyid": kid,
                "publisher": stmt["predicate"]["skill"]["publisher"],
                "signedAt": stmt["predicate"]["signedAt"],
                "attestation": ATTESTATION_FILE,
                "scheme": "ed25519-dsse",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return SignResult(digest=digest, key_id=kid, attestation_path=att, summary_path=summary, statement=stmt)


def verify_package(root: Path, *, trusted_keys: list[ed25519.Ed25519PublicKey] | None = None) -> VerifyResult:
    root = root.resolve()
    att = root / SIGNATURE_DIR / ATTESTATION_FILE
    digest = tree_digest(root)
    if not att.exists():
        return VerifyResult(
            ok=False, digest=digest, errors=["no attestation found (.skillfuse/attestation.dsse.json)"]
        )
    try:
        env = json.loads(att.read_text(encoding="utf-8"))
        payload_type, payload, sigs = decode_envelope(env)
        stmt = json.loads(payload)
    except (ValueError, KeyError) as exc:
        return VerifyResult(ok=False, digest=digest, errors=[f"malformed attestation: {exc}"])
    errors: list[str] = []
    if payload_type != PAYLOAD_TYPE:
        errors.append(f"unexpected payloadType {payload_type}")
    pub_pem = env.get("publicKey")
    trusted_map = {key_id_for(k): k for k in (trusted_keys or [])}
    verified_kid: str | None = None
    for kid, sig in sigs:
        key = trusted_map.get(kid)
        if key is None and pub_pem:
            try:
                candidate = load_public_key(str(pub_pem))
            except (ValueError, TypeError) as exc:
                errors.append(f"bad embedded public key: {exc}")
                continue
            if key_id_for(candidate) != kid:
                errors.append("embedded public key does not match keyid")
                continue
            key = candidate
        if key is None:
            errors.append(f"no key available for keyid {kid}")
            continue
        try:
            key.verify(sig, pae(payload_type, payload))
            verified_kid = kid
            break
        except InvalidSignature:
            errors.append(f"signature by {kid} is invalid")
    subjects = stmt.get("subject", [])
    expected = None
    for s in subjects:
        d = s.get("digest", {})
        if "sha256" in d and not str(s.get("name", "")).endswith(".tar.gz"):
            expected = f"sha256:{d['sha256']}"
            break
    if expected and expected != digest:
        errors.append(f"content digest mismatch: attestation {expected} != current {digest}")
    publisher = stmt.get("predicate", {}).get("skill", {}).get("publisher")
    signer_known = (verified_kid in trusted_map) if trusted_keys else None
    ok = (
        verified_kid is not None
        and expected == digest
        and not [e for e in errors if "mismatch" in e or "invalid" in e]
    )
    if trusted_keys and not signer_known:
        ok = False
        errors.append("signer key is not in the trusted key set")
    return VerifyResult(
        ok=ok,
        digest=digest,
        expected_digest=expected,
        key_id=verified_kid,
        publisher=publisher,
        signer_known=signer_known,
        errors=errors,
        statement=stmt,
    )
