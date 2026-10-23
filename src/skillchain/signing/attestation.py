"""in-toto Statement + DSSE envelope for skill attestations."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from skillchain import __version__
from skillchain.core.models import PolicyVerdict, SkillScan
from skillchain.report.text import summarise

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://skillchain.dev/attestation/skill/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
BUILDER_ID = "https://skillchain.dev/cli"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def statement(
    *,
    name: str,
    digest: str,
    publisher: str | None,
    version: str | None,
    kind: str,
    entrypoint: str,
    scan: SkillScan | None = None,
    verdict: PolicyVerdict | None = None,
    archive_digest: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    algo, _, hexval = digest.partition(":")
    subject = [{"name": name, "digest": {algo or "sha256": hexval}}]
    if archive_digest:
        a_algo, _, a_hex = archive_digest.partition(":")
        subject.append({"name": f"{name}.tar.gz", "digest": {a_algo or "sha256": a_hex}})
    predicate: dict[str, Any] = {
        "skill": {
            "name": name,
            "kind": kind,
            "version": version,
            "publisher": publisher,
            "entrypoint": entrypoint,
        },
        "builder": {"id": BUILDER_ID, "version": __version__},
        "signedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if scan is not None:
        predicate["scan"] = {
            "toolVersion": __version__,
            "summary": summarise(scan.findings),
            "capabilities": {
                "inferred": list(scan.inferred.capabilities),
                "declared": list(scan.declared.capabilities) if scan.declared else None,
                "observed": list(scan.observed.capabilities) if scan.observed else None,
                "undeclared": list(scan.diff.undeclared),
            },
            "findings": [
                {
                    "ruleId": f.rule_id,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "fingerprint": f.fingerprint,
                }
                for f in scan.findings
            ],
        }
    if verdict is not None:
        predicate["policy"] = {"decision": verdict.decision.value, "reasons": list(verdict.reasons)}
    if extra:
        predicate.update(extra)
    return {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type)).encode(),
            payload_type.encode(),
            str(len(payload)).encode(),
            payload,
        ]
    )


def envelope(
    payload: bytes, signatures: list[tuple[str, bytes]], payload_type: str = PAYLOAD_TYPE
) -> dict[str, Any]:
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": kid, "sig": base64.b64encode(sig).decode("ascii")} for kid, sig in signatures
        ],
    }


def decode_envelope(env: dict[str, Any]) -> tuple[str, bytes, list[tuple[str, bytes]]]:
    payload = base64.b64decode(env["payload"])
    sigs = [(str(s.get("keyid", "")), base64.b64decode(s["sig"])) for s in env.get("signatures", [])]
    return str(env.get("payloadType", PAYLOAD_TYPE)), payload, sigs
