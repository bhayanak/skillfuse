"""Optional Open Policy Agent bridge.

When a ``.rego`` policy is supplied and the ``opa`` binary is on PATH, SkillFuse serialises the scan into an
input document and asks OPA for ``data.skillfuse.result`` which must be an object of the shape
``{"decision": "allow|quarantine|block", "reasons": ["..."]}``. See ``examples/policy.rego``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from skillfuse.core.models import Decision, PolicyVerdict, SkillScan
from skillfuse.report.text import skill_to_dict


class OpaUnavailableError(RuntimeError):
    pass


def opa_available() -> bool:
    return shutil.which("opa") is not None


def opa_input(scan: SkillScan, *, signed: bool | None = None, in_lock: bool | None = None) -> dict[str, Any]:
    doc = skill_to_dict(scan)
    doc["signed"] = signed
    doc["in_lock"] = in_lock
    return doc


def evaluate_with_opa(
    scan: SkillScan,
    rego_path: Path,
    *,
    signed: bool | None = None,
    in_lock: bool | None = None,
    timeout: float = 30.0,
) -> PolicyVerdict:
    opa = shutil.which("opa")
    if opa is None:
        msg = "opa binary not found on PATH"
        raise OpaUnavailableError(msg)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(opa_input(scan, signed=signed, in_lock=in_lock), fh)
        input_path = Path(fh.name)
    try:
        proc = subprocess.run(
            [
                opa,
                "eval",
                "--format",
                "json",
                "-d",
                str(rego_path),
                "-i",
                str(input_path),
                "data.skillfuse.result",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    finally:
        input_path.unlink(missing_ok=True)
    if proc.returncode != 0:
        msg = f"opa eval failed: {proc.stderr.strip()}"
        raise RuntimeError(msg)
    return parse_opa_output(scan.package.name, proc.stdout)


def parse_opa_output(skill: str, stdout: str) -> PolicyVerdict:
    data = json.loads(stdout)
    try:
        value = data["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        msg = "unexpected opa output shape"
        raise RuntimeError(msg) from exc
    decision = Decision(str(value.get("decision", "allow")).lower())
    reasons = tuple(str(r) for r in value.get("reasons", []))
    return PolicyVerdict(
        skill=skill, decision=decision, reasons=reasons or ("opa policy",), matched_rules=("opa",)
    )
