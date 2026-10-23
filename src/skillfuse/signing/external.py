"""Optional adapters for keyless signing with Sigstore (``sigstore`` CLI) and ``cosign``.

Both tools are shelled out to when present; SkillFuse never bundles them. The produced bundles are stored
next to the Ed25519 attestation so a package can carry both an offline and a keyless signature.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from skillfuse.core.hashing import SIGNATURE_DIR
from skillfuse.signing.sign import ATTESTATION_FILE

SIGSTORE_BUNDLE = "attestation.sigstore.json"
COSIGN_BUNDLE = "attestation.cosign.bundle"


@dataclass(slots=True)
class ExternalSignResult:
    tool: str
    bundle_path: Path
    stdout: str


def sigstore_available() -> bool:
    return shutil.which("sigstore") is not None


def cosign_available() -> bool:
    return shutil.which("cosign") is not None


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def sign_with_sigstore(
    root: Path, *, identity_token: str | None = None, timeout: float = 300
) -> ExternalSignResult:
    exe = shutil.which("sigstore")
    if exe is None:
        msg = "sigstore CLI not found; install with `pip install skillfuse[sigstore]`"
        raise RuntimeError(msg)
    att = root / SIGNATURE_DIR / ATTESTATION_FILE
    bundle = root / SIGNATURE_DIR / SIGSTORE_BUNDLE
    cmd = [exe, "sign", "--bundle", str(bundle), "--overwrite"]
    if identity_token:
        cmd += ["--identity-token", identity_token]
    cmd.append(str(att))
    proc = _run(cmd, timeout)
    if proc.returncode != 0:
        msg = f"sigstore sign failed: {proc.stderr.strip()}"
        raise RuntimeError(msg)
    return ExternalSignResult(tool="sigstore", bundle_path=bundle, stdout=proc.stdout)


def verify_with_sigstore(root: Path, *, cert_identity: str, oidc_issuer: str, timeout: float = 120) -> bool:
    exe = shutil.which("sigstore")
    if exe is None:
        msg = "sigstore CLI not found"
        raise RuntimeError(msg)
    att = root / SIGNATURE_DIR / ATTESTATION_FILE
    bundle = root / SIGNATURE_DIR / SIGSTORE_BUNDLE
    proc = _run(
        [
            exe,
            "verify",
            "identity",
            "--bundle",
            str(bundle),
            "--cert-identity",
            cert_identity,
            "--cert-oidc-issuer",
            oidc_issuer,
            str(att),
        ],
        timeout,
    )
    return proc.returncode == 0


def sign_with_cosign(root: Path, *, key: str | None = None, timeout: float = 300) -> ExternalSignResult:
    exe = shutil.which("cosign")
    if exe is None:
        msg = "cosign not found on PATH"
        raise RuntimeError(msg)
    att = root / SIGNATURE_DIR / ATTESTATION_FILE
    bundle = root / SIGNATURE_DIR / COSIGN_BUNDLE
    cmd = [exe, "sign-blob", "--yes", "--bundle", str(bundle)]
    if key:
        cmd += ["--key", key]
    cmd.append(str(att))
    proc = _run(cmd, timeout)
    if proc.returncode != 0:
        msg = f"cosign sign-blob failed: {proc.stderr.strip()}"
        raise RuntimeError(msg)
    return ExternalSignResult(tool="cosign", bundle_path=bundle, stdout=proc.stdout)


def verify_with_cosign(
    root: Path,
    *,
    key: str | None = None,
    cert_identity: str | None = None,
    oidc_issuer: str | None = None,
    timeout: float = 120,
) -> bool:
    exe = shutil.which("cosign")
    if exe is None:
        msg = "cosign not found on PATH"
        raise RuntimeError(msg)
    att = root / SIGNATURE_DIR / ATTESTATION_FILE
    bundle = root / SIGNATURE_DIR / COSIGN_BUNDLE
    cmd = [exe, "verify-blob", "--bundle", str(bundle)]
    if key:
        cmd += ["--key", key]
    if cert_identity:
        cmd += ["--certificate-identity", cert_identity]
    if oidc_issuer:
        cmd += ["--certificate-oidc-issuer", oidc_issuer]
    cmd.append(str(att))
    return _run(cmd, timeout).returncode == 0
