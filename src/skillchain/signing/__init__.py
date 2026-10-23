"""Signing, provenance attestations, reproducible packaging, and the transparency log."""

from skillchain.signing.attestation import (
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    canonical_json,
    statement,
)
from skillchain.signing.external import (
    cosign_available,
    sign_with_cosign,
    sign_with_sigstore,
    sigstore_available,
    verify_with_cosign,
    verify_with_sigstore,
)
from skillchain.signing.keys import (
    KeyPair,
    generate_keypair,
    key_id_for,
    load_private_key,
    load_public_key,
    public_pem,
    write_keypair,
)
from skillchain.signing.pack import pack
from skillchain.signing.sign import ATTESTATION_FILE, SignResult, VerifyResult, sign_package, verify_package
from skillchain.signing.transparency import GENESIS, LogEntry, TransparencyLog

__all__ = [
    "ATTESTATION_FILE",
    "GENESIS",
    "PAYLOAD_TYPE",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "KeyPair",
    "LogEntry",
    "SignResult",
    "TransparencyLog",
    "VerifyResult",
    "canonical_json",
    "cosign_available",
    "generate_keypair",
    "key_id_for",
    "load_private_key",
    "load_public_key",
    "pack",
    "public_pem",
    "sign_package",
    "sign_with_cosign",
    "sign_with_sigstore",
    "sigstore_available",
    "statement",
    "verify_package",
    "verify_with_cosign",
    "verify_with_sigstore",
    "write_keypair",
]
