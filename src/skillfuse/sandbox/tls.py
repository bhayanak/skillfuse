"""Ephemeral certificate authority used by the sandbox's TLS-terminating mock recorder.

The CA lives for one detonation and is written to a scratch directory; the sandboxed process trusts it via
``SSL_CERT_FILE`` / ``REQUESTS_CA_BUNDLE`` / ``NODE_EXTRA_CA_CERTS`` / ``CURL_CA_BUNDLE``. Leaf certificates are
minted lazily per host name from the TLS SNI, so bodies sent over HTTPS are captured instead of failing at the
handshake.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_SAFE = re.compile(r"[^A-Za-z0-9.-]")
_VALIDITY = datetime.timedelta(days=1)


class EphemeralCA:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SkillFuse Sandbox CA")])
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + _VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self.ca_file = directory / "ca.pem"
        self.ca_file.write_bytes(self._cert.public_bytes(serialization.Encoding.PEM))
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()
        self._sni = threading.local()

    def issue(self, host: str) -> tuple[Path, Path]:
        """Mint (certfile, keyfile) for *host* (DNS name or IP literal)."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        san: x509.GeneralName
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + _VALIDITY)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        stem = _SAFE.sub("_", host) or "default"
        certfile = self.directory / f"{stem}.crt"
        keyfile = self.directory / f"{stem}.key"
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        keyfile.chmod(0o600)
        return certfile, keyfile

    def context_for(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                certfile, keyfile = self.issue(host)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile, keyfile)
                self._contexts[host] = ctx
            return ctx

    def server_context(self, default_host: str | None = None) -> ssl.SSLContext:
        """A server context that swaps in a per-host certificate based on SNI."""
        ctx = self.context_for(default_host or "localhost")

        def _sni(sock: ssl.SSLObject | ssl.SSLSocket, name: str | None, _ctx: ssl.SSLContext) -> None:
            if name:
                sock.context = self.context_for(name)
                self._sni.name = name

        ctx.sni_callback = _sni
        return ctx

    def last_sni(self) -> str | None:
        """SNI seen by the most recent handshake on the calling thread, if any."""
        name = getattr(self._sni, "name", None)
        self._sni.name = None
        return str(name) if name else None


TRUST_ENV_VARS: tuple[str, ...] = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "AWS_CA_BUNDLE",
    "DENO_CERT",
    "SKILLFUSE_CA_FILE",
)
