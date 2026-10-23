from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from skillchain.core.hashing import tree_digest
from skillchain.signing import (
    GENESIS,
    TransparencyLog,
    canonical_json,
    generate_keypair,
    key_id_for,
    load_private_key,
    load_public_key,
    pack,
    public_pem,
    sign_package,
    statement,
    verify_package,
    write_keypair,
)
from skillchain.signing.attestation import decode_envelope, envelope, pae
from skillchain.signing.external import (
    cosign_available,
    sign_with_cosign,
    sign_with_sigstore,
    sigstore_available,
    verify_with_cosign,
    verify_with_sigstore,
)


class TestKeys:
    def test_roundtrip(self, tmp_path: Path) -> None:
        pair = generate_keypair()
        priv, pub = write_keypair(pair, tmp_path / "k")
        assert oct(priv.stat().st_mode & 0o777) == "0o600"
        key = load_private_key(priv)
        assert key_id_for(key.public_key()) == pair.key_id
        assert key_id_for(load_public_key(pub.read_bytes())) == pair.key_id
        raw_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        assert key_id_for(load_public_key(raw_b64)) == pair.key_id
        assert "BEGIN PUBLIC KEY" in public_pem(key.public_key())

    def test_passphrase(self, tmp_path: Path) -> None:
        pair = generate_keypair(b"pw")
        priv, _ = write_keypair(pair, tmp_path)
        load_private_key(priv, b"pw")
        with pytest.raises(Exception):  # noqa: B017
            load_private_key(priv)

    def test_wrong_key_type(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        k = ec.generate_private_key(ec.SECP256R1())
        p = tmp_path / "ec.key"
        p.write_bytes(
            k.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        with pytest.raises(TypeError):
            load_private_key(p)
        with pytest.raises(TypeError):
            load_public_key(
                k.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )


class TestAttestation:
    def test_pae_and_envelope(self) -> None:
        p = pae("t", b"abc")
        assert p == b"DSSEv1 1 t 3 abc"
        env = envelope(b"abc", [("kid", b"sig")], payload_type="t")
        assert decode_envelope(env) == ("t", b"abc", [("kid", b"sig")])

    def test_statement(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        s = corpus_result.skills[0]
        st = statement(
            name="n",
            digest="sha256:ab",
            publisher="p",
            version="1",
            kind="skill",
            entrypoint="SKILL.md",
            scan=s,
            archive_digest="sha256:cd",
            extra={"x": 1},
        )
        assert st["subject"][0]["digest"] == {"sha256": "ab"}
        assert st["subject"][1]["name"] == "n.tar.gz"
        assert st["predicate"]["scan"]["summary"]["total"] == len(s.findings)
        assert st["predicate"]["x"] == 1
        assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


class TestSignVerify:
    def test_sign_then_verify(self, skill_dir: Path) -> None:
        pair = generate_keypair()
        priv, pub = write_keypair(pair, skill_dir.parent / "keys")
        key = load_private_key(priv)
        res = sign_package(skill_dir, key, publisher="acme")
        assert res.attestation_path.exists()
        assert res.summary_path.exists()
        assert res.digest == tree_digest(skill_dir)
        v = verify_package(skill_dir)
        assert v.ok and v.signed
        assert v.key_id == pair.key_id
        assert v.publisher == "acme"
        assert v.trusted is None
        v2 = verify_package(skill_dir, trusted_keys=[load_public_key(pub.read_bytes())])
        assert v2.ok and v2.trusted
        other = generate_keypair()
        v3 = verify_package(skill_dir, trusted_keys=[load_public_key(other.public_pem)])
        assert not v3.ok
        assert any("trusted" in e for e in v3.errors)

    def test_tamper_detected(self, skill_dir: Path) -> None:
        key = load_private_key(write_keypair(generate_keypair(), skill_dir.parent / "k")[0])
        sign_package(skill_dir, key)
        (skill_dir / "scripts" / "run.py").write_text("print('evil')")
        v = verify_package(skill_dir)
        assert not v.ok
        assert any("mismatch" in e for e in v.errors)

    def test_bad_signature_and_missing(self, skill_dir: Path) -> None:
        assert not verify_package(skill_dir).ok
        key = load_private_key(write_keypair(generate_keypair(), skill_dir.parent / "k")[0])
        res = sign_package(skill_dir, key)
        env = json.loads(res.attestation_path.read_text())
        env["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
        res.attestation_path.write_text(json.dumps(env))
        v = verify_package(skill_dir)
        assert not v.ok and any("invalid" in e for e in v.errors)
        env["publicKey"] = generate_keypair().public_pem.decode()
        res.attestation_path.write_text(json.dumps(env))
        assert any("does not match keyid" in e for e in verify_package(skill_dir).errors)
        res.attestation_path.write_text("{not json")
        assert any("malformed" in e for e in verify_package(skill_dir).errors)
        del env["publicKey"]
        res.attestation_path.write_text(json.dumps(env))
        assert any("no key available" in e for e in verify_package(skill_dir).errors)

    def test_signing_excludes_signature_dir_from_digest(self, skill_dir: Path) -> None:
        key = load_private_key(write_keypair(generate_keypair(), skill_dir.parent / "k")[0])
        before = tree_digest(skill_dir)
        sign_package(skill_dir, key)
        assert tree_digest(skill_dir) == before
        # re-signing is idempotent w.r.t. digest
        assert sign_package(skill_dir, key).digest == before


class TestPack:
    def test_reproducible(self, skill_dir: Path, tmp_path: Path) -> None:
        d1 = pack(skill_dir, tmp_path / "a.tgz")
        import os
        import time

        os.utime(skill_dir / "SKILL.md", (time.time() - 10_000, time.time() - 10_000))
        d2 = pack(skill_dir, tmp_path / "b.tgz")
        assert d1 == d2
        assert (tmp_path / "a.tgz").read_bytes() == (tmp_path / "b.tgz").read_bytes()
        (skill_dir / "new.txt").write_text("x")
        assert pack(skill_dir, tmp_path / "c.tgz") != d1

    def test_contents(self, skill_dir: Path, tmp_path: Path) -> None:
        import tarfile

        pack(skill_dir, tmp_path / "a.tgz", prefix="")
        with tarfile.open(tmp_path / "a.tgz") as tar:
            names = sorted(tar.getnames())
            assert names == ["SKILL.md", "scripts/run.py"]
            for m in tar.getmembers():
                assert m.mtime == 0 and m.uid == 0 and m.uname == ""


class TestTransparencyLog:
    def test_append_verify_inclusion(self, tmp_path: Path) -> None:
        log = TransparencyLog(tmp_path / "log.jsonl")
        assert log.head() == GENESIS
        assert log.verify() == (True, [])
        e0 = log.append(
            subject_name="a",
            subject_digest="sha256:aa",
            key_id="k",
            signature_b64="c2ln",
            public_key_pem="PEM",
        )
        e1 = log.append(
            subject_name="b",
            subject_digest="sha256:bb",
            key_id="k",
            signature_b64="c2ln",
            public_key_pem=None,
        )
        assert e1.prev == e0.hash
        assert log.head() == e1.hash
        assert log.verify()[0]
        assert [e.index for e in log.inclusion("sha256:aa")] == [0]
        proof = log.inclusion_proof(0)
        assert proof["chain"] == [e0.hash, e1.hash]
        assert proof["size"] == 2
        with pytest.raises(IndexError):
            log.inclusion_proof(5)
        assert e0.body["kind"] == "hashedrekord"
        assert e0.body["spec"]["data"]["hash"]["value"] == "aa"

    def test_tamper_detection(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        log = TransparencyLog(path)
        log.append(
            subject_name="a", subject_digest="sha256:aa", key_id="k", signature_b64="x", public_key_pem=None
        )
        log.append(
            subject_name="b", subject_digest="sha256:bb", key_id="k", signature_b64="x", public_key_pem=None
        )
        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        first["subject"]["digest"] = "sha256:evil"
        path.write_text(json.dumps(first) + "\n" + lines[1] + "\n")
        ok, errors = log.verify()
        assert not ok
        assert any("hash mismatch" in e for e in errors)
        assert any("prev" in e for e in errors)
        # truncation: drop last line, chain still valid (append-only can't detect truncation without head pinning)
        path.write_text(lines[0] + "\n")
        assert log.verify()[0]
        # reorder index
        path.write_text(lines[1] + "\n")
        ok, errors = log.verify()
        assert not ok and any("out of sequence" in e for e in errors)


class TestExternal:
    def test_unavailable(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr("shutil.which", lambda _n: None)
        assert not sigstore_available() and not cosign_available()
        for fn in (
            lambda: sign_with_sigstore(tmp_path),
            lambda: sign_with_cosign(tmp_path),
            lambda: verify_with_sigstore(tmp_path, cert_identity="a", oidc_issuer="b"),
            lambda: verify_with_cosign(tmp_path),
        ):
            with pytest.raises(RuntimeError):
                fn()

    def test_shellout(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import subprocess

        monkeypatch.setattr("shutil.which", lambda n: f"/bin/{n}")
        calls: list[list[str]] = []

        def fake_run(cmd, **_k):  # type: ignore[no-untyped-def]
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        r = sign_with_sigstore(tmp_path, identity_token="tok")
        assert r.tool == "sigstore" and "--identity-token" in calls[-1]
        r = sign_with_cosign(tmp_path, key="k.pem")
        assert r.tool == "cosign" and "--key" in calls[-1]
        assert verify_with_sigstore(tmp_path, cert_identity="me", oidc_issuer="iss")
        assert verify_with_cosign(tmp_path, key="k.pem", cert_identity="me", oidc_issuer="iss")
        monkeypatch.setattr(
            subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, "", "err")
        )
        with pytest.raises(RuntimeError, match="sigstore sign failed"):
            sign_with_sigstore(tmp_path)
        with pytest.raises(RuntimeError, match="cosign"):
            sign_with_cosign(tmp_path)
