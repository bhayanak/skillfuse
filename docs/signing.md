# Signing, provenance & transparency

## Identity: the tree digest

`sha256:<hex>` over every file in the package: `<mode>\0<posix-relative-path>\0<sha256(content)>\n` per entry,
sorted. Only the executable bit is included — never mtimes, owners, or the `.skillchain/` signature directory. The
same content on macOS, Linux and Windows yields the same digest.

## Offline signing (Ed25519, DSSE, in-toto)

```bash
skillchain keys generate -o .skillchain-keys [--passphrase-env KEY_PASS]
skillchain sign ./skill -k .skillchain-keys/skillchain.key --publisher acme \
    [--policy policy.yaml] [--pack skill.tar.gz] [--log transparency.jsonl]
skillchain verify ./skill [-t .skillchain-keys/skillchain.pub] [--log transparency.jsonl]
```

`sign` refuses to sign a package the policy **blocks**. It writes:

- `.skillchain/attestation.dsse.json` — a [DSSE](https://github.com/secure-systems-lab/dsse) envelope over an
  [in-toto Statement v1](https://in-toto.io/Statement/v1) whose subject is the tree digest (and the archive digest if
  `--pack` was used). The predicate (`https://skillchain.dev/attestation/skill/v1`) records the skill metadata,
  scan summary, capabilities, finding fingerprints, and policy decision.
- `.skillchain/signature.json` — a small human-readable summary.

`verify` recomputes the digest, checks the DSSE signature against `--trusted-key`s (or the embedded public key
when none are given, reporting `trusted: null`), and optionally requires inclusion in a transparency log.

## Reproducible packaging

`skillchain pack ./skill -o skill.tar.gz` writes a gzip'd PAX tar with zeroed mtimes/uids, normalised modes and
sorted entries — identical bytes for identical content, so the archive digest can be a second attestation subject.

## Transparency log

A JSONL hash chain: each entry commits to the previous entry's hash and carries a Rekor-compatible `hashedrekord`
body so it can be mirrored to a public Rekor instance.

```bash
skillchain log list transparency.jsonl
skillchain log verify transparency.jsonl             # chain integrity
skillchain log inclusion transparency.jsonl sha256:… # linear inclusion proof
```

Pin the log head (`TransparencyLog.head()`) out-of-band (e.g. in release notes) to detect truncation.

## Keyless signing (optional)

- `--sigstore` shells out to the `sigstore` CLI (`pip install skillchain[sigstore]`) and writes
  `.skillchain/attestation.sigstore.json`. In GitHub Actions this uses the workflow's OIDC identity.
- `--cosign` uses `cosign sign-blob --bundle`.

Both sign the DSSE attestation file, so a package can carry an offline signature and a keyless one.

## Release artefacts of SkillChain itself

The release workflow produces: sdist + wheel, CycloneDX SBOM, Sigstore signatures for every artefact,
SLSA Level 3 provenance (slsa-github-generator), PyPI attestations via trusted publishing, and a GHCR image with
BuildKit provenance + SBOM and a GitHub build-provenance attestation.
