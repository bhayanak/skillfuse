# Release process

Releases are fully automated from a tag; maintainers only bump the version and write the changelog.

## One-time setup (repository admin)

1. **PyPI trusted publishing** — on PyPI, add a *pending publisher* for project `skillchain`, owner
   `skillchain-dev`, repository `skillchain`, workflow `release.yml`, environment `pypi`.
2. **GitHub environment** `pypi` with required reviewers.
3. **Branch protection** on `main`: require the `CI` checks, signed commits, linear history.
4. Enable *Private vulnerability reporting*, *Dependabot alerts*, and *Code scanning* in repository settings.

## Cutting a release

```bash
# 1. bump version
sed -i '' 's/^version = .*/version = "0.2.0"/' pyproject.toml
sed -i '' 's/^__version__ = .*/__version__ = "0.2.0"/' src/skillchain/__init__.py
# 2. move Unreleased notes under ## [0.2.0] - YYYY-MM-DD in CHANGELOG.md
# 3. commit, tag, push
git commit -am "chore: release v0.2.0"
git tag -s v0.2.0 -m "v0.2.0"
git push origin main v0.2.0
```

The `Release` workflow then:

1. Verifies the tag matches `pyproject.toml`, runs the fast test suite, builds sdist + wheel with
   `SOURCE_DATE_EPOCH` for reproducibility, and generates a CycloneDX SBOM.
2. Produces **SLSA L3 provenance** via `slsa-github-generator`.
3. **Signs** every artefact with Sigstore (keyless, workflow OIDC identity).
4. Publishes to **PyPI** via trusted publishing with attestations (environment approval required).
5. Builds and pushes the **container image** to GHCR with BuildKit provenance/SBOM and a GitHub attestation.
6. Creates the **GitHub release** with the changelog section and all signed artefacts attached.

Dry run without publishing: *Actions → Release → Run workflow* with `dry-run = true`.

## Verifying a release

```bash
pip download skillchain==0.2.0 --no-deps -d dist
sigstore verify github dist/*.whl --repository skillchain-dev/skillchain
slsa-verifier verify-artifact dist/*.whl --provenance-path multiple.intoto.jsonl --source-uri github.com/skillchain-dev/skillchain
cosign verify ghcr.io/skillchain-dev/skillchain:0.2.0 --certificate-identity-regexp 'github.com/skillchain-dev/skillchain' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
