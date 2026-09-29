
# Artifact Provenance & SBOM Attestations

This document describes the provenance and Software Bill of Materials (SBOM)
system for xConfess deployment artifacts, implemented as part of issue #131.

## Overview

Every artifact that ships to staging or production is accompanied by:

1. A **SLSA v1.0 provenance attestation** signed with the GitHub OIDC key,
   binding the artifact SHA-256 to the repository, commit, and workflow run.
2. A **CycloneDX 1.6 SBOM** listing every direct and transitive npm dependency
   at the exact version locked in `package-lock.json`.

Both are stored in the GitHub attestation registry and uploaded as Actions
artifacts retained for 30 days.

## Workflow

The `provenance.yml` workflow runs automatically after every successful CI run
on `main`.  It can also be triggered manually from the Actions tab.

```
CI passes on main
       ↓
provenance.yml: build → SBOM → attest → verify
       ↓
cd.yml: migration gate → build → deploy
```

## Verifying an artifact locally

```bash
# Install the GitHub CLI (https://cli.github.com) if you haven't already.

# Download the artifact from the Actions run or a release.
gh run download <run-id> --name xconfess-backend-attested-<sha>

# Verify provenance — this confirms the artifact was built by this repository.
gh attestation verify xconfess-backend-<sha>.tar.gz \
  --repo yazeed11011/Xconfess

# The output shows the signing identity, commit SHA, and workflow run.
```

## Verifying before deployment (CD integration)

The CD workflow (`cd.yml`) runs `node scripts/migration-gate.js` before
building artifacts.  After build, operators can verify the artifact before
rsyncing to the host:

```bash
gh attestation verify xconfess-backend-<sha>.tar.gz \
  --repo yazeed11011/Xconfess \
  --format json | jq '.[0].verificationResult'
```

A non-zero exit code means the artifact is unverifiable and the deploy should
be aborted.

## SBOM contents

The CycloneDX JSON SBOMs (`sbom-backend-*.cdx.json`, `sbom-frontend-*.cdx.json`)
are uploaded as Actions artifacts and can be ingested by any CycloneDX-compatible
tool for vulnerability scanning or licence auditing.

```bash
# Download from the Actions run
gh run download <run-id> --name sbom-backend-<sha>

# Scan with grype (https://github.com/anchore/grype)
grype sbom:sbom-backend-<sha>.cdx.json
```

## Security properties

- The signing key is GitHub's ephemeral OIDC key — there is no long-lived
  private key to manage or rotate.
- The attestation registry is append-only; attestations cannot be deleted
  without repository admin access.
- Attestations include the `workflow_run` trigger, so the provenance chain
  shows both the originating CI run and the attestation run.

## Assumptions & follow-up work

- The `verify` job in `provenance.yml` downloads the artifact from the same
  Actions run and re-verifies.  In production, CD jobs should download the
  artifact independently and call `gh attestation verify` before deploying.
- Container image attestations (for Docker builds) are not yet included.
  Follow-up: add `docker buildx build --attest type=sbom,type=provenance` when
  the project moves to container-based deployment.
- The `@cyclonedx/cyclonedx-npm` plugin is pinned to `1.19.3`.  Bump it when
  security advisories are published.

