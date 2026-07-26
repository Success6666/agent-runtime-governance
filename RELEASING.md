# Releasing

Releases are created from the protected `main` branch only. Maintainers do not
push release commits directly to `main`; version and changelog changes use the
same issue, pull request, CI, CodeRabbit, and merge process as every other
change.

During the single-maintainer phase, GitHub cannot accept self-approval. Release
pull requests still require every status and CodeRabbit gate; a human code-owner
approval becomes mandatory when a second maintainer is added.

## One-time PyPI setup

1. Create the `agent-runtime-governance` project on PyPI or configure a pending
   trusted publisher for it.
2. Configure the publisher with owner `Success6666`, repository
   `agent-runtime-governance`, workflow `publish-pypi.yml`, and environment
   `pypi`.
3. Create the protected GitHub environment `pypi`. Restrict deployment branches
   and tags to protected branches and tags matching `v*`.

No long-lived PyPI token is stored in GitHub. Publishing uses GitHub OIDC and
PyPI Trusted Publishing.

## Release procedure

1. Open an issue describing the release scope.
2. Update `pyproject.toml`, `agent_runtime_governance.__version__`,
   `CHANGELOG.md`, and `README.md` in a pull request that closes the issue.
3. Merge only after every required check and review gate passes.
4. Create a non-prerelease GitHub release for the matching `vX.Y.Z` tag, with
   `main` as the target.
5. Wait for `Release artifacts` to verify that the tag belongs to `main`, rerun
   lint, tests, dependency audit, and Docker integration smoke, then attach the
   wheel, source distribution, SPDX SBOM, checksums, and GitHub provenance.
6. Dispatch `Publish to PyPI` with the exact release tag. It verifies checksums
   and GitHub provenance before using Trusted Publishing.
7. Install the published version in a fresh environment and verify
   `agent_runtime_governance.__version__`.

Dispatch from the immutable tag, not from a moving branch:

```bash
gh workflow run publish-pypi.yml --ref "vX.Y.Z" -f tag="vX.Y.Z"
```

The workflow rejects a missing, draft, prerelease, or mismatched tag and
publishes only the package distributions already verified by the release
workflow.

Do not replace release assets in place. A failed or compromised release is
yanked and followed by a new patch version.
