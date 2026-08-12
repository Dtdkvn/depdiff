# Releasing Depdiff

Releases are created only by `.github/workflows/release.yml` after a `v<version>` tag is pushed. The workflow is deliberately rerunnable and treats the npm tarball as the release unit.

## Preconditions

1. Merge the release commit into `main` in `https://github.com/Dtdkvn/depdiff`.
2. Set `package.json` to a strict SemVer version and update the changelog.
3. Create the exact matching tag, for example `v0.2.0`, on that commit.
4. Push the tag without moving or recreating it later.

Before dependencies or npm credentials are available, the workflow verifies that the event is an exact `v${package.version}` tag, resolves the tagged object to `GITHUB_SHA`, and proves that commit is an ancestor of the fetched `origin/main`.

## Artifact and rerun contract

After tests pass, the workflow runs `npm pack` once. It independently verifies the tarball's SHA-1 and SHA-512 digests, checks required documentation/assets, uploads that exact tarball as a workflow artifact, and passes the same path to `npm publish`.

On a rerun, the publisher queries npm's `dist.shasum` first:

- identical shasum: skip publication successfully;
- different shasum: fail closed;
- version absent: publish the already verified tarball, then query npm again to confirm the shasum.

Never rebuild or repack between verification and publication.

## Credentials and provenance

The current workflow reads the environment-scoped `NPM_TOKEN` only in the final registry-check/publish step. Keep the `npm` GitHub environment protected and scope the token to this package with the minimum publish permission. The job grants `id-token: write` solely for npm provenance.

The preferred migration is npm trusted publishing. Configure `Dtdkvn/depdiff`, workflow `release.yml`, and environment `npm` as an npm trusted publisher; then remove the `NPM_TOKEN` secret, the final step's `NODE_AUTH_TOKEN`, and the token-presence guard in `scripts/publish-release.mjs`. Keep provenance and the same tag, ancestry, tarball, and shasum checks.
