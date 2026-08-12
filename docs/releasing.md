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

The release workflow is OIDC-only: it grants `id-token: write` and deliberately provides no `NPM_TOKEN`, `NODE_AUTH_TOKEN`, or other publish credential. The npm account's bootstrap token has been revoked and the GitHub `npm` environment no longer contains that secret. Do not add a token fallback.

Trusted-publisher registration is not complete yet because the npm publisher account still requires its external 2FA/account confirmation. Before creating another release tag, register package `depdiff-audit` on npm with GitHub owner/repository `Dtdkvn/depdiff`, workflow filename `release.yml`, environment `npm`, and `npm publish` permission. Until that exact trust relationship exists, the final `npm publish` command is expected to fail authentication after the workflow has safely verified and preserved the artifact. Keep the same tag, ancestry, single-tarball, provenance, and post-publish shasum checks when the registration is completed.
