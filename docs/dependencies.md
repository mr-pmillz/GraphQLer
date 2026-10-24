# Dependency maintenance

Versions were checked against upstream releases on 2026-10-23. Python runtime,
development, docs, and optional MCP dependencies have exact constraints in
`pyproject.toml`; `uv.lock` records resolved versions and artifact hashes. Build
dependencies have a separate hash-checked lock in `build-constraints.txt`.
Git versioning uses Hatch VCS 0.5.0 and setuptools-scm 10.3.4, checked on
2026-10-24 and pinned alongside Hatchling in the build requirements and hash lock.

The runtime remains Python 3.12. CI and containers use Python 3.12.15 and uv
0.13.5. Docker base images, the uv build stage, and the CI BuildKit image use
immutable SHA-256 digests. GitHub Actions and pre-commit hooks use full commit
SHAs with release annotations.

## Compatibility constraints

- Textual stays at 6.2.1 because newer releases require Rich 14 or later, while
  Clairvoyance 2.5.5 requires Rich below 14.
- The JavaScript sample APIs use Apollo Server 5 and Express 5. Apollo's peer
  requirement keeps their GraphQL runtime at 16.14.2. The Python scanner uses
  graphql-core 3.3.0; Graphene fixtures retain their compatible transitive version.
- LiteLLM is pinned to 1.106.2. Version 1.107.0 was removed after an upstream
  compromise; see the [maintainer's incident report](https://litellm.vercel.app/blog/security-incident-oct-21-2026).

Node fixtures require Node 24 and install with `npm ci`. Every direct dependency
is exact and package locks contain registry integrity hashes. The sample API's
Docker image is pinned to Node 24.22.1 with a registry digest.

The fixture locks also update `path-to-regexp` to 8.4.2. The affected optional-group
and multiple-wildcard routing patterns are not used by these fixtures; this is a
defensive update for the [upstream routing advisories](https://github.com/pillarjs/path-to-regexp/security/advisories/GHSA-j3q9-mxjg-w52f).

## Updating pins

Check release notes and dependency compatibility before editing direct version
constraints, then regenerate the appropriate locks with native tools:

```sh
uv lock --upgrade
uv sync --locked --extra mcp
uv pip compile build-requirements.txt --generate-hashes --output-file build-constraints.txt
# Run within each changed sample API directory:
npm install --package-lock-only
npm ci
```

Update each action's commit SHA and matching version comment together. Resolve
container digests from the registry for the exact versioned tag. Refresh the
matching workflow versions, Dockerfiles, fixture manifests, and lockfiles.

Run the checks in [Installation](installation.md#development-and-verification),
validate workflows with actionlint, and build and smoke-test both changed
containers. A versioned tag and a hash pin serve different purposes; retain both.
