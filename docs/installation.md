# Installation

This fork targets Python 3.12 and publishes from `mr-pmillz/GraphQLer`.

## From source

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```sh
git clone https://github.com/mr-pmillz/GraphQLer.git
cd GraphQLer
uv sync --locked --extra mcp
uv run graphqler --help
```

`uv.lock` contains exact versions and artifact hashes. The optional `mcp` extra
adds the MCP server. The upstream PyPI package is maintained separately; install
this checkout or a wheel from this fork's GitHub Releases to use these features.

## GitHub Releases

Versions come from Git tags; there is no version number to edit in `pyproject.toml`.
A clean `v2.4.2` tag builds version `2.4.2`. Later commits produce development
versions with the commit identifier. Tags such as `v2.5.0rc1` produce prereleases.
CI fetches full tag history and verifies that the wheel, source archive, installed
package, and release tag agree. The GHCR image installs that same wheel.

Push a new tag on the commit you want to release. CI tests the code and publishes
a wheel, source archive, hashed `requirements.txt`, and `SHA256SUMS` to this fork's
GitHub Releases. Existing tags retain their original code and workflow; use a new
tag for fixes. Verify the checksums before installing a downloaded wheel:

```sh
sha256sum --check SHA256SUMS
pip install --require-hashes -r requirements.txt
pip install --no-deps ./graphqler-2.4.2-py3-none-any.whl
```

The release dependency export includes the optional MCP dependencies. Use a
Python 3.12 virtual environment for installation.

Source distributions retain their version without Git. GitHub source archives use
Git archive metadata. For a shallow clone, run `git fetch --unshallow --tags`
before building. `uv` refreshes package metadata when the checked-out commit or
tags change; use `uv sync --reinstall-package graphqler` to refresh metadata for
uncommitted edits. Sources with no Git history or archive metadata fail the build
instead of silently inventing a release version.

## Docker

Images publish to `ghcr.io/mr-pmillz/graphqler`, with commit-SHA and release-version
tags. Use a registry digest when you need immutable deployment inputs:

```sh
# Replace DIGEST with the SHA-256 digest from the published image.
mkdir -p results
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/results:/work/results" \
  ghcr.io/mr-pmillz/graphqler@sha256:DIGEST \
  --mode run --url https://example.com/ --output /work/results
```

The entry point is the installed `graphqler` command; the working directory is
`/work`. It starts directly without resolving or downloading packages. Mount your
output directory to preserve results. `--proxy` works for both HTTP and HTTPS;
use `--insecure` only if you intentionally bypass certificate verification.
New catalogs and reports are private to their owner. On Linux, `--user` gives
mounted output files your host user ID so you can read them after the container exits.

To build locally, create the same artifacts used by CI. Start with an empty
`dist/` directory so older wheels cannot be mixed into the image:

```sh
uv build --build-constraints build-constraints.txt --require-hashes
uv export --locked --no-dev --extra mcp --no-emit-project --format requirements-txt --output-file dist/requirements.txt
uv run --no-sync python scripts/verify_dist.py dist
(cd dist && sha256sum *.whl *.tar.gz requirements.txt > SHA256SUMS)
docker build -t graphqler:local .
docker run --rm graphqler:local --version
```

The Docker build verifies checksums and installs dependencies with hash checking.
Its build context includes only distribution artifacts, excluding Git metadata
and local scan outputs.

## Development and verification

```sh
uv run --locked --extra mcp pytest tests/unit/
uv run --locked --extra mcp pytest tests/integration/
uv run --locked --extra mcp pytest tests/e2e/ -n 4 --dist loadfile
uv run --locked ruff check .
uv run --locked --extra mcp ty check
uv build --build-constraints build-constraints.txt --require-hashes
uv run --locked pytest tests/packaging/
uv run --locked --only-group docs zensical build --clean
```

Integration/end-to-end tests use local sample APIs and require Node 24. The
fixtures install with `npm ci` and `uv sync --locked`; no target credentials are
needed. See [Contributing](CONTRIBUTING.md).

To install the pinned pre-commit hooks, run `uv run pre-commit install`.
