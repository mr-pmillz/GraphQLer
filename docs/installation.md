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

Once a `v<project.version>` tag is pushed, CI tests the code, builds the GHCR image,
and publishes a wheel, source archive, hashed `requirements.txt`, and `SHA256SUMS` to the fork's GitHub
Releases. Verify the checksums before installing a downloaded wheel:

```sh
sha256sum --check SHA256SUMS
pip install --require-hashes -r requirements.txt
pip install --no-deps ./graphqler-2.4.0-py3-none-any.whl
```

The release dependency export includes the optional MCP dependencies. Use a
Python 3.12 virtual environment for installation.

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

## Development and verification

```sh
uv run --locked --extra mcp pytest tests/unit/
uv run --locked --extra mcp pytest tests/integration/
uv run --locked --extra mcp pytest tests/e2e/ -n 4 --dist loadfile
uv run --locked ruff check .
uv run --locked --extra mcp ty check
uv build --build-constraints build-constraints.txt --require-hashes
uv run --locked --only-group docs zensical build --clean
```

Integration/end-to-end tests use local sample APIs and require Node 24. The
fixtures install with `npm ci` and `uv sync --locked`; no target credentials are
needed. See [Contributing](CONTRIBUTING.md).

To install the pinned pre-commit hooks, run `uv run pre-commit install`.
