FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad

COPY --from=uv /uv /usr/local/bin/uv
LABEL org.opencontainers.image.source="https://github.com/mr-pmillz/GraphQLer"
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Install the same Git-versioned artifacts that were verified for the release.
# This also works without Git metadata in the Docker build context.
COPY dist/ /tmp/graphqler-dist/
RUN cd /tmp/graphqler-dist \
    && sha256sum --check --strict SHA256SUMS \
    && set -- *.whl && test "$#" -eq 1 \
    && uv venv /app/.venv \
    && uv pip install --python /app/.venv/bin/python --require-hashes -r requirements.txt \
    && uv pip install --python /app/.venv/bin/python --no-deps "$1" \
    && cd /app && rm -rf /tmp/graphqler-dist
ENV PATH="/app/.venv/bin:$PATH" \
    MPLCONFIGDIR=/tmp/graphqler-matplotlib \
    XDG_CACHE_HOME=/tmp/graphqler-cache
WORKDIR /work
ENTRYPOINT ["/app/.venv/bin/graphqler"]
