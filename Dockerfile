FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad

COPY --from=uv /uv /usr/local/bin/uv
LABEL org.opencontainers.image.source="https://github.com/mr-pmillz/GraphQLer"
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock build-constraints.txt README.md LICENSE ./
COPY graphqler ./graphqler
RUN uv build --wheel --build-constraints build-constraints.txt --require-hashes \
    && uv sync --locked --no-dev --no-install-project --extra mcp \
    && uv pip install --no-deps dist/*.whl
ENV PATH="/app/.venv/bin:$PATH" \
    MPLCONFIGDIR=/tmp/graphqler-matplotlib \
    XDG_CACHE_HOME=/tmp/graphqler-cache
WORKDIR /work
ENTRYPOINT ["/app/.venv/bin/graphqler"]
