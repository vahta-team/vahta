# The bench image: Vahta built from this checkout, plus the bench's Python.
#
#   docker build -f bench/docker/Dockerfile -t vahta-bench .     (from the repo root)
#
# The daemon is built with its `test-surface` feature: that is the daemon's
# scripted prompt surface, the only way to set up a vault and open a session in
# a container with no terminal window and nobody to type a password. It is a
# TEST BUILD, used only inside bench containers, never installed on a host.

# Keep in step with rust-toolchain.toml.
FROM rust:1.99.0-slim-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p vahta-cli -p vahta-hook \
        --features vahta-daemon/test-surface \
    && mkdir /out \
    && cp target/release/vahta target/release/vh target/release/vahta-hook /out/

# Claude Code, pinned (the npm "stable" tag when this was written). The npm package
# is a thin wrapper around a native binary, which is all the runtime image keeps:
# the image needs no Node. Used only by the `claude-code` red-team mode.
FROM node:22-bookworm-slim AS claude
ARG CLAUDE_CODE_VERSION=2.1.286
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
    && mkdir /out \
    && cp "$(readlink -f /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe)" /out/claude \
    && /out/claude --version

FROM python:3.12-slim-bookworm
COPY --from=builder /out/ /usr/local/bin/
COPY --from=claude /out/claude /usr/local/bin/claude
RUN useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /bench /work && chown agent /work
COPY bench/*.py /bench/
# The slim image has no curl and installing it would need a download.
RUN ln -s /bench/curl.py /usr/local/bin/curl && chmod +x /bench/curl.py
COPY bench/regression /bench/regression
USER agent
ENV HOME=/home/agent PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /work
