#!/bin/bash
set -euo pipefail

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DIST="dist/v${VERSION}"
NAME="nightreign-map-extract"
IMAGE="nightreign-builder"

echo "Building ${NAME} v${VERSION}"
echo

# Build the Docker image (cached after first run)
docker build -t "${IMAGE}" -f - . <<'DOCKERFILE'
FROM rust:latest
RUN apt-get update && \
    apt-get install -y --no-install-recommends mingw-w64 zip && \
    rustup target add x86_64-pc-windows-gnu && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
DOCKERFILE

mkdir -p "${DIST}"

# Linux x86_64
echo "→ x86_64-unknown-linux-gnu"
docker run --rm -v "$PWD":/src -w /src "${IMAGE}" \
    cargo build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/"${NAME}" "${DIST}/"
(cd "${DIST}" && tar czf "${NAME}-v${VERSION}-x86_64-linux.tar.gz" "${NAME}" && rm "${NAME}")
echo "  ✓ ${DIST}/${NAME}-v${VERSION}-x86_64-linux.tar.gz"

# Windows x86_64
echo "→ x86_64-pc-windows-gnu"
docker run --rm -v "$PWD":/src -w /src "${IMAGE}" \
    cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/"${NAME}.exe" "${DIST}/"
(cd "${DIST}" && zip -q "${NAME}-v${VERSION}-x86_64-windows.zip" "${NAME}.exe" && rm "${NAME}.exe")
echo "  ✓ ${DIST}/${NAME}-v${VERSION}-x86_64-windows.zip"

echo
echo "Release artifacts:"
ls -lh "${DIST}"
