#!/bin/bash
set -euo pipefail

echo "Building GitHub Deploy Key Generator..."

if ! command -v go &>/dev/null; then
    echo "Go is not installed. Please install Go first."
    exit 1
fi

VERSION="v1.0.0"

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%%/*}
    GOARCH=${PLATFORM##*/}
    OUTPUT="gdkg-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "${BUILD_DIR}/${OUTPUT}" main.go
    if [ $? -eq 0 ]; then
        echo "Built: ${BUILD_DIR}/${OUTPUT}"
    else
        echo "Failed to build for $GOOS/$GOARCH"
        exit 1
    fi
done

echo "Build completed. Binaries are in ${BUILD_DIR}/"
