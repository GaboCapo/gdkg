#!/bin/bash
set -euo pipefail

echo "Build the Binary..."

if ! command -v go &>/dev/null; then
    echo "Go not installed. Install Go first"
    exit 1
fi

go build -o gdkg main.go

echo "build: ./gdkg"

