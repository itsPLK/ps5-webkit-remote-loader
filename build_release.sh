#!/bin/bash
# PS5 WebKit Remote Loader - Versioned Release Build Script

set -e
cd "$(dirname "$0")"

# 1. Compute version and build time
python3 tools/gen_version.py
VERSION=$(python3 tools/gen_version.py --print)
export BUILD_VERSION="$VERSION"
BUILD_TIME=$(python3 tools/gen_version.py --build-time)

if [ -z "$VERSION" ]; then
    echo "Error: Could not compute version"
    exit 1
fi

OUTPUT_ELF="webkit-remote-loader-installer_v${VERSION}.elf"
HOST_PY="webkit-remote-loader-host_v${VERSION}.py"
IMAGE_NAME="ps5-webkit-autoloader-sdk"

echo "=== Building PS5 WebKit Remote Loader v$VERSION ==="

# 2. Clean up previous versioned artifacts
rm -f webkit-remote-loader-installer_v*.elf webkit-remote-loader-host_v*.py
echo "[*] Cleaned old versioned artifacts"

# 3. Check or build the shared SDK Docker image
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
    echo "[*] Docker image $IMAGE_NAME not found. Building SDK image..."
    docker build -t "$IMAGE_NAME" -f Dockerfile.sdk .
    echo "[*] Docker image built successfully."
fi

# 5. Build native installer ELF via Docker
echo "[1/2] Building native installer ELF via Docker..."
docker run --rm -u "$(id -u):$(id -g)" \
    -e BUILD_VERSION \
    -e "BUILD_TYPE=${BUILD_TYPE:-dev}" \
    -e "CUSTOM_VERSION=${CUSTOM_VERSION:-}" \
    -v "$(pwd)":/src -w /src \
    $IMAGE_NAME make -f installer/Makefile clean all

if [ -f "installer.elf" ]; then
    mv installer.elf "$OUTPUT_ELF"
    echo "      Created installer ELF: $OUTPUT_ELF"
else
    echo "Error: installer.elf not found after build!"
    exit 1
fi

# 6. Build standalone host script with embedded bundle and TLS certs
echo "[2/2] Building standalone host script..."
python3 tools/build_host.py --output "$HOST_PY" --version "$VERSION" --build-time "$BUILD_TIME"
echo "      Created host script: $HOST_PY"

echo "=== Build Complete! ==="
echo "Artifacts produced:"
ls -la "$OUTPUT_ELF" "$HOST_PY"
echo "Note: Windows executable (.exe) is built via GitHub Actions."
