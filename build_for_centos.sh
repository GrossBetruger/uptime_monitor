#!/bin/bash
# Build script for CentOS 7.8.2003 x86 Docker image
#
# Note: This builds for linux/amd64 (x86_64) architecture. If you're on an ARM64 Mac,
# Docker will use QEMU emulation. You may see platform warnings - this is expected
# and harmless. The build will work correctly.

set -e

IMAGE_NAME="uptime_monitor"
IMAGE_TAG="centos7.8.2003-x86"

echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"

# Use buildx for cross-platform builds (supports linux/amd64 on ARM64 hosts)
docker buildx build \
    --platform linux/amd64 \
    --load \
    -t ${IMAGE_NAME}:${IMAGE_TAG} \
    -t ${IMAGE_NAME}:latest \
    -f Dockerfile \
    .

echo "Build complete!"
echo ""
echo "To run the container (on ARM64 Mac, use --platform flag):"
echo "  docker run --platform linux/amd64 ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "To extract the binary:"
echo "  docker create --name temp_container ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  docker cp temp_container:/usr/local/bin/uptime_monitor ./uptime_monitor_centos7.8.2003"
echo "  docker rm temp_container"

