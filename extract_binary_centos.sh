#!/bin/bash
# Extract uptime_monitor binary from Docker image to repo root

set -e

IMAGE_NAME="uptime_monitor"
IMAGE_TAG="centos7.8.2003-x86"
CONTAINER_NAME="temp_uptime_monitor_extract"
OUTPUT_FILE="uptime_monitor_centos"

echo "Extracting binary from ${IMAGE_NAME}:${IMAGE_TAG}..."

# Create a temporary container (don't run it, just create it)
docker create --name ${CONTAINER_NAME} ${IMAGE_NAME}:${IMAGE_TAG} > /dev/null

# Copy the binary from container to repo root
docker cp ${CONTAINER_NAME}:/usr/local/bin/uptime_monitor ./${OUTPUT_FILE}

# Remove the temporary container
docker rm ${CONTAINER_NAME} > /dev/null

echo "Binary extracted successfully to ./${OUTPUT_FILE}"
chmod +x ./${OUTPUT_FILE}

