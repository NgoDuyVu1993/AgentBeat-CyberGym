# Dockerfile for CyberGym Image Builder
# Builds all vulnerability task Docker images on startup

FROM python:3.11-slim

LABEL maintainer="CyberGym Team"
LABEL description="Image Builder - Builds vulnerability Docker images"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies including Docker CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy the setup script
COPY scenarios/cybergym/docker_setup.py .

# Create data directory
RUN mkdir -p /app/cybergym_docker_data

# Build script that runs on container start
COPY <<EOF /app/build_images.sh
#!/bin/bash
echo "=============================================="
echo "CyberGym Image Builder"
echo "Building vulnerability Docker images..."
echo "=============================================="

# Check if images already exist
EXISTING=\$(docker images --format "{{.Repository}}:{{.Tag}}" | grep "cybergym/" | wc -l)

if [ "\$EXISTING" -ge 14 ]; then
    echo "All images already built (\$EXISTING images found)"
    exit 0
fi

# Build images
python docker_setup.py --build

echo "=============================================="
echo "Image build complete!"
echo "=============================================="
EOF

RUN chmod +x /app/build_images.sh

# Run the build script
CMD ["/app/build_images.sh"]
