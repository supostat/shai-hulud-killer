FROM rust:1.84-bookworm

# Install development tools
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV CARGO_HOME=/root/.cargo

# Set working directory
WORKDIR /app

# Default command
CMD ["bash"]
