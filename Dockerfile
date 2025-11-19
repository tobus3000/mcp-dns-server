# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for the application
# - libffi-dev and libssl-dev for cryptography/dnssec support
# - libpcap-dev for scapy network operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir .

# Expose port for MCP server communication (default for stdio transport)
# Note: Adjust if using HTTP or WebSocket transport
EXPOSE 3000

# Set the entry point to launch the server
ENTRYPOINT ["python", "launch.py"]
