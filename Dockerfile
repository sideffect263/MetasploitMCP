# Build stage for dependencies
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 mcpuser

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/mcpuser/.local

# Copy application files
COPY MetasploitMCP.py .
COPY static/ ./static/

# Create payload directory
RUN mkdir -p /app/payloads && chown mcpuser:mcpuser /app/payloads

# Switch to non-root user
USER mcpuser

# Add user's pip packages to PATH
ENV PATH=/home/mcpuser/.local/bin:$PATH

# Set environment variables
ENV MSF_PASSWORD=${MSF_PASSWORD:-yourpassword}
ENV MSF_SERVER=${MSF_SERVER:-metasploit}
ENV MSF_PORT=${MSF_PORT:-55553}
ENV MSF_SSL=${MSF_SSL:-false}
ENV PAYLOAD_SAVE_DIR=/app/payloads
ENV LOG_LEVEL=${LOG_LEVEL:-INFO}

# Expose the MCP server port
EXPOSE 8085

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8085/healthz || exit 1

# Run the server
CMD ["python", "MetasploitMCP.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8085"] 