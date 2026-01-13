# PostgreSQL with Ghidra BSim lshvector extension
# This Dockerfile builds the lshvector extension from Ghidra source
# and installs it into PostgreSQL 15

FROM postgres:15 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    postgresql-server-dev-15 \
    && rm -rf /var/lib/apt/lists/*

# Clone Ghidra repository (only the lshvector source needed)
WORKDIR /build
RUN git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/NationalSecurityAgency/ghidra.git && \
    cd ghidra && \
    git sparse-checkout set Ghidra/Features/BSim/src/lshvector

# Build the lshvector extension
WORKDIR /build/ghidra/Ghidra/Features/BSim/src/lshvector
RUN make

# Final image
FROM postgres:15

# Copy built extension from builder stage
COPY --from=builder /build/ghidra/Ghidra/Features/BSim/src/lshvector/lshvector.so \
    /usr/lib/postgresql/15/lib/
COPY --from=builder /build/ghidra/Ghidra/Features/BSim/src/lshvector/lshvector.control \
    /usr/share/postgresql/15/extension/
COPY --from=builder /build/ghidra/Ghidra/Features/BSim/src/lshvector/lshvector--1.0.sql \
    /usr/share/postgresql/15/extension/

# Verify extension files are in place
RUN ls -la /usr/lib/postgresql/15/lib/lshvector.so && \
    ls -la /usr/share/postgresql/15/extension/lshvector*

# Default entrypoint from postgres image
