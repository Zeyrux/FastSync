FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make libc6-dev cmake libzstd-dev git ca-certificates curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*
