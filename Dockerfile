FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc cmake libzstd-dev git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
