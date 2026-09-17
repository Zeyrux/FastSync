FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make libc6-dev cmake libzstd-dev libssl-dev git ca-certificates curl cppcheck clang-format \
    python3 python3-pip python3-venv openssl openssh-client \
    lcov valgrind clang libclang-rt-18-dev \
    acl attr zlib1g-dev liblz4-dev libxxhash-dev && \
    pip3 install --break-system-packages pytest pytest-xdist && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# rsync is used as the reference implementation for drop-in parity tests.
# Ubuntu 24.04 ships 3.2.7, so build the pinned 3.4.1 reference from source.
ARG RSYNC_VERSION=3.4.1
ARG RSYNC_SHA256=2924bcb3a1ed8b551fc101f740b9f0fe0a202b115027647cf69850d65fd88c52
RUN curl -fsSL "https://download.samba.org/pub/rsync/src/rsync-${RSYNC_VERSION}.tar.gz" -o /tmp/rsync.tar.gz && \
    echo "${RSYNC_SHA256}  /tmp/rsync.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/rsync.tar.gz -C /tmp && \
    cd "/tmp/rsync-${RSYNC_VERSION}" && \
    ./configure --enable-zstd --enable-xxhash --enable-lz4 && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf "/tmp/rsync-${RSYNC_VERSION}" /tmp/rsync.tar.gz
