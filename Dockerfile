FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make libc6-dev cmake libzstd-dev libssl-dev git ca-certificates curl cppcheck clang-format \
    python3 python3-pip python3-venv openssl openssh-client \
    lcov valgrind clang libclang-rt-18-dev && \
    pip3 install --break-system-packages pytest pytest-xdist && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*
