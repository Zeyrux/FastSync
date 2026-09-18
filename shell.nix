{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  # Development shell for FastSync.  Provides the host-side toolchain needed to
  # build, lint, unit-test, integration-test and benchmark the project.
  # It deliberately does NOT build on entry: run the CMake commands in README.md
  # (or use the CI Docker image for exact CI parity).
  nativeBuildInputs = with pkgs; [
    # build
    gcc
    cmake
    gnumake
    pkg-config
    # lint / static analysis (matches CI)
    clang-tools # clang-format
    cppcheck
    # tests
    (python3.withPackages (ps: with ps; [ pytest pytest-xdist psutil ]))
    openssh # SSH transport integration tests
    # debugging
    gdb
    valgrind
    # coverage
    lcov
    # benchmark tooling
    rsync
    iproute2 # tc/netem for network shaping
    # misc
    git
    curl
    nodejs
    nixpkgs-fmt
    docker
    tea
  ];

  buildInputs = with pkgs; [
    zstd
    zlib
    lz4
    openssl
  ];

  # The CMake configure step fetches xxHash via FetchContent, which needs
  # network access; NIX_ENFORCE_PURITY must be off so the sandbox does not block.
  NIX_ENFORCE_PURITY = 0;

  shellHook = ''
    export NIX_ENFORCE_PURITY=0
    # Make an existing build tree available on PATH, but never build here.
    if [ -d "$PWD/build" ]; then
      export PATH="$PWD/build:$PATH"
    fi
    echo "FastSync dev shell ready."
    echo "  Build:      cmake -B build -S . && cmake --build build -j\$(nproc)"
    echo "  Unit:       ./build/tests"
    echo "  CI parity:  docker run --rm --user \"\$(id -u):\$(id -g)\" -v \"\$PWD:/workspace\" -w /workspace gitea.tap-tap.win/taptap/fastsync-ci:v11 ..."
  '';
}
