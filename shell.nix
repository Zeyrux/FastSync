{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    gcc
    cmake
    gnumake
    pkg-config
    docker
    tea
  ];

  buildInputs = with pkgs; [
    zstd
  ];

  NIX_ENFORCE_PURITY = 0;

  shellHook = ''
    export NIX_ENFORCE_PURITY=0
    cmake -B build
    export PATH="$PWD/build:$PATH"
  '';
}
