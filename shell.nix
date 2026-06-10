{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    gcc
    cmake
    gnumake
    pkg-config
  ];

  buildInputs = with pkgs; [
    zstd
  ];

  shellHook = ''
    echo "fastSync development environment loaded"
  '';
}
