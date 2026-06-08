{
  description = "Zig DNS-over-HTTPS server";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls-overlay.url = "github:zigtools/zls";
  };

  outputs = inputs @ {
    flake-parts,
    zig-overlay,
    zls-overlay,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem = {system, ...}: let
        pkgs = import inputs.nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        zig = zig-overlay.packages.${system}.master;
        zls = zls-overlay.packages.${system}.zls;

        wolfssl = pkgs.stdenv.mkDerivation rec {
          pname = "wolfssl";
          version = "5.9.1";
          src = pkgs.fetchFromGitHub {
            owner = "wolfSSL";
            repo = "wolfssl";
            rev = "v${version}-stable";
            sha256 = "sha256-q3V2cxk7dBRJoE8EpfWxkYmXPfDzoMwrX1JLazrHOuA=";
          };
          nativeBuildInputs = [pkgs.autoreconfHook];
          configureFlags = [
            "--enable-tls13"
            "--enable-alpn"
            "--enable-sni"
          ];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            zig
            zls
            wolfssl
            nghttp2
            nghttp2.dev
            llvmPackages.libclang
            mkcert
            certbot
            woodpecker-cli
            rr
            gdb
          ];

          shellHook = ''
            export C_INCLUDE_PATH=${wolfssl}/include:${pkgs.nghttp2.dev}/include:$C_INCLUDE_PATH
            export LIBRARY_PATH=${wolfssl}/lib:${pkgs.nghttp2}/lib:$LIBRARY_PATH
            export LD_LIBRARY_PATH=${wolfssl}/lib:${pkgs.nghttp2}/lib:$LD_LIBRARY_PATH
            export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib
            export CFLAGS="-D_GNU_SOURCE"
          '';
        };
      };
    };
}
