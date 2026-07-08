{
  description = "Zig DNS-over-HTTPS server";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { system, ... }:
        let
          pkgs = import inputs.nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };

          wolfssl = pkgs.stdenv.mkDerivation rec {
            pname = "wolfssl";
            version = "5.9.2";
            src = pkgs.fetchFromGitHub {
              owner = "wolfSSL";
              repo = "wolfssl";
              rev = "v${version}-stable";
              sha256 = "sha256-BKzmTkNWpBhYNBuMdzeL4XDZI/rXO1NrLkfwmwFcNng=";
            };
            nativeBuildInputs = [pkgs.autoreconfHook];
            configureFlags = [
              "--enable-tls13"
              "--enable-alpn"
              "--enable-sni"
            ];
          };

          doh = pkgs.stdenv.mkDerivation {
            name = "doh";
            src = ./.;
            nativeBuildInputs = [ pkgs.zig pkgs.zig.hook pkgs.pkg-config ];
            buildInputs = [ wolfssl pkgs.nghttp2 pkgs.nghttp2.dev ];
            zigBuildFlags = [ "-Doptimize=ReleaseSafe" ];
          };
        in
        {
          packages.default = doh;

          packages.dockerImage = pkgs.dockerTools.buildLayeredImage {
            name = "doh";
            tag = "latest";
            contents = [ doh ];
            config = {
              Cmd = [ "${doh}/bin/doh" ];
              WorkingDir = "/app";
              ExposedPorts = { "8443/tcp" = { }; };
            };
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.zig
              pkgs.zls
              wolfssl
              pkgs.nghttp2
              pkgs.nghttp2.dev
              pkgs.llvmPackages.libclang
              pkgs.mkcert
              pkgs.certbot
              pkgs.woodpecker-cli
              pkgs.rr
              pkgs.gdb
            ];

            shellHook = ''
              export C_INCLUDE_PATH=${wolfssl}/include:$C_INCLUDE_PATH
              export LIBRARY_PATH=${wolfssl}/lib:$LIBRARY_PATH
              export LD_LIBRARY_PATH=${wolfssl}/lib:$LD_LIBRARY_PATH
              export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib
              export CFLAGS="-D_GNU_SOURCE"
            '';
          };
        };
    };
}
