{
  description = "Zig DNS-over-HTTPS server";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
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
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              zig
              zls
              wolfssl.dev
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
              export C_INCLUDE_PATH=${pkgs.c-ares.dev}/include:${pkgs.wolfssl.dev}/include:$C_INCLUDE_PATH
              export LIBRARY_PATH=${pkgs.c-ares}/lib:${pkgs.wolfssl}/lib:$LIBRARY_PATH
              export LD_LIBRARY_PATH=${pkgs.c-ares}/lib:${pkgs.wolfssl}/lib:$LD_LIBRARY_PATH
              export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib
              export CFLAGS="-D_GNU_SOURCE"
            '';
          };
        };
    };
}
