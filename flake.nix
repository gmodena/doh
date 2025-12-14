{
  description = "Zig DNS-over-HTTPS server";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }: 
  let 
    system = "x86_64-linux";

    pkgs = import nixpkgs {
      inherit system; 
      
      config = {
          allowUnfree = true;
        };
    };
  in {
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = [
        pkgs.zig
        pkgs.zls
        pkgs.wolfssl.dev
        pkgs.glibc
        pkgs.glibc.dev
        pkgs.nghttp2
        pkgs.nghttp2.dev
        pkgs.openssl 
        pkgs.llvmPackages.libclang 
        pkgs.gcc
        pkgs.gdb
        pkgs.dnslookup
        pkgs.mkcert
        pkgs.vscode
        pkgs.vscode-extensions.ziglang.vscode-zig
        pkgs.claude-code
        pkgs.dig
        pkgs.certbot
      ];

      shellHook = ''
        export C_INCLUDE_PATH=${pkgs.c-ares.dev}/include:${pkgs.wolfssl.dev}/include:$C_INCLUDE_PATH
        export LIBRARY_PATH=${pkgs.c-ares}/lib:${pkgs.wolfssl}/lib:$LIBRARY_PATH
        export LD_LIBRARY_PATH=${pkgs.c-ares}/lib:${pkgs.wolfssl}/lib:$LD_LIBRARY_PATH
        export CPATH=${pkgs.glibc.dev}/include:$CPATH  # Ensure system headers are visible
        export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib  # Help Zig find libclang
        export CFLAGS="-D_GNU_SOURCE"  # Ensure GNU extensions are enabled
      '';
    };
  };
}
