{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs =
            with pkgs;
            [
              # Rust toolchain
              rustToolchain

              # Build tools
              pkg-config

              # Common system libraries that Rust projects often need
              openssl

              # Development tools
              cargo-watch
              cargo-edit
              cargo-audit
              cargo-outdated
              cargo-expand

              # Additional useful tools
              git
              curl

              # Platform-specific dependencies
            ]
            ++ lib.optionals stdenv.isDarwin [
              # macOS specific
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
              libiconv
            ]
            ++ lib.optionals stdenv.isLinux [
              # Linux specific
              gcc
            ];

          shellHook = ''
            echo "🦀 Rust development environment loaded!"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo ""
            echo "Available tools:"
            echo "  cargo-watch  - automatically run commands on file changes"
            echo "  cargo-edit   - add/remove dependencies from command line"
            echo "  cargo-audit  - audit dependencies for security vulnerabilities"
            echo "  cargo-outdated - check for outdated dependencies"
            echo "  cargo-expand - show macro expansions"
            echo ""
          '';

          # Environment variables
          RUST_BACKTRACE = "1";
          RUST_LOG = "debug";
        };

        # Optional: define packages that can be built
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "jose";
          version = "0.1.0";
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };
      }
    );
}
