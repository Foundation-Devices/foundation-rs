# SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "Foundation Devices Rust libraries";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    corrosion-src = {
      url = "github:corrosion-rs/corrosion/v0.5.0";
      flake = false;
    };

    googletest-src = {
      url = "github:google/googletest/v1.15.2";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      flake-utils,
      advisory-db,
      corrosion-src,
      googletest-src,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustStable = pkgs.rust-bin.stable."1.93.1".default.override {
          extensions = [
            "rust-src"
            "rustfmt"
            "clippy"
          ];
          targets = [ "thumbv7em-none-eabihf" ];
        };

        rustNightly = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain:
          toolchain.default.override {
            extensions = [ "rust-src" ];
          }
        );

        craneLib = (crane.mkLib pkgs).overrideToolchain rustStable;

        # Source filtering: include everything needed for builds and checks.
        srcFilter =
          path: type:
          let
            baseName = builtins.baseNameOf path;
            parentDir = builtins.baseNameOf (builtins.dirOf path);
            pathStr = builtins.toString path;
            rootStr = builtins.toString ./.;
            relPath = pkgs.lib.removePrefix (rootStr + "/") pathStr;
          in
          # Always include Rust sources and Cargo files
          (craneLib.filterCargoSources path type)
          # C/C++ sources and headers
          || pkgs.lib.hasSuffix ".cpp" baseName
          || pkgs.lib.hasSuffix ".h" baseName
          # CMake
          || baseName == "CMakeLists.txt"
          # cbindgen config
          || baseName == "cbindgen.toml"
          # Test data
          || (pkgs.lib.hasInfix "test-vectors/data/" relPath)
          # REUSE licensing
          || (pkgs.lib.hasPrefix ".reuse/" relPath)
          || (pkgs.lib.hasPrefix "LICENSES/" relPath)
          # FFI include directory (committed header)
          || (pkgs.lib.hasPrefix "ffi/include/" relPath)
          # clang-format config
          || baseName == ".clang-format";

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = srcFilter;
          name = "foundation-rs-source";
        };

        # Common arguments for all crane derivations.
        commonArgs = {
          inherit src;
          strictDeps = true;

          # The faster-hex git dependency requires an output hash for vendoring.
          outputHashes = {
            "faster-hex-0.10.0" = "sha256-RDqdms4swqXhG/+MOfaeFniCBGMEFqOxCsPQng6KyI0=";
          };
        };

        # Build workspace dependencies once and share across checks.
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in
      {
        checks = {
          # --- REUSE license compliance ---
          reuse =
            pkgs.runCommand "reuse-check"
              {
                nativeBuildInputs = [ pkgs.reuse ];
                src = pkgs.lib.cleanSourceWith {
                  src = ./.;
                  filter =
                    path: type:
                    let
                      relPath = pkgs.lib.removePrefix (builtins.toString ./. + "/") (builtins.toString path);
                    in
                    # REUSE needs all source files plus license metadata
                    !(pkgs.lib.hasPrefix "target/" relPath)
                    && !(pkgs.lib.hasPrefix ".git/" relPath)
                    && !(pkgs.lib.hasPrefix "result" relPath);
                };
              }
              ''
                cd $src
                reuse lint
                touch $out
              '';

          # --- Cargo check (default features) ---
          cargo-check-default = craneLib.cargoBuild (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoBuildCommand = "cargo check";
            }
          );

          # --- Cargo check (no default features) ---
          cargo-check-no-default = craneLib.cargoBuild (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoBuildCommand = "cargo check";
              cargoExtraArgs = "--no-default-features --workspace --exclude foundation-ffi";
            }
          );

          # --- Cargo check (all features) ---
          cargo-check-all-features = craneLib.cargoBuild (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoBuildCommand = "cargo check";
              cargoExtraArgs = "--all-features --workspace --exclude stratum-v1";
            }
          );

          # --- Cargo fmt ---
          cargo-fmt = craneLib.cargoFmt {
            inherit src;
          };

          # --- Cargo clippy ---
          cargo-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = ""; # original CI runs without --all-targets
            }
          );

          # --- Cargo test (default features) ---
          cargo-test-default = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );

          # --- Cargo test (no default features) ---
          cargo-test-no-default = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoTestExtraArgs = "--no-default-features --workspace --exclude foundation-ffi";
            }
          );

          # --- Cargo test (all features) ---
          cargo-test-all-features = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoTestExtraArgs = "--all-features --workspace --exclude stratum-v1";
            }
          );

          # --- cbindgen header verification ---
          cbindgen-verify =
            let
              vendoredCargoDeps = craneLib.vendorCargoDeps {
                inherit src;
                outputHashes = commonArgs.outputHashes;
              };
            in
            pkgs.runCommand "cbindgen-verify"
              {
                nativeBuildInputs = [
                  pkgs.rust-cbindgen
                  rustStable
                ];
              }
              ''
                # cbindgen needs a writable directory for cargo metadata
                cp -r ${src} source
                chmod -R u+w source
                cd source

                # Set up vendored cargo deps so cargo metadata works in the sandbox
                export HOME=$(mktemp -d)
                mkdir -p .cargo
                cp ${vendoredCargoDeps}/config.toml .cargo/config.toml

                cbindgen --config ffi/cbindgen.toml \
                         --output ffi/include/foundation.h \
                         --verify \
                         ffi/

                touch $out
              '';

          # --- clang-format check ---
          clang-format =
            pkgs.runCommand "clang-format-check"
              {
                nativeBuildInputs = [ pkgs.clang-tools ];
              }
              ''
                cd ${src}
                clang-format --dry-run --Werror ffi/integration/*.cpp
                touch $out
              '';

          # --- Cargo audit ---
          cargo-audit = craneLib.cargoAudit {
            inherit src advisory-db;
          };

          # --- FFI integration tests (CMake + Corrosion + GoogleTest) ---
          ffi-integration =
            let
              # Vendor cargo dependencies so Corrosion can invoke cargo in the sandbox.
              vendoredCargoDeps = craneLib.vendorCargoDeps {
                inherit src;
                outputHashes = commonArgs.outputHashes;
              };
            in
            pkgs.stdenv.mkDerivation {
              name = "ffi-integration-tests";
              inherit src;

              nativeBuildInputs = [
                pkgs.cmake
                pkgs.pkg-config
                rustStable
              ];

              buildInputs = [
                pkgs.nlohmann_json
              ];

              configurePhase = ''
                # Set up cargo vendored dependencies for Corrosion.
                export HOME=$(mktemp -d)
                mkdir -p $HOME/.cargo
                cp ${vendoredCargoDeps}/config.toml $HOME/.cargo/config.toml

                # Build from ffi/integration with the correct relative path
                # so codecs.cpp can find ../../../test-vectors/data/nip-19.json
                cmake -S ffi/integration \
                      -B ffi/integration/cmake-build-debug \
                      -Werror=dev \
                      -Werror=deprecated \
                      -DFETCHCONTENT_SOURCE_DIR_CORROSION=${corrosion-src} \
                      -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=${googletest-src}
              '';

              buildPhase = ''
                cmake --build ffi/integration/cmake-build-debug
              '';

              checkPhase = ''
                ctest --test-dir ffi/integration/cmake-build-debug --output-on-failure
              '';

              installPhase = ''
                touch $out
              '';

              doCheck = true;
            };
        };

        devShells = {
          # Default dev shell with stable Rust and all development tools.
          default = pkgs.mkShell {
            inputsFrom = [ ];
            nativeBuildInputs = [
              rustStable
              pkgs.rust-cbindgen
              pkgs.cargo-audit
              pkgs.cmake
              pkgs.clang-tools
              pkgs.jq
              pkgs.nlohmann_json
              pkgs.pkg-config
              pkgs.reuse
            ];
          };

          # Nightly shell for fuzzing and minimal-versions checks.
          nightly = pkgs.mkShell {
            nativeBuildInputs = [
              rustNightly
              pkgs.cargo-fuzz
              pkgs.jq
            ];
          };
        };
      }
    );
}
