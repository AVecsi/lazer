{
  description = "lazer dev shell (lattice-based ZK proof library)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        #   "aarch64-linux"
        #   "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          isDarwin = pkgs.stdenv.isDarwin;

          pythonEnv = pkgs.python3.withPackages (
            ps: with ps; [
              cffi
              pip
            ]
          );
        in
        {
          devShells.default = pkgs.mkShell {
            name = "lazer-dev";

            buildInputs =
              with pkgs;
              [
                # toolchain
                gcc13
                gnumake
                cmake
                pkg-config
                git
                unzip
                patch

                # math libs lazer links against
                gmp
                mpfr
                libffi

                # sagemath for parameter codegen (scripts/*.sage)
                # sage

                pythonEnv

                # NOTE: deliberately NOT providing cpu_features here, even though ARM
                # builds need it (Homebrew equivalent on macOS, matches the "brew
                # install cpu_features" step in CLAUDE.md). On x86 Linux HEXL's
                # CMakeLists (find_package(CpuFeatures CONFIG)) would find this nix
                # package and skip its normal self-contained path
                # (hexl_create_archive(hexl cpu_features), which bundles cpu_features'
                # objects into libhexl.a) in favor of a bare target_link_libraries
                # against an external lib — which our plain-gcc Makefile link line
                # never references, so the final link fails with
                # "undefined reference to GetX86Info". Leaving this package out lets
                # HEXL fall back to its documented x86 flow: git-clone+build its own
                # vendored cpu_features and bundle it directly into libhexl.a.
                # Only add this back if this flake starts targeting aarch64.

                clang-tools # clang-format, matches .clang-format style
              ]
              ++ lib.optionals stdenv.isLinux [
                valgrind # tests/valgrind-test (gated by VALGRIND in config.h)
              ];

            shellHook = ''
              echo "lazer devShell: gcc $(gcc --version | head -1), $(sage --version 2>/dev/null || echo sage-not-run), $(python3 --version)"
              ${pkgs.lib.optionalString isDarwin ''
                export DYLD_LIBRARY_PATH="$PWD:$DYLD_LIBRARY_PATH"
              ''}
              # nixpkgs' cmake is newer than the vendored third_party sub-builds
              # (HEXL's bundled cpu_features) declare support for; the Makefile
              # already passes this for macOS/Android (HEXL_CMAKE_ENV) but plain
              # Linux never needed it before nix's cmake got this new.
              export CMAKE_POLICY_VERSION_MINIMUM=3.5
              echo "Build: make        (liblazer.a + liblazer.so)"
              echo "Test:  make check"
              echo "Python bindings: cd python && make"
            '';
          };
        }
      );
}
