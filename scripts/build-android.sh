#!/usr/bin/env bash
#
# Cross-compile the lazer native stack for Android and stage it for gomobile.
#
# Produces, per ABI, the four static libs the cgo binding links against plus the
# GMP/MPFR headers it includes:
#
#   <lazer>/android/<abi>/lib/{liblazer,libhexl,libmpfr,libgmp}.a
#   <lazer>/android/<abi>/include/{gmp.h,mpfr.h}
#
# This is the C/C++ analogue of pq-gabi's `make build-android` (which is pure
# cargo). Unlike Rust, the lazer stack needs GMP + MPFR (autotools) and HEXL
# (cmake) cross-built with the Android NDK before liblazer itself.
#
# Usage:
#   scripts/build-android.sh [--targets android/arm64] [--api 26]
#
# Only android/arm64 (arm64-v8a) is supported today; other targets are skipped
# with a warning. Re-running is cheap: each library is skipped if already staged
# (use --force / `make clean`-style removal of android/ to rebuild).
set -euo pipefail

ROOT=$(cd "$(dirname "$(realpath "$0")")/.." && pwd) # lazer repo root
cd "$ROOT"

# ── defaults / args ───────────────────────────────────────────────────────────
TARGETS="android/arm64"
ANDROIDAPI=26
FORCE=0
GMP_VER=6.3.0
MPFR_VER=4.2.2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets) TARGETS="$2"; shift 2 ;;
    --api)     ANDROIDAPI="$2"; shift 2 ;;
    --force)   FORCE=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; exit 1 ;;
  esac
done

log() { echo "[lazer-android] $*"; }

# ── locate the NDK ────────────────────────────────────────────────────────────
find_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
    echo "$ANDROID_NDK_HOME"; return
  fi
  local root
  for root in "${ANDROID_NDK_ROOT:-}" "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" \
              "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [[ -n "$root" && -d "$root/ndk" ]] || continue
    local v; v=$(ls -1 "$root/ndk" | sort -V | tail -1)
    [[ -n "$v" ]] && { echo "$root/ndk/$v"; return; }
  done
  echo ""
}

NDK=$(find_ndk)
if [[ -z "$NDK" ]]; then
  echo "error: Android NDK not found. Set ANDROID_NDK_HOME or install it under the SDK." >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) NDK_HOST=darwin-x86_64 ;;
  Linux)  NDK_HOST=linux-x86_64 ;;
  *) echo "error: unsupported build host $(uname -s)" >&2; exit 1 ;;
esac
TC="$NDK/toolchains/llvm/prebuilt/$NDK_HOST/bin"
[[ -d "$TC" ]] || { echo "error: NDK toolchain not at $TC" >&2; exit 1; }
log "NDK: $NDK (host $NDK_HOST)"

JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
BUILD="$ROOT/build-android"
DL="$BUILD/download"
mkdir -p "$DL"

# ── per-ABI build ─────────────────────────────────────────────────────────────
# Map gomobile target -> (abi, autotools host triple, clang target prefix)
abi_triple() {
  case "$1" in
    android/arm64) echo "arm64-v8a aarch64-linux-android aarch64-linux-android" ;;
    *) return 1 ;;
  esac
}

fetch() { # url dest
  [[ -f "$2" ]] && return 0
  log "download $(basename "$2")"
  curl -fL --retry 3 -o "$2" "$1"
}

build_abi() {
  local target="$1" abi triple clangpfx
  read -r abi triple clangpfx <<<"$(abi_triple "$target")"

  local STAGE="$ROOT/android/$abi"
  local PREFIX="$STAGE"            # gmp/mpfr install here (include/, lib/)
  local OBJ="$BUILD/$abi/obj"
  mkdir -p "$PREFIX/lib" "$PREFIX/include" "$OBJ"

  local CC="$TC/${clangpfx}${ANDROIDAPI}-clang"
  local CXX="$TC/${clangpfx}${ANDROIDAPI}-clang++"
  local AR="$TC/llvm-ar"
  local RANLIB="$TC/llvm-ranlib"
  local STRIP="$TC/llvm-strip"

  log "=== $abi (api $ANDROIDAPI) ==="

  # ---- GMP -------------------------------------------------------------------
  if [[ $FORCE -eq 1 || ! -f "$PREFIX/lib/libgmp.a" ]]; then
    fetch "https://ftp.gnu.org/gnu/gmp/gmp-$GMP_VER.tar.xz" "$DL/gmp-$GMP_VER.tar.xz"
    rm -rf "$BUILD/$abi/gmp-$GMP_VER"
    tar -C "$BUILD/$abi" -xf "$DL/gmp-$GMP_VER.tar.xz"
    ( cd "$BUILD/$abi/gmp-$GMP_VER"
      ./configure --host="$triple" --prefix="$PREFIX" \
        --enable-static --disable-shared \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP"
      make -j"$JOBS"
      make install )
    log "GMP staged: $PREFIX/lib/libgmp.a"
  else
    log "GMP: already staged (skip)"
  fi

  # ---- MPFR ------------------------------------------------------------------
  if [[ $FORCE -eq 1 || ! -f "$PREFIX/lib/libmpfr.a" ]]; then
    fetch "https://ftp.gnu.org/gnu/mpfr/mpfr-$MPFR_VER.tar.xz" "$DL/mpfr-$MPFR_VER.tar.xz"
    rm -rf "$BUILD/$abi/mpfr-$MPFR_VER"
    tar -C "$BUILD/$abi" -xf "$DL/mpfr-$MPFR_VER.tar.xz"
    ( cd "$BUILD/$abi/mpfr-$MPFR_VER"
      ./configure --host="$triple" --prefix="$PREFIX" \
        --with-gmp="$PREFIX" --enable-static --disable-shared \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP"
      make -j"$JOBS"
      make install )
    log "MPFR staged: $PREFIX/lib/libmpfr.a"
  else
    log "MPFR: already staged (skip)"
  fi

  # ---- HEXL (cmake, NDK android toolchain) -----------------------------------
  # Reuse the already-unzipped + patched host source tree; separate build dir.
  local HEXL_SRC="$ROOT/third_party/hexl-development"
  local HEXL_BUILD="$BUILD/$abi/hexl"
  [[ -d "$HEXL_SRC" ]] || { echo "error: HEXL source missing ($HEXL_SRC); run host 'make' once first" >&2; exit 1; }
  if [[ $FORCE -eq 1 || ! -f "$PREFIX/lib/libhexl.a" ]]; then
    # HEXL's hexl_create_archive() bundles libcpu_features.a into libhexl.a with
    # a POST_BUILD step that calls a hardcoded `ar` (not ${CMAKE_AR}). On a macOS
    # host that resolves to BSD ar, which cannot read the GNU/LLVM-format cross
    # archives and corrupts them. Shim `ar`/`ranlib` -> the NDK llvm tools on PATH
    # so that literal `ar` becomes llvm-ar for the whole HEXL build.
    local SHIM="$BUILD/$abi/arshim"
    mkdir -p "$SHIM"
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$AR" > "$SHIM/ar"
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$RANLIB" > "$SHIM/ranlib"
    chmod +x "$SHIM/ar" "$SHIM/ranlib"

    rm -rf "$HEXL_BUILD"   # start clean: a prior failed merge can leave stray .o
    PATH="$SHIM:$PATH" CMAKE_POLICY_VERSION_MINIMUM=3.5 cmake -S "$HEXL_SRC" -B "$HEXL_BUILD" \
      -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$ANDROIDAPI" \
      -DCMAKE_BUILD_TYPE=Release \
      -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DHEXL_SHARED_LIB=OFF \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    PATH="$SHIM:$PATH" CMAKE_POLICY_VERSION_MINIMUM=3.5 cmake --build "$HEXL_BUILD" -j"$JOBS"
    local hexllib
    hexllib=$(find "$HEXL_BUILD" -name libhexl.a | head -1)
    [[ -n "$hexllib" ]] || { echo "error: libhexl.a not produced" >&2; exit 1; }
    cp "$hexllib" "$PREFIX/lib/libhexl.a"
    log "HEXL staged: $PREFIX/lib/libhexl.a"
  else
    log "HEXL: already staged (skip)"
  fi

  # ---- liblazer.a ------------------------------------------------------------
  # Mirror the Makefile's liblazer.a recipe (ARM path: portable Falcon FFT, no
  # LaBRADOR, no -march=native), compiled straight into a scratch dir so the
  # host artifacts in the tree are never clobbered.
  if [[ $FORCE -eq 1 || ! -f "$PREFIX/lib/liblazer.a" ]]; then
    [[ -f "$ROOT/lazer.h" ]] || ( cd "$ROOT" && make lazer.h )
    local FALCON="$ROOT/third_party/Falcon-impl-20211101"
    local HEXL_INC="$HEXL_SRC/hexl/include"
    local CFLAGS="-O3 -g -Wall -Wextra -fomit-frame-pointer -DNDEBUG -DFALCON_FPNATIVE"
    local INC="-I$ROOT -I$FALCON -I$PREFIX/include"
    local objs=()

    log "compiling Falcon (portable) ..."
    local f
    for f in codec common falcon fft fpr keygen rng shake sign vrfy; do
      "$CC" $CFLAGS -I"$FALCON" -c -o "$OBJ/falcon_$f.o" "$FALCON/$f.c"
      objs+=("$OBJ/falcon_$f.o")
    done

    log "compiling lazer unity TU ..."
    "$CC" $CFLAGS $INC -c -o "$OBJ/lazer.o" "$ROOT/src/lazer.c"
    objs+=("$OBJ/lazer.o")

    log "compiling HEXL glue (C++17) ..."
    "$CXX" $CFLAGS -std=c++17 -I"$ROOT/src" -I"$HEXL_INC" -I"$PREFIX/include" \
      -c -o "$OBJ/hexl.o" "$ROOT/src/hexl.cpp"
    objs+=("$OBJ/hexl.o")

    rm -f "$PREFIX/lib/liblazer.a"
    "$AR" rcs "$PREFIX/lib/liblazer.a" "${objs[@]}"
    log "liblazer staged: $PREFIX/lib/liblazer.a"
  else
    log "liblazer: already staged (skip)"
  fi

  # ---- verify ----------------------------------------------------------------
  local missing=0 l
  for l in liblazer.a libhexl.a libmpfr.a libgmp.a; do
    [[ -f "$PREFIX/lib/$l" ]] || { echo "[lazer-android] MISSING $abi/lib/$l" >&2; missing=1; }
  done
  for h in gmp.h mpfr.h; do
    [[ -f "$PREFIX/include/$h" ]] || { echo "[lazer-android] MISSING $abi/include/$h" >&2; missing=1; }
  done
  [[ $missing -eq 0 ]] || exit 1
  log "OK: $abi complete -> $PREFIX"
}

IFS=',' read -ra _targets <<<"$TARGETS"
built_any=0
for t in "${_targets[@]}"; do
  if abi_triple "$t" >/dev/null 2>&1; then
    build_abi "$t"; built_any=1
  else
    log "skip unsupported target '$t' (only android/arm64 is implemented)"
  fi
done
[[ $built_any -eq 1 ]] || { echo "error: no supported targets in '$TARGETS'" >&2; exit 1; }
log "done."
