# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

lazer is a C library (with Python and Go bindings) for lattice-based zero-knowledge proofs. It implements the ABDLOP commitment scheme, the LNP family of proof systems for linear relations with norm bounds, and wraps the external LaBRADOR proof system. Demos in `demos/` (C) and `python/` reproduce results from the accompanying paper (blind signatures, Kyber1024 PoK, anonymous credentials, Swoosh NIKE proofs, aggregate signatures).

## Platform requirements (current, upstream)

As shipped, the library builds and runs on **Linux x86-64 with AVX2/AVX-512 and AES instruction set extensions**. It uses `-march=native` and assumes those extensions plus GMP, MPFR, and Intel HEXL. The default `config.h` sets `TARGET TARGET_AMD64`.

Toolchain: gcc >= 13.2, make >= 4.2, cmake >= 3.26, sagemath >= 10.2, python3 >= 3.10 (with dev headers + `cffi`).

## ARM port (mobile + Apple Silicon)

**Goal:** build and run lazer's core library on ARM (Apple Silicon arm64 macOS, and mobile iOS/Android arm64) while keeping the x86 build working. ARM support is layered on through the existing `TARGET`/OS abstraction, keyed off `__aarch64__`/`__arm__` (C) and `uname -m` (make), with x86-64 unchanged as the default branch.

**Status — Phase 1 done (arm64 macOS core build).** A plain `make` on Apple Silicon produces native arm64 `liblazer.a` and `liblazer.so`. Individual smoke tests pass (`lazer-test`, `int-test`, `rng-test`, `poly-test`, `intvec-test`); a full `make check` run has not yet been completed end-to-end. Remaining: Python bindings on arm64 macOS (Phase 3), mobile cross-compilation (Phase 4).

**Scope decisions:** HEXL uses its built-in non-AVX native fallback (not ported/optimized, only made to build). LaBRADOR is dropped on ARM (x86-only `.S` NTT assembly in `src/labrador/`); the `agg_sig.py`/`labrador.py` demos are out of scope there. Falcon uses its portable native-double FFT (`-DFALCON_FPNATIVE` only, no AVX2/FMA).

### Building on arm64 macOS

```bash
brew install gmp mpfr cpu_features   # one-time native deps
make                                 # produces liblazer.a + liblazer.so (arm64)
```

No env vars needed — the Makefile auto-detects arm64 macOS and handles Homebrew paths, cmake flags, and the HEXL patch. (Tested on Apple clang 14, cmake 4.1, Homebrew at `/opt/homebrew`.)

### Changes that made it work (all gated so x86/Linux is untouched)

- [config.h](config.h) — `TARGET` is now arch-conditional: `TARGET_GENERIC` on `__aarch64__`/`__arm__`, else `TARGET_AMD64`. This master switch selects the portable AES-CTR path ([src/aes256ctr.c](src/aes256ctr.c), validated by `rng-test`) and disables the AES-NI path ([src/aes256ctr-amd64.c](src/aes256ctr-amd64.c)).
- [src/lazer-in2.h](src/lazer-in2.h) — (1) the second `immintrin.h`/`x86intrin.h` include is now gated on `TARGET == TARGET_AMD64` (was `#ifndef _OS_IOS`, which still fired on arm64 macOS). (2) `_addcarry_u64_`/`_subborrow_u64_` use the x86 intrinsics only on `TARGET_AMD64`; **all other targets now use `unsigned __int128`**, not `__builtin_addcll`/`__builtin_subcll`. ⚠️ The `__builtin_*cll` carry-chain builtins are **miscompiled by Apple clang 14 on arm64 at -O2/-O3** (correct at -O0/-O1) — they silently drop the inter-limb borrow, corrupting all multi-limb integer arithmetic. `int-test` catches this. Do not reintroduce them.
- [Makefile](Makefile) — arch/OS detection at the top sets `ARCH_ARM`/`OS_MACOS`. On ARM: Falcon flags drop to `-DFALCON_FPNATIVE`, `-march=native` → `-mcpu=native`, C++ runtime `-lstdc++` → `-lc++`, LaBRADOR `.so`s and `valgrind-test` are excluded. On macOS it also adds Homebrew `-I`/`-L`, the HEXL static lib is found under `lib/` or `lib64/`, `hexl.cpp` is compiled with `-std=c++17` (Apple clang doesn't default to it; gcc 13 does), and `liblazer.so` is linked self-contained (macOS dylibs can't carry undefined symbols — Linux `.so`s can, so this is macOS-only).
- [src/hexl.patch](src/hexl.patch) — applied to the HEXL tree right after unzip (like `falcon.patch`). HEXL's `cpu-features.hpp` and three `*-avx512`/util headers `#include <immintrin.h>` unconditionally and get pulled into HEXL's *native* TUs; the patch arch-guards those includes and forces `has_avx512* = false` on non-x86, so HEXL builds entirely on its native path. The AVX512 `.cpp` files are already CMake-gated on `HEXL_HAS_AVX512DQ` (off on ARM), so they aren't compiled. **This patch is the durable home for the HEXL fix — never hand-edit the unzipped `third_party/hexl-development/` tree, since `make`/`make clean` re-unzips and discards edits.**
- HEXL build, macOS specifics (in the `$(HEXL_DIR)` Makefile rule): cmake gets `-DCMAKE_PREFIX_PATH=$(brew --prefix)` so `find_package(CpuFeatures)` finds Homebrew's modern `cpu_features` instead of HEXL's bundled 2021 version (which has no Apple Silicon support and fails to build), and `CMAKE_POLICY_VERSION_MINIMUM=3.5` so cmake ≥ 4 will configure HEXL's old-minimum sub-builds.

### Not yet done
- **Python bindings (Phase 3):** [python/lazer_cffi_build.py](python/lazer_cffi_build.py) still lists `stdc++` (needs `c++` on macOS) and a fixed hexl lib dir; [python/params_cffi_build.py](python/params_cffi_build.py) inherits the same. LaBRADOR `.so` auto-detection is already conditional, so it no-ops on ARM.
- **Mobile (Phase 4):** iOS/Android consume `liblazer.a` via the C API directly (the cffi layer is desktop-only). The `_OS_IOS` branch in `src/lazer-in2.h` already handles iOS endian/`bzero`. A mobile build is a separate cross-compilation against the platform SDK, not the in-repo Makefile as-is.
- **Full `make check`** has not been run to completion on arm64 macOS.

## Build commands

```bash
make all        # builds lazer.h, static + shared libs (liblazer + liblabrador{24,32,40,48}; no labrador on ARM)
make            # default target: liblazer.a + liblazer.so only
make build=debug ...   # -Og -ggdb3 instead of the optimized arch flags
make check      # build and run the C test suite (cd tests && ./run-tests)
make clean
```

- `make -j` parallelizes compilation.
- On first build, the Makefile unzips `third_party/Falcon-impl-20211101.zip` (applying `src/falcon.patch`) and `third_party/hexl-development.zip` (applying `src/hexl.patch`, then cmake-built). On x86 it also clones Google `cpu_features` from GitHub for HEXL (internet required); on macOS it uses Homebrew's `cpu_features` instead (see the ARM section).
- `liblabrador` is built once per modulus bit-width as a separate `.so` (`LOGQ` = 24/32/40/48); LaBRADOR lives in the `src/labrador` git submodule. **Not built on ARM.**
- **arm64 macOS:** `brew install gmp mpfr cpu_features` first; then plain `make` works (see the ARM port section above).

Python module (after the C library is built):
```bash
cd python && make        # runs lazer_cffi_build.py -> _lazer_cffi via cffi
```

Documentation:
```bash
cd docs && make html     # Sphinx; requires sphinx >= 5.3 + sphinxcontrib-bibtex
```

## Running a single C test

Each test is its own executable built from `tests/<name>-test.c`, linked against `liblazer.a`:
```bash
make tests/lnp-tbox-test   # build one test
./tests/lnp-tbox-test      # run it directly
```
`tests/run-tests` (invoked by `make check`) runs them all and reports pass/skip/fail using automake exit codes (0=pass, 77=skip, 1=fail, 99=error).

## Running demos

C demos (`demos/<name>/`): `cd demos/<name> && make && ./<name>-demo`.

Python demos (`python/<name>/`): `cd python/<name> && make && python3 <name>.py`. `agg_sig.py` (LaBRADOR aggregate signature) runs directly from `python/`.

## Architecture

### Unity build
`src/lazer.c` `#include`s every other `src/*.c` file and is the **only** translation unit compiled into `liblazer` (see `src/lazer_static.o`/`src/lazer_shared.o` rules in the Makefile). When adding a new `.c` file to the core library, add it to both the `#include` list in `src/lazer.c` and to `LIBSOURCES` in the Makefile.

### The public header is generated
`lazer.h` (large, gitignored, regenerated by the `lazer.h:` Makefile rule) is **assembled** by concatenating `src/lazer-in1.h`, `config.h`, `src/lazer-in2.h`, and `src/moduli.h`. Never edit `lazer.h` directly — edit the `src/lazer-in*.h` sources. Build-time options live in `config.h` (`TARGET`, `RNG` = SHAKE128 or AES256CTR, `ASSERT`, `TIMERS`, `DEBUGINFO`, `VALGRIND`).

### Layered design (low → high)
1. **Arithmetic primitives**: `int.c`, `intvec.c`, `intmat.c` (multi-precision constant-time ints via GMP), and the polynomial-ring layer `polyring.c`, `poly.c`, `polyvec.c`, `polymat.c`. `spolymat.c`/`spolyvec.c` are sparse variants. Rings are `Rp = Zp[X]/(X^d + 1)`; NTT/multiplication is offloaded to Intel HEXL via `src/hexl.cpp`.
2. **Sampling & coding**: `urandom.c` (uniform), `brandom.c` (binomial/bounded), `grandom.c` (Gaussian), `rejection.c` (rejection sampling, uses MPFR), `coder.c` (proof serialization), `dcompress.c` (decomposition/compression), `shake128.c` / `aes256ctr*.c` / `rng.c` (PRNGs).
3. **Commitment**: `abdlop.c` — the ABDLOP commitment scheme; parameters are `abdlop_params_t`.
4. **Proof systems** (each builds on the layer below, reflected in the nested `*_params` structs in `src/lazer-in2.h`): `lnp-quad.c` and `lnp-quad-many.c` (quadratic relations), `lnp-quad-eval.c` (quadratic-eval), `lnp-tbox.c` (the "toolbox" proof combining norm proofs — top of the LNP stack), and `lin-proofs.c` (the high-level linear-relation prover/verifier exposed to demos).
5. **LaBRADOR** (`src/labrador` submodule): a separate recursive proof system with its own `.so` per modulus size, wrapped for Python in `python/labrador.py`.

### Parameter generation (sage codegen)
Proof parameters are **not** hand-written. A specification is a Python file (`*params.py` / `*-params.py`) describing the ring, dimensions, partitions of the witness, and norm bounds (see `python/demo/demo_params.py` for the canonical example). A sagemath code generator turns it into a C header:
```bash
cd scripts && sage lin-codegen.sage <spec.py> > <out_params.h>
```
Codegen scripts: `lin-codegen.sage` (linear relations), `abdlop-codegen.sage`, `lnp-quad-codegen.sage`, `lnp-quad-eval-codegen.sage`, `lnp-tbox-codegen.sage`, `moduli.sage` (generates `src/moduli.h`). These call the lattice-estimator repeatedly and can take **minutes** for large parameter sets (e.g. Swoosh). Generated `*params.h` files are committed so codegen only re-runs when the spec changes or the header is deleted (the per-demo Makefiles encode this dependency).

### Bindings
- **Python**: `python/lazer.py` is a hand-written object-oriented wrapper (`poly_t`, `polyvec_t`, `polymat_t`, `lin_prover_state_t`, `lin_verifier_state_t`, …) over the cffi-generated `_lazer_cffi`. Per-demo parameter headers are compiled into their own cffi modules via `python/params_cffi_build.py`. `python/labrador.py` wraps the LaBRADOR `.so`s.
- **Go**: `golang/lazer/lazer.go` (module in `golang/`), with `golang/demo.go`.

## Conventions

- C style is enforced by `.clang-format` (GNU-ish: 2-space indent, braces on own lines). Match it.
- Types follow a strict pattern: for a struct `foo_struct` there are `foo_t` (array-of-1, for stack allocation by value), `foo_ptr`, and `foo_srcptr` (const) typedefs. Functions take the `_t`/`_ptr` forms.
- The library targets constant-time behavior for secret-dependent operations; `make check` includes a valgrind-based test (`tests/valgrind-test`, gated by `VALGRIND` in `config.h`, which requires `ASSERT_DISABLED`).
- `src/*XXX*` files (e.g. `lnp-tboxXXX.c`, `moduliXXX.h`) and `ntt.c`/`ntt.h` are not part of the unity build (`ntt` is commented out in both `lazer.c` and `LIBSOURCES`) — treat them as dormant/scratch unless wiring them in deliberately.
