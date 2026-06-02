# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

lazer is a C library (with Python and Go bindings) for lattice-based zero-knowledge proofs. It implements the ABDLOP commitment scheme, the LNP family of proof systems for linear relations with norm bounds, and wraps the external LaBRADOR proof system. Demos in `demos/` (C) and `python/` reproduce results from the accompanying paper (blind signatures, Kyber1024 PoK, anonymous credentials, Swoosh NIKE proofs, aggregate signatures).

## Platform requirements (current, upstream)

As shipped, the library builds and runs on **Linux x86-64 with AVX2/AVX-512 and AES instruction set extensions**. It uses `-march=native` and assumes those extensions plus GMP, MPFR, and Intel HEXL. The default `config.h` sets `TARGET TARGET_AMD64`.

Toolchain: gcc >= 13.2, make >= 4.2, cmake >= 3.26, sagemath >= 10.2, python3 >= 3.10 (with dev headers + `cffi`).

## ARM port (Apple Silicon + Android/Termux)

**Goal:** build and run lazer's core library and Python bindings on ARM — Apple Silicon (arm64 macOS) and Android (aarch64, via Termux) — while keeping the x86 build working. ARM support is layered on through the existing `TARGET`/OS abstraction, keyed off `__aarch64__`/`__arm__` and `__ANDROID__` (C) and `uname -m`/`uname -o` (make); x86-64/glibc Linux is the unchanged default branch.

**Status:** the core C library (`liblazer.a`/`.so`) and the Python module build and run natively on both arm64 macOS and Android/Termux. **`make check` passes 25/25 on arm64 macOS** (sage-test runs; nothing skipped), matching x86. The Python demos run (`demo.py`, `anon_cred.py`, `kyber1024`, `blindsig`). LaBRADOR-based demos (`agg_sig.py`) remain out of scope on ARM. iOS is scaffolded (`_OS_IOS` branch) but not built.

**Scope decisions:** HEXL uses its built-in non-AVX native path (made to build, not optimized). LaBRADOR is dropped on ARM (x86-only `.S` NTT assembly in `src/labrador/`). Falcon uses its portable native-double FFT (`-DFALCON_FPNATIVE` only, no AVX2/FMA). The PRNG is set to SHAKE128 (see "Performance" below).

### Building

**arm64 macOS:**
```bash
brew install gmp mpfr cpu_features   # one-time
make                                 # liblazer.a + liblazer.so (arm64)
cd python && make                    # _lazer_cffi
```
**Android (Termux):**
```bash
pkg install clang make cmake binutils git unzip patch libgmp libmpfr libffi python
pip install cffi
make
cd python && make
```
No env vars needed — the Makefile auto-detects the platform (Homebrew paths + cmake flags on macOS; Termux prefix is already on the default paths). Tested: Apple clang 14 + cmake 4.1; Termux clang 21. To run a Python demo on macOS, `liblazer.so`'s install name is unqualified, so set `DYLD_LIBRARY_PATH=<repo root>` (on Linux/Android the rpath is honored automatically).

### ⚠️ Three latent-bug classes in the bignum code (the hard part)

lazer's multi-precision integer layer (`src/int.c`, `src/lazer-in2.h`'s `limbs_*` helpers) hit **three distinct bugs** on ARM, all producing *silently wrong arithmetic* (not crashes): wrong modular reductions → either the prover's rejection/norm checks never pass (it loops forever) or proofs fail to verify. They're caught by `int-test`/`poly-test`/`abdlop-test` — **always run `make check` after touching this code or changing compiler/opt flags.** The first two were caught only with the right test; #3 needed a >64-bit-modulus parameter set (`abdlop-params2`).

1. **`__builtin_addcll`/`__builtin_subcll` carry chain** — miscompiled by Apple clang at `-O2`/`-O3` (drops the inter-limb borrow). The iOS branch originally used these. Fixed by using `unsigned __int128` for the carry/borrow on all non-`TARGET_AMD64` targets. **Do not reintroduce the `__builtin_*cll` builtins.**
2. **Strict-aliasing UB** — `limb_t` is `uint64_t`, which is `unsigned long long` on Apple arm64 but `unsigned long` on **LP64 Linux/Android**. The stores `(unsigned long long *)&r[i]` in `limbs_add`/`limbs_sub`/`limbs_to_twoscom` type-punned an `unsigned long` object on Linux aarch64 → UB that **clang 21 exploits at `-O2`/`-O3`** (failure point moves with the opt level — the classic UB tell). Apple clang 14 never saw it because the types coincide there. Fixed by storing through a real `unsigned long long` temp (also closes the same latent UB on x86). **Don't cast limb pointers between `unsigned long`/`unsigned long long`.**
3. **Non-normalised divisor to GMP** — `int_mod` passed `m->nlimbs` to `mpn_sec_div_r`, but `m` may carry leading zero limbs (a sub-2⁶⁴ modulus in a 2-limb `int_t`). `mpn_sec_*` requires a normalised divisor (top limb nonzero); the padded call is UB — benign on x86, but on arm64 it duplicated the low limb into the high one (result off by ~2⁶⁴). This only triggers with a **>64-bit modulus** (e.g. `abdlop-params2`, q≈2⁷⁶), corrupting the `dcompress` high-bits reduction and breaking ABDLOP/lnp-quad verification while the d=64/single-limb tests passed. Fixed by trimming `m` to its effective limb count before the `mpn` call and zero-extending the remainder (as `int_div` already does via `bnlimbs`). **Any `mpn_sec_*` call must use the divisor's trimmed length, not the padded `int_t` `nlimbs`.**

### Other changes (all gated so x86/glibc Linux is untouched)

- [config.h](config.h) — `TARGET` is arch-conditional: `TARGET_GENERIC` on ARM, else `TARGET_AMD64`. Selects the portable AES-CTR ([src/aes256ctr.c](src/aes256ctr.c)) over AES-NI ([src/aes256ctr-amd64.c](src/aes256ctr-amd64.c)). Also `RNG RNG_SHAKE128` (see Performance).
- [src/lazer-in2.h](src/lazer-in2.h) — the second `immintrin.h` include re-gated on `TARGET == TARGET_AMD64` (was `#ifndef _OS_IOS`, fired on arm64 macOS). Under `__ANDROID__`, include `<strings.h>` + `<sys/random.h>` and `#define explicit_bzero bzero` (Bionic puts `explicit_bzero` in `<strings.h>` and `getentropy` in `<sys/random.h>`, unlike glibc).
- [Makefile](Makefile) — detects `ARCH_ARM`/`OS_MACOS`/`OS_ANDROID`. ARM: Falcon `-DFALCON_FPNATIVE` only, `-march=native`→`-mcpu=native`, LaBRADOR + `valgrind-test` excluded. C++ runtime: `-lstdc++` (glibc) / `-lc++` (macOS) / `-lc++_shared` (Termux). `hexl.cpp` always `-std=c++17`. HEXL static lib found under `lib/` or `lib64/`. macOS: Homebrew `-I`/`-L`, self-contained `liblazer.so` link (macOS dylibs can't carry undefined symbols; Linux/Android can), and HEXL cmake gets `-DCMAKE_PREFIX_PATH=$(brew --prefix)` + `CMAKE_POLICY_VERSION_MINIMUM=3.5`.
- [src/hexl.patch](src/hexl.patch) — applied after unzip (like `falcon.patch`). HEXL's `cpu-features.hpp` and three `*-avx512` util headers `#include <immintrin.h>` unconditionally and get pulled into HEXL's *native* TUs; the patch arch-guards those includes and forces `has_avx512* = false` on non-x86. The AVX512 `.cpp` files are already CMake-gated on `HEXL_HAS_AVX512DQ` (off on ARM). **This patch is the durable home for the HEXL fix — never hand-edit the unzipped `third_party/hexl-development/` tree; `make`/`make clean` re-unzips and discards edits.** On macOS the bundled 2021 `cpu_features` lacks Apple Silicon support (hence Homebrew's); on aarch64 Linux/Android the bundled one builds.
- [python/lazer_cffi_build.py](python/lazer_cffi_build.py) — C++ runtime is platform-aware: `c++` (macOS), `c++_shared` (Android/Termux, detected via `ANDROID_ROOT`/`PREFIX`), `stdc++` (glibc). On Termux there is no `libc++.so`, only `libc++_shared.so`, so linking `c++` produces a module that fails to load. (`params_cffi_build.py` links no C++ libs, so it needs no change.)

### Performance note (ARM)
lazer's generic C AES (`TARGET_GENERIC`) is **pathologically slow** — on ARM, `RNG_AES256CTR` made `anon_cred` ~40–70× slower than `RNG_SHAKE128`, because the whole runtime was software AES. `config.h` is therefore set to `RNG_SHAKE128` on this branch. A future option is a NEON hardware-AES backend (ARMv8 `vaeseq_u8`), which all Apple Silicon and arm64 Android SoCs support, to keep AES as the RNG at speed. Note `config.h`'s `RNG` is global (not arch-conditional) — x86 with AES-NI prefers `RNG_AES256CTR`.

### Not yet done
- `make check` on Android/Termux (passes 25/25 on arm64 macOS; not yet run end-to-end on Termux).
- iOS build (cross-compile `liblazer.a` against the SDK; `_OS_IOS` header branch exists).
- NEON hardware AES; HEXL/Falcon ARM vectorization (left on the portable path).

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
- **ARM (arm64 macOS / Android-Termux):** install the native deps first, then plain `make` works — see the "ARM port" section above for the exact dependency list and notes.

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
