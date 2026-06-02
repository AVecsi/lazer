/*
 * TARGET: GENERIC, AMD64
 * Architecture target.
 * Auto-selected by architecture: ARM (arm64/arm) uses the portable
 * GENERIC path; x86-64 keeps the AVX/AES AMD64 path. Define TARGET
 * before including/concatenating this file to override.
 */
#ifndef TARGET
#if defined(__aarch64__) || defined(__arm__) || defined(_M_ARM64)
#define TARGET TARGET_GENERIC
#else
#define TARGET TARGET_AMD64
#endif
#endif

/*
 * RNG: SHAKE128, AES256CTR
 * Use Shake128 or AES-256-CTR for pseudorandom generation.
 */
#define RNG RNG_SHAKE128

/*
 * ASSERT: ENABLED, DISABLED
 * Enable or diasble assertions.
 */
#define ASSERT ASSERT_DISABLED

/*
 * TIMERS: ENABLED, DISABLED
 * Run timers and print the results.
 */
#define TIMERS TIMERS_DISABLED

/*
 * DEBUGINFO: ENABLED, DISABLED
 * Print out debug information.
 */
#define DEBUGINFO DEBUGINFO_DISABLED

/*
 * VALGRIND: ENABLED, DISABLED
 * Build and run valgrind tests.
 * Requires valgrind installation.
 * Requires ASSERT_DISABLED
 */
#define VALGRIND VALGRIND_DISABLED
