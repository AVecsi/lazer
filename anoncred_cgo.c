/* The anonymous-credential implementation is deliberately NOT part of
 * liblazer.a's unity build (see Makefile: "anoncred is not part of liblazer.a's
 * unity build, so compile src/anoncred.c directly"). The Go binding therefore
 * pulls it into the cgo package here, so anoncred_keygen()/anoncred_* land in
 * the built object for every target (host and Android) without depending on
 * liblazer.a.
 *
 * cgo compiles this TU with the package #cgo CFLAGS, i.e. at -O2, which is
 * REQUIRED for anoncred correctness (see the note in lazer_binding.go).
 * src/anoncred.c is found via the package's -I${SRCDIR}/src. */
#include "anoncred.c"
