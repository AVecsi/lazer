/* Compile the anonymous-credentials C implementation into this cgo package.
 * (anoncred.c is not part of liblazer.a's unity build.) Resolved via the
 * -I${SRCDIR}/../../src include path set in lazer.go. */
#include "anoncred.c"
