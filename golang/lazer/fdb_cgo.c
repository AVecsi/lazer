/* Compile the Falcon device-binding C implementation into this cgo package.
 * (fdb.c is not part of liblazer.a's unity build.) Resolved via the
 * -I${SRCDIR}/../../src include path set in lazer.go. */
#include "fdb.c"
