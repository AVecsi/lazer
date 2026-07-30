package lazer

/*
#include "fdb.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// Falcon device binding (Go binding of src/fdb.h).
//
// A signer holding a Falcon-512 keypair first ISSUES a credential: the
// commitment t_h = AR*rc + AM*h to its public key h, under fresh secret
// randomness rc. The verifier stores that credential. Afterwards the signer
// can, for any message the verifier picks, produce a zero-knowledge proof that
// it holds a valid Falcon signature under the key COMMITTED in the credential,
// revealing neither the key, the signature, nor rc. The verifier only learns
// accept/reject.
//
// All data crossing the boundary is bytes: the credential at issuance, and the
// (salt, proof) pair per signature. The verifier recomputes the Falcon
// challenge c = HashToPoint(salt||msg) itself, which is what binds a proof to
// one message; a proof does not verify under another message, nor against
// another credential.

const FdbPubkeyLen = 897       // FDB_PUBKEYLEN
const FdbPrivkeyLen = 1281     // FDB_PRIVKEYLEN
const FdbSaltLen = 40          // FDB_SALT_BYTES
const FdbProofLenMax = 1048576 // FDB_PROOF_MAXLEN
const FdbCredLenMax = 8192     // FDB_CRED_MAXLEN

type FdbSignerState struct{ c *C.fdb_signer_state_struct }
type FdbVerifierState struct{ c *C.fdb_verifier_state_struct }

// FdbKeygen returns a Falcon-512 (secret, public) key pair.
func FdbKeygen() (sk []byte, pk []byte) {
	_sk := C.malloc(C.size_t(FdbPrivkeyLen))
	_pk := C.malloc(C.size_t(FdbPubkeyLen))
	C.fdb_keygen((*C.uint8_t)(_sk), (*C.uint8_t)(_pk))
	sk = C.GoBytes(_sk, C.int(FdbPrivkeyLen))
	pk = C.GoBytes(_pk, C.int(FdbPubkeyLen))
	C.free(_sk)
	C.free(_pk)
	return
}

// FdbSignerInit initializes a signer holding the keypair (sk, pk). seed is the
// PUBLIC 32-byte setup seed shared with the verifier (it expands to the
// commitment matrices and AR/AM); it is not secret and is never used as prover
// randomness.
func FdbSignerInit(seed []byte, sk []byte, pk []byte) (st FdbSignerState) {
	if len(seed) != 32 {
		panic("FdbSignerInit: len(seed) != 32")
	}
	if len(sk) != FdbPrivkeyLen {
		panic("FdbSignerInit: bad private key length")
	}
	if len(pk) != FdbPubkeyLen {
		panic("FdbSignerInit: bad public key length")
	}
	_seed := C.CBytes(seed)
	_sk := C.CBytes(sk)
	_pk := C.CBytes(pk)
	st.c = (*C.fdb_signer_state_struct)(C.malloc(C.sizeof_fdb_signer_state_struct))
	C.fdb_signer_init(st.c, (*C.uint8_t)(_seed), (*C.uint8_t)(_sk), (*C.uint8_t)(_pk))
	C.free(_seed)
	C.free(_sk)
	C.free(_pk)
	return
}

func FdbSignerClear(st *FdbSignerState) {
	C.fdb_signer_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// FdbSignerIssue samples fresh secret randomness rc and returns the serialized
// credential t_h = AR*rc + AM*h committing to the signer's public key. rc is
// kept in the signer state and enters every later proof's witness, so a second
// call invalidates credentials issued before it.
func FdbSignerIssue(st *FdbSignerState) []byte {
	_cred := C.malloc(C.size_t(C.FDB_CRED_MAXLEN))
	_len := C.malloc(C.sizeof_size_t)
	rc := C.fdb_signer_issue(st.c, (*C.uint8_t)(_cred), (*C.size_t)(_len))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_cred, C.int(*(*C.size_t)(_len)))
	}
	C.free(_cred)
	C.free(_len)
	return out
}

// FdbSignerProve blackbox-signs msg (a fresh salt is sampled and the Falcon
// challenge derived from it internally) and proves in zero knowledge that the
// signature is valid under the key committed by the last FdbSignerIssue.
// Requires a prior FdbSignerIssue. Returns (1, salt, proof) on success,
// (0, nil, nil) on failure (including when nothing has been issued yet).
func FdbSignerProve(st *FdbSignerState, msg []byte) (int, []byte, []byte) {
	_proof := C.malloc(C.size_t(C.FDB_PROOF_MAXLEN))
	_len := C.malloc(C.sizeof_size_t)
	_salt := C.malloc(C.size_t(FdbSaltLen))
	_msg := C.CBytes(msg)
	rc := C.fdb_signer_prove(st.c, (*C.uint8_t)(_proof), (*C.size_t)(_len),
		(*C.uint8_t)(_salt), (*C.uint8_t)(_msg), C.size_t(len(msg)))
	var salt, proof []byte
	if rc == 1 {
		salt = C.GoBytes(_salt, C.int(FdbSaltLen))
		proof = C.GoBytes(_proof, C.int(*(*C.size_t)(_len)))
	}
	C.free(_proof)
	C.free(_len)
	C.free(_salt)
	C.free(_msg)
	return int(rc), salt, proof
}

// FdbVerifierInit initializes a verifier from the same public setup seed as the
// signer. The state holds public data only.
func FdbVerifierInit(seed []byte) (st FdbVerifierState) {
	if len(seed) != 32 {
		panic("FdbVerifierInit: len(seed) != 32")
	}
	_seed := C.CBytes(seed)
	st.c = (*C.fdb_verifier_state_struct)(C.malloc(C.sizeof_fdb_verifier_state_struct))
	C.fdb_verifier_init(st.c, (*C.uint8_t)(_seed))
	C.free(_seed)
	return
}

func FdbVerifierClear(st *FdbVerifierState) {
	C.fdb_verifier_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// FdbVerifierSetCredential stores the credential received at issuance. Must be
// called before FdbVerifierVrfy. Returns 1 on success, 0 on a malformed
// credential.
func FdbVerifierSetCredential(st *FdbVerifierState, cred []byte) int {
	_cred := C.CBytes(cred)
	rc := C.fdb_verifier_set_credential(st.c, (*C.uint8_t)(_cred), C.size_t(len(cred)))
	C.free(_cred)
	return int(rc)
}

// FdbVerifierVrfy verifies a proof for msg with the salt the signer returned,
// against the stored credential. Requires a prior FdbVerifierSetCredential
// (returns 0 without one). Returns 1 if valid, 0 otherwise.
func FdbVerifierVrfy(st *FdbVerifierState, proof []byte, msg []byte, salt []byte) int {
	if len(salt) != FdbSaltLen {
		return 0
	}
	_proof := C.CBytes(proof)
	_msg := C.CBytes(msg)
	_salt := C.CBytes(salt)
	rc := C.fdb_verifier_vrfy(st.c, (*C.uint8_t)(_proof), C.size_t(len(proof)),
		(*C.uint8_t)(_msg), C.size_t(len(msg)), (*C.uint8_t)(_salt))
	C.free(_proof)
	C.free(_msg)
	C.free(_salt)
	return int(rc)
}
