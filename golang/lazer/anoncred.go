package lazer

/*
#include "anoncred.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// init allocates the HEXL NTT tables (hexl_ntt_d64/d128). Without this the
// NTT pointers are NULL and the first polyvec_mul dereferences NULL. It is
// idempotent, so calling it from package init is safe.
func init() {
	C.lazer_init()
}

// Anonymous credentials (C port of python/anon_cred/anon_cred.py).

const AnonPubkeyLen = 897  // ANONCRED_PUBKEYLEN
const AnonPrivkeyLen = 1281 // ANONCRED_PRIVKEYLEN
const AnonMsgLen = 64       // ANONCRED_MSGLEN (8 polys * 64 bits)

type AnonUserState struct{ c *C.anoncred_user_state_struct }
type AnonSignerState struct{ c *C.anoncred_signer_state_struct }
type AnonVerifierState struct{ c *C.anoncred_verifier_state_struct }

// AnonKeygen returns a Falcon-512 (secret, public) key pair.
func AnonKeygen() (sk []byte, pk []byte) {
	_sk := C.malloc(C.size_t(AnonPrivkeyLen))
	_pk := C.malloc(C.size_t(AnonPubkeyLen))
	C.anoncred_keygen((*C.uint8_t)(_sk), (*C.uint8_t)(_pk))
	sk = C.GoBytes(_sk, C.int(AnonPrivkeyLen))
	pk = C.GoBytes(_pk, C.int(AnonPubkeyLen))
	C.free(_sk)
	C.free(_pk)
	return
}

// cUintArray copies a Go []uint into C memory; returns the pointer (or nil)
// and a free function. The pointer is valid until free is called.
func cUintArray(v []uint) (*C.uint, func()) {
	if len(v) == 0 {
		return nil, func() {}
	}
	p := C.malloc(C.size_t(len(v)) * C.size_t(unsafe.Sizeof(C.uint(0))))
	s := unsafe.Slice((*C.uint)(p), len(v))
	for i, x := range v {
		s[i] = C.uint(x)
	}
	return (*C.uint)(p), func() { C.free(p) }
}

func AnonUserInit(pk []byte) (st AnonUserState) {
	_pk := C.CBytes(pk)
	st.c = (*C.anoncred_user_state_struct)(C.malloc(C.sizeof_anoncred_user_state_struct))
	C.anoncred_user_init(st.c, (*C.uint8_t)(_pk))
	C.free(_pk)
	return
}

func AnonUserClear(st *AnonUserState) {
	C.anoncred_user_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// AnonUserMaskmsg outputs the masked credentials (encoded t || P1 proof).
func AnonUserMaskmsg(st *AnonUserState, msg []byte) []byte {
	_mm := C.malloc(C.size_t(C.ANONCRED_MASKEDMSGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_msg := C.CBytes(msg)
	C.anoncred_user_maskmsg(st.c, (*C.uint8_t)(_mm), (*C.size_t)(_len), (*C.uint8_t)(_msg))
	out := C.GoBytes(_mm, C.int(*(*C.size_t)(_len)))
	C.free(_mm)
	C.free(_len)
	C.free(_msg)
	return out
}

// AnonUserSign outputs a disclosure proof; pubMvec lists the disclosed
// message indices. Returns (1, sig) on success, (0, nil) on decode failure.
func AnonUserSign(st *AnonUserState, blindsig []byte, pubMvec []uint) (int, []byte) {
	_sig := C.malloc(C.size_t(C.ANONCRED_SIGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_bs := C.CBytes(blindsig)
	pm, freePm := cUintArray(pubMvec)
	rc := C.anoncred_user_sign(st.c, (*C.uint8_t)(_sig), (*C.size_t)(_len),
		(*C.uint8_t)(_bs), C.size_t(len(blindsig)), pm, C.uint(len(pubMvec)))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_sig, C.int(*(*C.size_t)(_len)))
	}
	freePm()
	C.free(_sig)
	C.free(_len)
	C.free(_bs)
	return int(rc), out
}

func AnonSignerInit(pk []byte, sk []byte) (st AnonSignerState) {
	_pk := C.CBytes(pk)
	_sk := C.CBytes(sk)
	st.c = (*C.anoncred_signer_state_struct)(C.malloc(C.sizeof_anoncred_signer_state_struct))
	C.anoncred_signer_init(st.c, (*C.uint8_t)(_pk), (*C.uint8_t)(_sk))
	C.free(_pk)
	C.free(_sk)
	return
}

func AnonSignerClear(st *AnonSignerState) {
	C.anoncred_signer_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// AnonSignerSign verifies P1 and, if valid, outputs blinded credentials.
// Returns (1, blindsig) on success, (0, nil) if the masked message is invalid.
func AnonSignerSign(st *AnonSignerState, maskedMsg []byte) (int, []byte) {
	_bs := C.malloc(C.size_t(C.ANONCRED_BLINDSIGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_mm := C.CBytes(maskedMsg)
	rc := C.anoncred_signer_sign(st.c, (*C.uint8_t)(_bs), (*C.size_t)(_len),
		(*C.uint8_t)(_mm), C.size_t(len(maskedMsg)))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_bs, C.int(*(*C.size_t)(_len)))
	}
	C.free(_bs)
	C.free(_len)
	C.free(_mm)
	return int(rc), out
}

func AnonVerifierInit(pk []byte) (st AnonVerifierState) {
	_pk := C.CBytes(pk)
	st.c = (*C.anoncred_verifier_state_struct)(C.malloc(C.sizeof_anoncred_verifier_state_struct))
	C.anoncred_verifier_init(st.c, (*C.uint8_t)(_pk))
	C.free(_pk)
	return
}

func AnonVerifierClear(st *AnonVerifierState) {
	C.anoncred_verifier_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// AnonVerifierVrfy verifies a disclosure proof against the public message
// (private positions must already be zeroed). Returns 1 if valid, else 0.
func AnonVerifierVrfy(st *AnonVerifierState, pubMsg []byte, pubMvec []uint, sig []byte) int {
	_msg := C.CBytes(pubMsg)
	_sig := C.CBytes(sig)
	pm, freePm := cUintArray(pubMvec)
	rc := C.anoncred_verifier_vrfy(st.c, (*C.uint8_t)(_msg), pm, C.uint(len(pubMvec)),
		(*C.uint8_t)(_sig), C.size_t(len(sig)))
	freePm()
	C.free(_msg)
	C.free(_sig)
	return int(rc)
}
