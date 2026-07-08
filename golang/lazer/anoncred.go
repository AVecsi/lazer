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

const AnonPubkeyLen = 897    // ANONCRED_PUBKEYLEN
const AnonPrivkeyLen = 1281  // ANONCRED_PRIVKEYLEN
const AnonNumSecret = 4      // ANONCRED_NSECRET (secret blocks, committed by user)
const AnonNumTiers = 7       // ANONCRED_NTIERS
const AnonNpubMax = 60       // ANONCRED_NPUB_MAX (largest tier's issuer capacity)
const AnonNumBlocksMax = 64  // ANONCRED_NMSG_MAX (secret + NpubMax)
const AnonMsgLen = 512       // ANONCRED_MSGLEN (max full m: 64 blocks * 64 bits)
const AnonSecretLen = 32     // ANONCRED_SECRETLEN (4 secret blocks)
const AnonPubMsgLenMax = 480 // ANONCRED_PUBMSGLEN_MAX (60 issuer blocks)
const AnonOpeningLen = 2080  // ANONCRED_OPENINGLEN (16*64 int16 r + 32-byte secret)

// AnonTierNpub returns the public-attribute capacity of a tier index (0..6).
func AnonTierNpub(tier int) int { return int(C.anoncred_tier_npub(C.uint(tier))) }

// AnonTierForNpub returns the smallest tier index whose capacity covers npub
// public attributes, or -1 if npub exceeds the maximum (AnonNpubMax).
func AnonTierForNpub(npub int) int { return int(C.anoncred_tier_for_npub(C.uint(npub))) }

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

// AnonUserInit initializes a user state for disclosure at the given tier.
func AnonUserInit(pk []byte, tier int) (st AnonUserState) {
	_pk := C.CBytes(pk)
	st.c = (*C.anoncred_user_state_struct)(C.malloc(C.sizeof_anoncred_user_state_struct))
	C.anoncred_user_init(st.c, (*C.uint8_t)(_pk), C.uint(tier))
	C.free(_pk)
	return
}

func AnonUserClear(st *AnonUserState) {
	C.anoncred_user_clear(st.c)
	C.free(unsafe.Pointer(st.c))
}

// AnonUserMaskmsg commits the user's secret (AnonSecretLen bytes) and outputs
// the masked credentials (encoded t_user || P1 proof).
func AnonUserMaskmsg(st *AnonUserState, secret []byte) []byte {
	_mm := C.malloc(C.size_t(C.ANONCRED_MASKEDMSGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_sec := C.CBytes(secret)
	C.anoncred_user_maskmsg(st.c, (*C.uint8_t)(_mm), (*C.size_t)(_len), (*C.uint8_t)(_sec))
	out := C.GoBytes(_mm, C.int(*(*C.size_t)(_len)))
	C.free(_mm)
	C.free(_len)
	C.free(_sec)
	return out
}

// AnonUserSign outputs a disclosure proof over the full message m = (secret,
// pubMsg); pubMsg supplies the AnonPubMsgLen issuer blocks. pubMvec lists the
// disclosed block indices. Returns (1, sig) on success, (0, nil) on failure.
func AnonUserSign(st *AnonUserState, pubMsg []byte, blindsig []byte, pubMvec []uint) (int, []byte) {
	_sig := C.malloc(C.size_t(C.ANONCRED_SIGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_pub := C.CBytes(pubMsg)
	_bs := C.CBytes(blindsig)
	pm, freePm := cUintArray(pubMvec)
	rc := C.anoncred_user_sign(st.c, (*C.uint8_t)(_sig), (*C.size_t)(_len),
		(*C.uint8_t)(_pub), (*C.uint8_t)(_bs), C.size_t(len(blindsig)),
		pm, C.uint(len(pubMvec)))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_sig, C.int(*(*C.size_t)(_len)))
	}
	freePm()
	C.free(_sig)
	C.free(_len)
	C.free(_pub)
	C.free(_bs)
	return int(rc), out
}

// AnonUserCommit performs the stateless commit step over the user's secret
// (AnonSecretLen bytes): it returns the masked message (the commitment the
// issuer signs after adding its own blocks) and an opaque opening (serialized
// randomness r || secret) that the client stores and later passes to
// AnonUserDisclose. No issuer public key is needed for this step.
func AnonUserCommit(secret []byte) (maskedMsg []byte, opening []byte) {
	_mm := C.malloc(C.size_t(C.ANONCRED_MASKEDMSGLEN_MAX))
	_mmLen := C.malloc(C.sizeof_size_t)
	_op := C.malloc(C.size_t(AnonOpeningLen))
	_opLen := C.malloc(C.sizeof_size_t)
	_sec := C.CBytes(secret)
	C.anoncred_user_commit((*C.uint8_t)(_mm), (*C.size_t)(_mmLen),
		(*C.uint8_t)(_op), (*C.size_t)(_opLen), (*C.uint8_t)(_sec))
	maskedMsg = C.GoBytes(_mm, C.int(*(*C.size_t)(_mmLen)))
	opening = C.GoBytes(_op, C.int(*(*C.size_t)(_opLen)))
	C.free(_mm)
	C.free(_mmLen)
	C.free(_op)
	C.free(_opLen)
	C.free(_sec)
	return
}

// AnonUserDisclose performs the stateless disclosure step: it rebuilds a user
// state from (pk, opening), restores the saved randomness and secret, fills the
// issuer blocks from pubMsg (AnonPubMsgLen bytes), and outputs a disclosure
// proof revealing the blocks listed in pubMvec. Returns (1, sig) on success,
// (0, nil) on decode/opening failure.
func AnonUserDisclose(pk []byte, opening []byte, pubMsg []byte, blindsig []byte, pubMvec []uint, tier int) (int, []byte) {
	_pk := C.CBytes(pk)
	_op := C.CBytes(opening)
	_pub := C.CBytes(pubMsg)
	_bs := C.CBytes(blindsig)
	_sig := C.malloc(C.size_t(C.ANONCRED_SIGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	pm, freePm := cUintArray(pubMvec)
	rc := C.anoncred_user_disclose((*C.uint8_t)(_pk), (*C.uint8_t)(_op),
		C.size_t(len(opening)), (*C.uint8_t)(_pub), (*C.uint8_t)(_bs),
		C.size_t(len(blindsig)), pm, C.uint(len(pubMvec)),
		(*C.uint8_t)(_sig), (*C.size_t)(_len), C.uint(tier))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_sig, C.int(*(*C.size_t)(_len)))
	}
	freePm()
	C.free(_pk)
	C.free(_op)
	C.free(_pub)
	C.free(_bs)
	C.free(_sig)
	C.free(_len)
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

// AnonSignerSign verifies the well-formedness proof P1 and, if valid, adds the
// tier's issuer blocks pubMsg (AnonTierNpub(tier) blocks) and outputs blinded
// credentials. Returns (1, blindsig) on success, (0, nil) if invalid.
func AnonSignerSign(st *AnonSignerState, maskedMsg []byte, pubMsg []byte, tier int) (int, []byte) {
	_bs := C.malloc(C.size_t(C.ANONCRED_BLINDSIGLEN_MAX))
	_len := C.malloc(C.sizeof_size_t)
	_mm := C.CBytes(maskedMsg)
	_pub := C.CBytes(pubMsg)
	rc := C.anoncred_signer_sign(st.c, (*C.uint8_t)(_bs), (*C.size_t)(_len),
		(*C.uint8_t)(_mm), C.size_t(len(maskedMsg)), (*C.uint8_t)(_pub), C.uint(tier))
	var out []byte
	if rc == 1 {
		out = C.GoBytes(_bs, C.int(*(*C.size_t)(_len)))
	}
	C.free(_bs)
	C.free(_len)
	C.free(_mm)
	C.free(_pub)
	return int(rc), out
}

// AnonVerifierInit initializes a verifier for the given tier.
func AnonVerifierInit(pk []byte, tier int) (st AnonVerifierState) {
	_pk := C.CBytes(pk)
	st.c = (*C.anoncred_verifier_state_struct)(C.malloc(C.sizeof_anoncred_verifier_state_struct))
	C.anoncred_verifier_init(st.c, (*C.uint8_t)(_pk), C.uint(tier))
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
