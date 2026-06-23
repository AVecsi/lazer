package main

// Randomized end-to-end test of the anoncred Go binding. Varies the two
// in-practice-arbitrary inputs: msg (random) and pubMvec (random subset of
// {0..7}, incl. empty and full). Each honest run must verify; a flipped bit
// in a disclosed block must be rejected (negative control).
//
// Run: go test -v ./...   (in golang/anoncred)

import (
	"crypto/rand"
	"math/big"
	"testing"

	"XXX1.org/lazer"
)

// randomSplit returns a pubMvec of size npub (a random subset of {0..7}) and
// its complement privMvec, via a Fisher-Yates shuffle of {0..7}.
func randomSplit(t *testing.T, npub uint) (pub, priv []uint) {
	perm := []uint{0, 1, 2, 3, 4, 5, 6, 7}
	for i := len(perm) - 1; i > 0; i-- {
		j := randInt(t, i+1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	for i, v := range perm {
		if uint(i) < npub {
			pub = append(pub, v)
		} else {
			priv = append(priv, v)
		}
	}
	return
}

func randInt(t *testing.T, n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return int(v.Int64())
}

// runOnce performs a full honest protocol run and returns the verifier result.
func runOnce(t *testing.T, msg []byte, pub, priv []uint) int {
	sk, pk := lazer.AnonKeygen()
	user := lazer.AnonUserInit(pk)
	signer := lazer.AnonSignerInit(pk, sk)
	verifier := lazer.AnonVerifierInit(pk)
	defer lazer.AnonUserClear(&user)
	defer lazer.AnonSignerClear(&signer)
	defer lazer.AnonVerifierClear(&verifier)

	maskedMsg := lazer.AnonUserMaskmsg(&user, msg)
	rc, blindsig := lazer.AnonSignerSign(&signer, maskedMsg)
	if rc != 1 {
		t.Fatal("signer rejected a valid masked message")
	}
	rc, sig := lazer.AnonUserSign(&user, blindsig, pub)
	if rc != 1 {
		t.Fatal("user_sign decode failed")
	}
	msgPub := zeroOutBlocks(msg, priv)
	return lazer.AnonVerifierVrfy(&verifier, msgPub, pub, sig)
}

func TestAnoncredRandom(t *testing.T) {
	const iters = 12
	for i := 0; i < iters; i++ {
		// edge cases: i==0 none disclosed, i==1 all disclosed.
		var npub uint
		switch i {
		case 0:
			npub = 0
		case 1:
			npub = 8
		default:
			npub = uint(randInt(t, 9))
		}

		msg := make([]byte, lazer.AnonMsgLen)
		if _, err := rand.Read(msg); err != nil {
			t.Fatalf("rand msg: %v", err)
		}
		pub, priv := randomSplit(t, npub)

		if got := runOnce(t, msg, pub, priv); got != 1 {
			t.Fatalf("iter %d (npub=%d): honest run did NOT verify (got %d)", i, npub, got)
		}
		t.Logf("iter %2d: npub=%d msg=random -> VERIFIED", i, npub)

		// negative control: corrupt a disclosed block -> must be rejected.
		if npub > 0 {
			sk, pk := lazer.AnonKeygen()
			user := lazer.AnonUserInit(pk)
			signer := lazer.AnonSignerInit(pk, sk)
			verifier := lazer.AnonVerifierInit(pk)
			mm := lazer.AnonUserMaskmsg(&user, msg)
			rc, bs := lazer.AnonSignerSign(&signer, mm)
			if rc != 1 {
				t.Fatal("signer rejected (neg control setup)")
			}
			rc, sg := lazer.AnonUserSign(&user, bs, pub)
			if rc != 1 {
				t.Fatal("user_sign failed (neg control setup)")
			}
			msgPub := zeroOutBlocks(msg, priv)
			msgPub[pub[0]*8] ^= 0x01 // flip a bit in a disclosed block
			if got := lazer.AnonVerifierVrfy(&verifier, msgPub, pub, sg); got == 1 {
				t.Fatalf("iter %d: negative control FAILED, accepted corrupted message", i)
			}
			lazer.AnonUserClear(&user)
			lazer.AnonSignerClear(&signer)
			lazer.AnonVerifierClear(&verifier)
		}
	}
}
