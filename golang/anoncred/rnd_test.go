package main

// Randomized end-to-end test of the tiered anoncred Go binding (Option C). For
// each tier it varies the secret, the issuer blocks, and the disclosed subset
// (incl. empty and full). Each honest run must verify; a flipped bit in a
// disclosed block must be rejected (negative control).
//
// Run: go test -v ./...   (in golang/anoncred)

import (
	"crypto/rand"
	"math/big"
	"testing"

	"XXX1.org/lazer"
)

func randInt(t *testing.T, n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return int(v.Int64())
}

// randomSplit returns npub disclosed indices: a random subset of the tier's
// issuer block indices {AnonNumSecret .. AnonNumSecret+capacity-1}.
func randomSplit(t *testing.T, npub uint, tier int) (pub []uint) {
	cap := lazer.AnonTierNpub(tier)
	perm := make([]uint, cap)
	for i := 0; i < cap; i++ {
		perm[i] = uint(lazer.AnonNumSecret + i)
	}
	for i := len(perm) - 1; i > 0; i-- {
		j := randInt(t, i+1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	for i := 0; uint(i) < npub && i < len(perm); i++ {
		pub = append(pub, perm[i])
	}
	return
}

func randSecretPub(t *testing.T, tier int) (secret, pubMsg []byte) {
	secret = make([]byte, lazer.AnonSecretLen)
	pubMsg = make([]byte, lazer.AnonTierNpub(tier)*8)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	if _, err := rand.Read(pubMsg); err != nil {
		t.Fatalf("rand pubMsg: %v", err)
	}
	return
}

// runOnce performs a full honest protocol run (stateful API) at a tier.
func runOnce(t *testing.T, secret, pubMsg []byte, pub []uint, tier int) int {
	sk, pk := lazer.AnonKeygen()
	user := lazer.AnonUserInit(pk, tier)
	signer := lazer.AnonSignerInit(pk, sk)
	verifier := lazer.AnonVerifierInit(pk, tier)
	defer lazer.AnonUserClear(&user)
	defer lazer.AnonSignerClear(&signer)
	defer lazer.AnonVerifierClear(&verifier)

	maskedMsg := lazer.AnonUserMaskmsg(&user, secret)
	rc, blindsig := lazer.AnonSignerSign(&signer, maskedMsg, pubMsg, tier)
	if rc != 1 {
		t.Fatal("signer rejected a valid masked message")
	}
	rc, sig := lazer.AnonUserSign(&user, pubMsg, blindsig, pub)
	if rc != 1 {
		t.Fatal("user_sign decode failed")
	}
	return lazer.AnonVerifierVrfy(&verifier, disclosedMsg(fullMsg(secret, pubMsg), pub, tier), pub, sig)
}

func TestAnoncredRandom(t *testing.T) {
	for tier := 0; tier < lazer.AnonNumTiers; tier++ {
		cap := lazer.AnonTierNpub(tier)
		// edge cases: none disclosed, all disclosed, and a random partial.
		for _, npub := range []uint{0, uint(cap), uint(randInt(t, cap+1))} {
			secret, pubMsg := randSecretPub(t, tier)
			pub := randomSplit(t, npub, tier)

			if got := runOnce(t, secret, pubMsg, pub, tier); got != 1 {
				t.Fatalf("tier %d (cap %d, npub=%d): honest run did NOT verify (got %d)", tier, cap, npub, got)
			}
			t.Logf("tier %d (cap %2d): npub=%2d -> VERIFIED", tier, cap, npub)

			// negative control: corrupt a disclosed block -> must be rejected.
			if npub > 0 {
				sk, pk := lazer.AnonKeygen()
				user := lazer.AnonUserInit(pk, tier)
				signer := lazer.AnonSignerInit(pk, sk)
				verifier := lazer.AnonVerifierInit(pk, tier)
				mm := lazer.AnonUserMaskmsg(&user, secret)
				rc, bs := lazer.AnonSignerSign(&signer, mm, pubMsg, tier)
				if rc != 1 {
					t.Fatal("signer rejected (neg control setup)")
				}
				rc, sg := lazer.AnonUserSign(&user, pubMsg, bs, pub)
				if rc != 1 {
					t.Fatal("user_sign failed (neg control setup)")
				}
				full := disclosedMsg(fullMsg(secret, pubMsg), pub, tier)
				full[pub[0]*8] ^= 0x01
				if got := lazer.AnonVerifierVrfy(&verifier, full, pub, sg); got == 1 {
					t.Fatalf("tier %d: negative control FAILED, accepted corrupted message", tier)
				}
				lazer.AnonUserClear(&user)
				lazer.AnonSignerClear(&signer)
				lazer.AnonVerifierClear(&verifier)
			}
		}
	}
}
