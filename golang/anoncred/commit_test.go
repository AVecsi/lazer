package main

// End-to-end test of the stateless tiered commit/disclose binding
// (AnonUserCommit / AnonUserDisclose). The opening (r + secret) is
// tier-independent; the tier is supplied at disclosure/verification.
//
// Run: go test -v -run Commit ./...   (in golang/anoncred)

import (
	"testing"

	"github.com/AVecsi/lazer"
)

// runOnceCommit performs a full honest run via the stateless API at a tier.
func runOnceCommit(t *testing.T, secret, pubMsg []byte, pub []uint, tier int) int {
	sk, pk := lazer.AnonKeygen()
	signer := lazer.AnonSignerInit(pk, sk)
	verifier := lazer.AnonVerifierInit(pk, tier)
	defer lazer.AnonSignerClear(&signer)
	defer lazer.AnonVerifierClear(&verifier)

	maskedMsg, opening := lazer.AnonUserCommit(secret)
	if len(opening) != lazer.AnonOpeningLen {
		t.Fatalf("opening len = %d, want %d", len(opening), lazer.AnonOpeningLen)
	}

	rc, blindsig := lazer.AnonSignerSign(&signer, maskedMsg, pubMsg, tier)
	if rc != 1 {
		t.Fatal("signer rejected a valid masked message")
	}

	rc, sig := lazer.AnonUserDisclose(pk, opening, pubMsg, blindsig, pub, tier)
	if rc != 1 {
		t.Fatal("disclose decode failed")
	}

	return lazer.AnonVerifierVrfy(&verifier, disclosedMsg(fullMsg(secret, pubMsg), pub, tier), pub, sig)
}

func TestAnoncredCommitDisclose(t *testing.T) {
	for tier := 0; tier < lazer.AnonNumTiers; tier++ {
		cap := lazer.AnonTierNpub(tier)
		for _, npub := range []uint{0, uint(cap), uint(randInt(t, cap+1))} {
			secret, pubMsg := randSecretPub(t, tier)
			pub := randomSplit(t, npub, tier)

			if got := runOnceCommit(t, secret, pubMsg, pub, tier); got != 1 {
				t.Fatalf("tier %d (cap %d, npub=%d): honest commit/disclose did NOT verify (got %d)", tier, cap, npub, got)
			}
			t.Logf("tier %d (cap %2d): npub=%2d -> VERIFIED (stateless)", tier, cap, npub)

			if npub > 0 {
				sk, pk := lazer.AnonKeygen()
				signer := lazer.AnonSignerInit(pk, sk)
				verifier := lazer.AnonVerifierInit(pk, tier)
				mm, opening := lazer.AnonUserCommit(secret)
				rc, bs := lazer.AnonSignerSign(&signer, mm, pubMsg, tier)
				if rc != 1 {
					t.Fatal("signer rejected (neg control setup)")
				}
				rc, sg := lazer.AnonUserDisclose(pk, opening, pubMsg, bs, pub, tier)
				if rc != 1 {
					t.Fatal("disclose failed (neg control setup)")
				}
				full := disclosedMsg(fullMsg(secret, pubMsg), pub, tier)
				full[pub[0]*8] ^= 0x01
				if got := lazer.AnonVerifierVrfy(&verifier, full, pub, sg); got == 1 {
					t.Fatalf("tier %d: negative control FAILED, accepted corrupted message", tier)
				}
				lazer.AnonSignerClear(&signer)
				lazer.AnonVerifierClear(&verifier)
			}
		}
	}
}
