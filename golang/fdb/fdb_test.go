package main

// End-to-end test of the Falcon device-binding Go binding: issuance,
// blackbox signing + proof, verification, and the two binding checks (a proof
// verifies under neither another message nor another credential).
//
// Run: go test -v ./...   (in golang/fdb)

import (
	"crypto/rand"
	"testing"

	"XXX1.org/lazer"
)

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestFdbDeviceBinding(t *testing.T) {
	seed := randBytes(t, 32) // public setup seed, shared by both roles

	sk, pk := lazer.FdbKeygen()
	signer := lazer.FdbSignerInit(seed, sk, pk)
	verifier := lazer.FdbVerifierInit(seed)
	defer lazer.FdbSignerClear(&signer)
	defer lazer.FdbVerifierClear(&verifier)

	// issuance (once): the signer commits to its public key
	cred := lazer.FdbSignerIssue(&signer)
	if len(cred) == 0 {
		t.Fatal("issuance failed")
	}
	if lazer.FdbVerifierSetCredential(&verifier, cred) != 1 {
		t.Fatal("verifier rejected the credential")
	}

	// the verifier picks the message; the signer returns (salt, proof)
	msg := randBytes(t, 32)
	rc, salt, proof := lazer.FdbSignerProve(&signer, msg)
	if rc != 1 {
		t.Fatal("prove failed")
	}
	if len(salt) != lazer.FdbSaltLen {
		t.Fatalf("salt len = %d, want %d", len(salt), lazer.FdbSaltLen)
	}
	if lazer.FdbVerifierVrfy(&verifier, proof, msg, salt) != 1 {
		t.Fatal("honest proof did not verify")
	}
	t.Logf("proof size = %d bytes", len(proof))

	// bound to the message: the same proof under another message must fail
	msg2 := randBytes(t, 32)
	if lazer.FdbVerifierVrfy(&verifier, proof, msg2, salt) != 0 {
		t.Fatal("proof accepted under a different message")
	}

	// bound to the committed key: the same proof under another credential
	// (here a fresh issuance, i.e. different rc) must fail
	cred2 := lazer.FdbSignerIssue(&signer)
	if lazer.FdbVerifierSetCredential(&verifier, cred2) != 1 {
		t.Fatal("verifier rejected the re-issued credential")
	}
	if lazer.FdbVerifierVrfy(&verifier, proof, msg, salt) != 0 {
		t.Fatal("proof accepted under a different credential")
	}
}

// API misuse must fail cleanly, not read uninitialized state.
func TestFdbGuards(t *testing.T) {
	seed := randBytes(t, 32)
	sk, pk := lazer.FdbKeygen()
	signer := lazer.FdbSignerInit(seed, sk, pk)
	verifier := lazer.FdbVerifierInit(seed)
	defer lazer.FdbSignerClear(&signer)
	defer lazer.FdbVerifierClear(&verifier)

	msg := randBytes(t, 32)

	// proving before issuance: rc is unset
	if rc, _, _ := lazer.FdbSignerProve(&signer, msg); rc != 0 {
		t.Fatal("prove succeeded before issuance")
	}

	// verifying before a credential is stored: t_h and r0 are unset
	if lazer.FdbSignerIssue(&signer) == nil {
		t.Fatal("issuance failed")
	}
	rc, salt, proof := lazer.FdbSignerProve(&signer, msg)
	if rc != 1 {
		t.Fatal("prove failed")
	}
	if lazer.FdbVerifierVrfy(&verifier, proof, msg, salt) != 0 {
		t.Fatal("verify succeeded without a credential")
	}
}
