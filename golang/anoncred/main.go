package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/AVecsi/lazer"
)

// Tiered Option C / IRMA-fit demo. The message blocks are the user's secret
// (the first AnonNumSecret blocks) followed by the issuer-controlled blocks
// (metadata + public attributes). Credential size is dynamic: a credential
// uses the smallest tier whose capacity covers its public-attribute count, and
// the unused issuer blocks are zero. The user commits only the secret; the
// issuer adds its blocks when signing. At disclosure any subset of issuer
// blocks may be revealed; the secret stays hidden.

// tierNmsgBytes returns the byte length of a tier's full message (secret +
// issuer capacity blocks), 8 bytes per 64-bit block.
func tierNmsgBytes(tier int) int {
	return (lazer.AnonNumSecret + lazer.AnonTierNpub(tier)) * 8
}

// fullMsg concatenates the secret and the tier's issuer blocks.
func fullMsg(secret, pubMsg []byte) []byte {
	out := make([]byte, len(secret)+len(pubMsg))
	copy(out, secret)
	copy(out[len(secret):], pubMsg)
	return out
}

// disclosedMsg returns a tier-length message with only the blocks in idx copied
// from full (the rest zeroed) — the public message the verifier checks.
func disclosedMsg(full []byte, idx []uint, tier int) []byte {
	out := make([]byte, tierNmsgBytes(tier))
	for _, i := range idx {
		copy(out[i*8:i*8+8], full[i*8:i*8+8])
	}
	return out
}

func main() {
	fmt.Print("lazer anonymous credentials demo (Go, tiered Option C)\n")
	fmt.Print("------------------------------------------------------\n\n")

	// Choose a credential with this many public attributes; the tier follows.
	const nPublic = 16
	tier := lazer.AnonTierForNpub(nPublic)
	if tier < 0 {
		fmt.Printf("no tier for %d public attributes (max %d)\n", nPublic, lazer.AnonNpubMax)
		os.Exit(1)
	}
	npubBlocks := lazer.AnonTierNpub(tier)
	fmt.Printf("public attributes: %d -> tier %d (capacity %d, total %d blocks)\n\n",
		nPublic, tier, npubBlocks, lazer.AnonNumSecret+npubBlocks)

	// user secret (link secret)
	secret := make([]byte, lazer.AnonSecretLen)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	// issuer blocks: the tier's capacity (real attrs + zero padding)
	pubMsg := make([]byte, npubBlocks*8)
	if _, err := rand.Read(pubMsg[:nPublic*8]); err != nil {
		panic(err)
	}
	full := fullMsg(secret, pubMsg)

	// disclose two issuer blocks (indices >= AnonNumSecret); the secret hides.
	pubMvec := []uint{uint(lazer.AnonNumSecret), uint(lazer.AnonNumSecret + 3)}

	sk, pk := lazer.AnonKeygen()

	fmt.Print("Initialize user, signer (issuer), verifier ... ")
	user := lazer.AnonUserInit(pk, tier)
	signer := lazer.AnonSignerInit(pk, sk)
	verifier := lazer.AnonVerifierInit(pk, tier)
	fmt.Print("[OK]\n\n")

	issueStart := time.Now()
	fmt.Print("User commits its secret ... ")
	maskedMsg := lazer.AnonUserMaskmsg(&user, secret)
	fmt.Printf("[OK]  (masked: %d bytes)\n", len(maskedMsg))

	fmt.Print("Issuer checks P1, adds its blocks, blind-signs ... ")
	rc, blindsig := lazer.AnonSignerSign(&signer, maskedMsg, pubMsg, tier)
	if rc != 1 {
		fmt.Print("masked credentials are invalid.\n")
		os.Exit(1)
	}
	fmt.Printf("[OK]  (blindsig: %d bytes)\n", len(blindsig))
	issueTime := time.Since(issueStart)

	showStart := time.Now()
	fmt.Print("User outputs a disclosure proof revealing chosen issuer blocks ... ")
	rc, sig := lazer.AnonUserSign(&user, pubMsg, blindsig, pubMvec)
	if rc != 1 {
		fmt.Print("decoding failed.\n")
		os.Exit(1)
	}
	fmt.Printf("[OK]  (proof: %d bytes)\n", len(sig))

	fmt.Print("Verifier verifies the disclosure proof ... ")
	rc = lazer.AnonVerifierVrfy(&verifier, disclosedMsg(full, pubMvec, tier), pubMvec, sig)
	showTime := time.Since(showStart)
	if rc != 1 {
		fmt.Print("signature invalid.\n")
		os.Exit(1)
	}
	fmt.Print("[OK]\n\n")

	fmt.Printf("Issue time: %v\n", issueTime)
	fmt.Printf("Show time:  %v\n", showTime)

	lazer.AnonUserClear(&user)
	lazer.AnonSignerClear(&signer)
	lazer.AnonVerifierClear(&verifier)
}
