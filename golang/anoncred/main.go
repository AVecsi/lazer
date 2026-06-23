package main

import (
	"fmt"
	"os"
	"time"

	"XXX1.org/lazer"
)

// zeroOutBlocks zeroes the 8-byte message blocks at the given indices
// (Go port of zero_out_bytes(msg, priv_mvec, deg//8)).
func zeroOutBlocks(msg []byte, idx []uint) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	for _, i := range idx {
		for j := uint(0); j < 8; j++ {
			out[i*8+j] = 0
		}
	}
	return out
}

func main() {
	fmt.Print("lazer anonymous credentials demo (Go)\n")
	fmt.Print("--------------------------\n\n")

	// message: 64 bytes (8 message polynomials of 64 bits each)
	msg := make([]byte, lazer.AnonMsgLen)
	for i := range msg {
		msg[i] = byte((i%8)*0x22 + 0x01)
	}

	// disclosed message indices and their complement
	pubMvec := []uint{0, 4, 5}
	var privMvec []uint
	for i := uint(0); i < 8; i++ {
		isPub := false
		for _, p := range pubMvec {
			if p == i {
				isPub = true
			}
		}
		if !isPub {
			privMvec = append(privMvec, i)
		}
	}

	sk, pk := lazer.AnonKeygen()

	fmt.Print("Initialize user with public key ... ")
	user := lazer.AnonUserInit(pk)
	fmt.Print("[OK]\n\n")

	fmt.Print("Initialize signer with public and private key ... ")
	signer := lazer.AnonSignerInit(pk, sk)
	fmt.Print("[OK]\n\n")

	fmt.Print("Initialize verifier with public key ... ")
	verifier := lazer.AnonVerifierInit(pk)
	fmt.Print("[OK]\n\n")

	issueStart := time.Now()
	fmt.Print("User outputs masked credentials (incl. proof of well-formedness) ... ")
	maskedMsg := lazer.AnonUserMaskmsg(&user, msg)
	fmt.Print("[OK]\n")
	fmt.Printf("masked credentials (t,P1): %d bytes\n\n", len(maskedMsg))

	fmt.Print("Signer checks the proof and outputs blinded credentials ... ")
	rc, blindsig := lazer.AnonSignerSign(&signer, maskedMsg)
	if rc != 1 {
		fmt.Print("masked credentials are invalid.\n")
		os.Exit(1)
	}
	fmt.Print("[OK]\n")
	issueTime := time.Since(issueStart)
	fmt.Printf("blind credentials (tau,s1,s2): %d bytes\n\n", len(blindsig))

	showStart := time.Now()
	fmt.Print("User outputs a signature on the hidden credentials ... ")
	rc, sig := lazer.AnonUserSign(&user, blindsig, pubMvec)
	if rc != 1 {
		fmt.Print("decoding failed.\n")
		os.Exit(1)
	}
	fmt.Print("[OK]\n")
	fmt.Printf("signature (P2): %d bytes\n\n", len(sig))

	fmt.Print("Verifier verifies the signature of the blinded credentials ... ")
	msgPub := zeroOutBlocks(msg, privMvec)
	rc = lazer.AnonVerifierVrfy(&verifier, msgPub, pubMvec, sig)
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
