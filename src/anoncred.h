#ifndef ANONCRED_H
#define ANONCRED_H

/*
 * Anonymous credentials demo, C port of python/anon_cred/anon_cred.py.
 *
 * Falcon-512 based blind signature with selective disclosure of a message
 * vector. All proofs are LNP linear-relation proofs (lin_prover/lin_verifier)
 * over the statement ring Rp = Z_12289[X]/(X^64 + 1); the deg-512 Falcon
 * objects are represented as 8-block structures over Rp via the isoring maps.
 *
 * Parameters (p1_param, p2_param) come from anoncred-params.h.
 */

#include "lazer.h"
#include <stddef.h>
#include <stdint.h>

/* Falcon-512 encoded key sizes (see blindsig.h: PUBKEYLEN/PRIVKEYLEN). */
#define ANONCRED_PUBKEYLEN 897
#define ANONCRED_PRIVKEYLEN 1281

/* Message: a vector of ANONCRED_NMSG binary polynomials over Rp (deg 64),
 * i.e. ANONCRED_NMSG * 64 bits = ANONCRED_MSGLEN bytes. */
#define ANONCRED_NMSG 8
#define ANONCRED_MSGLEN (ANONCRED_NMSG * 64 / 8) /* 64 bytes */

/* Generous upper bounds for encoded objects (see anon_cred.py output). */
#define ANONCRED_MASKEDMSGLEN_MAX 24000
#define ANONCRED_BLINDSIGLEN_MAX 4000
#define ANONCRED_SIGLEN_MAX 32000

typedef struct
{
  polymat_t AR, AM, ATAU, B1, B2; /* public matrices over Rp */
  lin_prover_state_t p1;          /* P1 prover (well-formedness) */
  lin_prover_state_t p2;          /* P2 prover (disclosure) */
  polyvec_t r;                    /* saved randomness (dim 16) */
  polyvec_t m;                    /* saved message (dim 8) */
} anoncred_user_state_struct;
typedef anoncred_user_state_struct anoncred_user_state_t[1];

typedef struct
{
  polymat_t AR, AM, ATAU;            /* public matrices over Rp */
  uint8_t privkey[ANONCRED_PRIVKEYLEN];
  lin_verifier_state_t p1;           /* P1 verifier */
} anoncred_signer_state_struct;
typedef anoncred_signer_state_struct anoncred_signer_state_t[1];

typedef struct
{
  polymat_t AR, AM, ATAU, B1, B2; /* public matrices over Rp */
  lin_verifier_state_t p2;        /* P2 verifier */
} anoncred_verifier_state_struct;
typedef anoncred_verifier_state_struct anoncred_verifier_state_t[1];

/* Falcon keypair (compressed encodings). */
void anoncred_keygen (uint8_t sk[ANONCRED_PRIVKEYLEN],
                      uint8_t pk[ANONCRED_PUBKEYLEN]);

void anoncred_user_init (anoncred_user_state_t state,
                         const uint8_t pk[ANONCRED_PUBKEYLEN]);
void anoncred_user_clear (anoncred_user_state_t state);
/* Output masked credentials (encoded t || P1 proof). */
void anoncred_user_maskmsg (anoncred_user_state_t state, uint8_t *masked_msg,
                            size_t *masked_msglen,
                            const uint8_t msg[ANONCRED_MSGLEN]);
/* Output a disclosure proof. pub_mvec lists the npub disclosed message
 * indices (0..ANONCRED_NMSG-1). Returns 1 on success, 0 on decode failure. */
int anoncred_user_sign (anoncred_user_state_t state, uint8_t *sig,
                        size_t *siglen, const uint8_t *blindsig,
                        size_t blindsiglen, const unsigned int *pub_mvec,
                        unsigned int npub);

void anoncred_signer_init (anoncred_signer_state_t state,
                           const uint8_t pk[ANONCRED_PUBKEYLEN],
                           const uint8_t sk[ANONCRED_PRIVKEYLEN]);
void anoncred_signer_clear (anoncred_signer_state_t state);
/* Verify P1 and, if valid, output blinded credentials (tau,s1,s2).
 * Returns 1 on success, 0 if the masked message is invalid. */
int anoncred_signer_sign (anoncred_signer_state_t state, uint8_t *blindsig,
                          size_t *blindsiglen, const uint8_t *masked_msg,
                          size_t masked_msglen);

void anoncred_verifier_init (anoncred_verifier_state_t state,
                             const uint8_t pk[ANONCRED_PUBKEYLEN]);
void anoncred_verifier_clear (anoncred_verifier_state_t state);
/* Verify a disclosure proof against the public message (private positions
 * must already be zeroed). Returns 1 if valid, 0 otherwise. */
int anoncred_verifier_vrfy (anoncred_verifier_state_t state,
                            const uint8_t pub_msg[ANONCRED_MSGLEN],
                            const unsigned int *pub_mvec, unsigned int npub,
                            const uint8_t *sig, size_t siglen);

#endif
