#ifndef ANONCRED_H
#define ANONCRED_H

/*
 * Anonymous credentials (Falcon-512 blind signature, IRMA-style issuance).
 *
 * Selective-disclosure credential over the statement ring
 * Rp = Z_12289[X]/(X^64 + 1); deg-512 Falcon objects are 8-block structures
 * over Rp via the isoring maps. All proofs are LNP linear-relation proofs.
 *
 * Message model (Option C, IRMA-faithful):
 *   The first ANONCRED_NSECRET blocks are the user's *secret* (the link secret),
 *   committed by the user; the remaining blocks are *issuer-controlled*
 *   (metadata + public attributes), added homomorphically by the issuer when it
 *   signs. Concretely:
 *     - user_commit/maskmsg: commit t_user = AR*r + AM_secret*m_secret and prove
 *       well-formedness (P1) of the secret part only.
 *     - signer_sign: verify P1, then sign t = t_user + AM_pub*m_pub for the
 *       issuer's blocks m_pub. The issuer thus *certifies* its blocks; the user
 *       cannot influence them (its commitment excludes those columns).
 *     - user_sign/disclose: prove the full relation over m = (m_secret, m_pub),
 *       revealing any chosen subset of blocks (pub_mvec) and hiding the rest
 *       (the secret blocks are normally always hidden).
 *
 *   Credential size is dynamic via TIERS (see anoncred_tier_npub): the P1
 *   (commit) proof is shared across all tiers because it only commits the
 *   secret; each tier has its own P2 (disclosure) parameter set sized for that
 *   tier's total block count. A credential uses the smallest tier covering its
 *   attribute count and zero-pads unused issuer blocks.
 *
 * Parameters come from anoncred-params.h: one shared p1_param (witness dim
 * 16 + ANONCRED_NSECRET) plus per-tier p2_param_<npub> (witness dim
 * 40 + ANONCRED_NSECRET + npub). They are generated from
 * python/anon_cred/anon_cred_p1_params.py and anon_cred_p2_params_<npub>.py via
 * scripts/lin-codegen.sage; regenerate after changing the tier set or NSECRET.
 */

#include "lazer.h"
#include <stddef.h>
#include <stdint.h>

/* Falcon-512 encoded key sizes (see blindsig.h: PUBKEYLEN/PRIVKEYLEN). */
#define ANONCRED_PUBKEYLEN 897
#define ANONCRED_PRIVKEYLEN 1281

/* Message: binary polynomials over Rp (deg 64), 64 bits each. The first
 * ANONCRED_NSECRET blocks are the user secret (the link attribute); the
 * remaining blocks are issuer-controlled (metadata + public attributes).
 *
 * TIERS: the credential size is dynamic up to a maximum, chosen from a fixed
 * set of public-attribute tiers. The well-formedness proof P1 is SHARED across
 * tiers (it only commits the NSECRET secret blocks); each tier has its own
 * disclosure-proof parameters p2_param_<npub>. A credential uses the smallest
 * tier whose public-attribute capacity covers its attribute count, zero-padding
 * the unused issuer blocks. */
#define ANONCRED_NSECRET 4
#define ANONCRED_NTIERS 7
#define ANONCRED_NPUB_MAX 60                                /* tier 6 capacity */
#define ANONCRED_NMSG_MAX (ANONCRED_NSECRET + ANONCRED_NPUB_MAX) /* 64 blocks */
#define ANONCRED_MSGLEN (ANONCRED_NMSG_MAX * 64 / 8)        /* 512 bytes (max m) */
#define ANONCRED_SECRETLEN (ANONCRED_NSECRET * 64 / 8)      /* 32 bytes (secret) */
#define ANONCRED_PUBMSGLEN_MAX (ANONCRED_NPUB_MAX * 64 / 8) /* 480 bytes (issuer) */

/* Generous upper bounds for encoded objects (sized for the largest tier). */
#define ANONCRED_MASKEDMSGLEN_MAX 49152
#define ANONCRED_BLINDSIGLEN_MAX 4000
#define ANONCRED_SIGLEN_MAX 131072

/* Serialized commitment opening = the saved randomness r (16 polys of deg 64,
 * one centered int16 per coeff) followed by the secret blocks (m_secret). It is
 * tier-independent (the commitment binds only the secret). The issuer blocks
 * are not stored here: the client re-derives them (from the issuance request)
 * and supplies them as pub_msg at disclosure. */
#define ANONCRED_OPENINGLEN (16 * 64 * 2 + ANONCRED_SECRETLEN) /* 2080 */

/* Tier capacities (number of public-attribute blocks), ascending. The total
 * block count for tier t is ANONCRED_NSECRET + anoncred_tier_npub(t). */
unsigned int anoncred_tier_npub (unsigned int tier);
/* Smallest tier index whose capacity is >= npub, or -1 if npub exceeds the
 * maximum (ANONCRED_NPUB_MAX). */
int anoncred_tier_for_npub (unsigned int npub);

typedef struct
{
  polymat_t AR, AM, ATAU, B1, B2; /* public matrices over Rp (AM is 8 x NMSG_MAX) */
  lin_prover_state_t p1;          /* P1 prover (well-formedness, shared) */
  lin_prover_state_t p2;          /* P2 prover (disclosure, tier-specific) */
  polyvec_t r;                    /* saved randomness (dim 16) */
  polyvec_t m;                    /* saved message (dim ANONCRED_NMSG_MAX) */
  unsigned int nmsg;              /* tier total blocks; 0 = no p2 (commit only) */
} anoncred_user_state_struct;
typedef anoncred_user_state_struct anoncred_user_state_t[1];

typedef struct
{
  polymat_t AR, AM, ATAU;            /* public matrices over Rp (AM is 8 x NMSG_MAX) */
  uint8_t privkey[ANONCRED_PRIVKEYLEN];
  lin_verifier_state_t p1;           /* P1 verifier */
} anoncred_signer_state_struct;
typedef anoncred_signer_state_struct anoncred_signer_state_t[1];

typedef struct
{
  polymat_t AR, AM, ATAU, B1, B2; /* public matrices over Rp (AM is 8 x NMSG_MAX) */
  lin_verifier_state_t p2;        /* P2 verifier (tier-specific) */
  unsigned int nmsg;              /* tier total blocks */
} anoncred_verifier_state_struct;
typedef anoncred_verifier_state_struct anoncred_verifier_state_t[1];

/* Falcon keypair (compressed encodings). */
void anoncred_keygen (uint8_t sk[ANONCRED_PRIVKEYLEN],
                      uint8_t pk[ANONCRED_PUBKEYLEN]);

/* Initialize a user state for disclosure at the given tier (selects the P2
 * parameters and the total block count). */
void anoncred_user_init (anoncred_user_state_t state,
                         const uint8_t pk[ANONCRED_PUBKEYLEN],
                         unsigned int tier);
/* Like anoncred_user_init but without an issuer pk or a tier: builds only what
 * maskmsg needs (AR/AM + the shared P1). The resulting state can run maskmsg
 * (commit) but not user_sign. */
void anoncred_user_init_params (anoncred_user_state_t state);
void anoncred_user_clear (anoncred_user_state_t state);

/* Stateless commit: params-only init + maskmsg over the secret, exporting the
 * masked message (commitment t_user || P1 proof) and the opaque opening
 * (saved r || secret). No issuer pk needed. Returns 1. */
int anoncred_user_commit (uint8_t *masked_msg, size_t *masked_msglen,
                          uint8_t opening[ANONCRED_OPENINGLEN],
                          size_t *openinglen,
                          const uint8_t secret[ANONCRED_SECRETLEN]);
/* Stateless disclosure: rebuilds a user state from (pk, opening), restores the
 * saved r and secret blocks, fills the issuer blocks from pub_msg, and runs
 * user_sign. pub_mvec lists the npub disclosed block indices (0..NMSG-1).
 * Returns 1 on success, 0 on decode/opening failure. */
int anoncred_user_disclose (const uint8_t pk[ANONCRED_PUBKEYLEN],
                            const uint8_t opening[ANONCRED_OPENINGLEN],
                            size_t openinglen, const uint8_t *pub_msg,
                            const uint8_t *blindsig, size_t blindsiglen,
                            const unsigned int *pub_mvec, unsigned int npub,
                            uint8_t *sig, size_t *siglen, unsigned int tier);
/* Commit the secret blocks: output masked credentials (encoded t_user || P1
 * proof) where t_user = AR*r + AM_secret*m_secret. */
void anoncred_user_maskmsg (anoncred_user_state_t state, uint8_t *masked_msg,
                            size_t *masked_msglen,
                            const uint8_t secret[ANONCRED_SECRETLEN]);
/* Output a disclosure proof over the full message m = (secret, pub_msg).
 * pub_msg supplies the issuer-controlled blocks; pub_mvec lists the npub
 * disclosed block indices (0..NMSG-1). Returns 1 on success, 0 on decode
 * failure. */
/* Output a disclosure proof over the full message m = (secret, pub_msg) at the
 * state's tier. pub_msg supplies the tier's issuer blocks; pub_mvec lists the
 * npub disclosed block indices. Returns 1 on success, 0 on decode failure. */
int anoncred_user_sign (anoncred_user_state_t state, uint8_t *sig,
                        size_t *siglen, const uint8_t *pub_msg,
                        const uint8_t *blindsig, size_t blindsiglen,
                        const unsigned int *pub_mvec, unsigned int npub);

void anoncred_signer_init (anoncred_signer_state_t state,
                           const uint8_t pk[ANONCRED_PUBKEYLEN],
                           const uint8_t sk[ANONCRED_PRIVKEYLEN]);
void anoncred_signer_clear (anoncred_signer_state_t state);
/* Verify the well-formedness proof P1 over the user's secret commitment, then
 * add the tier's issuer blocks (t = t_user + AM_pub*m_pub from pub_msg) and
 * Falcon-sign the result. pub_msg holds anoncred_tier_npub(tier) blocks.
 * Returns 1 on success, 0 if the masked message is invalid. */
int anoncred_signer_sign (anoncred_signer_state_t state, uint8_t *blindsig,
                          size_t *blindsiglen, const uint8_t *masked_msg,
                          size_t masked_msglen, const uint8_t *pub_msg,
                          unsigned int tier);

/* Initialize a verifier for the given tier (selects the P2 parameters). */
void anoncred_verifier_init (anoncred_verifier_state_t state,
                             const uint8_t pk[ANONCRED_PUBKEYLEN],
                             unsigned int tier);
void anoncred_verifier_clear (anoncred_verifier_state_t state);
/* Verify a disclosure proof against the public message (the tier's blocks, with
 * private positions zeroed). Returns 1 if valid, 0 otherwise. */
int anoncred_verifier_vrfy (anoncred_verifier_state_t state,
                            const uint8_t *pub_msg,
                            const unsigned int *pub_mvec, unsigned int npub,
                            const uint8_t *sig, size_t siglen);

#endif
