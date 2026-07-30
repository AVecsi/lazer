#ifndef FDB_H
#define FDB_H

/*
 * Falcon device binding (FDB): a zero-knowledge proof that a Falcon-512
 * signature was produced by the key COMMITTED in a credential, without
 * revealing the key, the signature, or the commitment randomness.
 *
 * Three phases, two roles, talking only over serialized byte buffers:
 *
 *   - ISSUANCE (once, out of band): the holder samples fresh ternary
 *     randomness rc and publishes the credential commitment
 *
 *         t_h = AR*rc + AM*h        (over Rq; AR 8x16, AM 8x8 public)
 *
 *     The verifier receives t_h in serialized form (fdb_signer_issue ->
 *     fdb_verifier_set_credential) and stores it. rc stays secret with the
 *     holder; it becomes part of every later proof's witness. (t_h is hiding
 *     -- MLWE with the short rc -- so publishing it reveals nothing about h.)
 *
 *   - the SIGNER holds a Falcon-512 keypair (sk, pk) and exposes only
 *     BLACKBOX signing: given a message, it samples a fresh 40-byte salt,
 *     derives c = HashToPoint(salt||msg) as in plain Falcon, and gets a short
 *     (s1,s2) with s1 + s2*h = c (mod p=12289), ||(s1,s2)|| <= beta. It then
 *     proves in ZERO KNOWLEDGE (fdb_signer_prove):
 *
 *         s1 + s2*h - c - p*k = 0     (8 quadratic block equations over Rp),
 *         AR*rc + AM*h - t_h  = 0     (8 linear block equations over Rq:
 *                                      the credential opens to THIS h),
 *         ||(s1,s2)||_2 <= beta,      ||rc||_2 <= sqrt(16*64),
 *         ||(k, FSCALE*h)||_inf <= B' (one approximate-linf proof; its
 *                                      scaled rows bound |h|_inf)
 *
 *     revealing neither h, the signature, nor rc (only c and t_h are public).
 *     Because the SAME witness slots for h appear in the Falcon equations and
 *     in the opening equations, the proof shows the signature was made by the
 *     key committed in t_h -- not just any key.
 *
 *     The linf bound on h is NOT optional: without it the commitment is not
 *     binding mod p -- a cheater with its own key h* could open t_h as
 *     h' = h* + p*mu for an arbitrary mu mod q (p is invertible mod q) and the
 *     Falcon relation, which only sees h' mod p, would still close. The proof
 *     extracts |h'|_inf <= psi*B'/FSCALE << q, so any second opening of t_h is
 *     a SHORT solution on [AR|AM]: binding reduces to MSIS (see
 *     src/fdb-params.sage for the calibration of FSCALE and B').
 *
 *   - the VERIFIER (fdb_verifier_vrfy) never sees h, the signature, rc, or any
 *     other witness value. It picks a MESSAGE and sends it to the signer; the
 *     signer returns the salt (with the proof). The verifier recomputes
 *     c = HashToPoint(salt||msg) itself -- it never gets c directly and cannot
 *     choose it, matching a blackbox secure element. ALL public data is a pure
 *     function of the public parameters, c, and the stored t_h, so the verifier
 *     derives it independently instead of trusting the signer: the commitment
 *     matrices (A1/A2prime/Bmat), AR/AM, the equations' R2/r1 structure, AND
 *     the constant terms r0 (r0[i] = -c_i for the Falcon equations,
 *     r0[NEQ+i] = -t_h[i] for the opening equations). r0 is therefore NOT
 *     serialized; this is what binds the proof to the message AND to the
 *     committed key. (An earlier version made r0 witness-derived and sent it
 *     on the wire, which was unsound -- the equation became a tautology
 *     independent of c. See falcon-devicebind-soundness-issue.md.)
 *
 * Both roles derive the whole public setup from a shared 32-byte seed, so the
 * two sides cannot drift apart.  Both also derive the Fiat-Shamir transcript
 * the same way -- H(seed || salt || msg || t_h), then the ABDLOP commitment
 * (tA1, tB) hashed in -- so the challenge is bound to the public parameters,
 * the statement and the commitment.
 *
 * Parameters come from src/fdb-params.h (lnp_tbox_params_t fdb_param),
 * generated from src/fdb-params.sage via scripts/lnp-tbox-codegen.sage.
 */

#include "lazer.h"
#include <stddef.h>
#include <stdint.h>

/* Falcon-512 encoded key sizes (see blindsig.h: PUBKEYLEN/PRIVKEYLEN). */
#define FDB_PUBKEYLEN 897
#define FDB_PRIVKEYLEN 1281

#define FDB_NEQ 8  /* 8 quadratic block equations (Falcon relation) */
#define FDB_NLIN 8 /* 8 linear block equations (credential opening) */
#define FDB_NEQTOT (FDB_NEQ + FDB_NLIN)
#define FDB_RC_BLOCKS 16 /* ternary credential commitment randomness rc */

/* Blackbox-signing model: the key may live in a secure element, so we can only
 * hand it a MESSAGE, not a challenge c. The signer samples a fresh 40-byte
 * salt, derives c = HashToPoint(salt||msg) internally (plain Falcon), signs,
 * and returns the salt so both sides can recompute c. */
#define FDB_SALT_BYTES 40

/* Generous upper bounds for encoded objects. */
#define FDB_PROOF_MAXLEN (1 << 20)
#define FDB_CRED_MAXLEN (1 << 13) /* NLIN * 64 coeffs * 51 bits < 8 KiB */

/*
 * SIGNER state: the Falcon keypair (held in plain) plus everything needed to
 * build the witness and the proof. Nothing here is ever read by the verifier
 * -- only the serialized credential (at issuance) and the proof cross the
 * boundary.
 */
typedef struct
{
  abdlop_params_srcptr tbox;
  abdlop_params_srcptr quad;
  lnp_quad_eval_params_srcptr quade;
  polyring_srcptr Rq;
  unsigned int d;
  unsigned int m1;
  unsigned int Z;
  unsigned int l;
  unsigned int lambda;
  unsigned int n;
  unsigned int n_;

  /* Falcon keypair, in plain, and the per-challenge signature material */
  uint8_t sk[FDB_PRIVKEYLEN], pk[FDB_PUBKEYLEN];
  int16_t hc16[512], s1c16[512], s2c16[512];
  poly_t hf, cf, s1f, s2f;
  polymat_t Mh;
  polyvec_t hiso, ciso, s1iso, s2iso;

  /* credential: t_h = AR*rc + AM*h over Rq; rc is a long-lived secret */
  polyvec_t rc, th;

  /* witness + proof-output material */
  polyvec_t s1, s2, mvec, tA1, tA2, tB, hout, z1, z21, hint, z3, z4;
  poly_t cpoly;
  spolymat_t R2ii[FDB_NEQ]; /* the linear eqs have R2 = NULL */
  spolyvec_t r1ii[FDB_NEQTOT];
  spolymat_ptr R2[FDB_NEQTOT];
  spolyvec_ptr r1[FDB_NEQTOT];
  /* no r0: the signer never needs the equations' constant term (lnp_tbox_prove
   * works from the witness, and r0 is not serialized) */
  /* Em/vv entries and Ds/u are zero and passed to lnp-tbox as NULL */
  polymat_t Es0, Es1, Dm, A1, A2prime, Bmat, ARmat, AMmat;
  polymat_ptr Es[2], Em[2];
  polyvec_ptr vv[2];

  uint8_t seed[32]; /* the PUBLIC setup seed (part of the transcript) */
  int issued;       /* 1 once fdb_signer_issue has run (rc/th are set) */
  uint8_t hashp[32];
} fdb_signer_state_struct;
typedef fdb_signer_state_struct fdb_signer_state_t[1];

/*
 * VERIFIER state: public data only. There are no witness fields at all -- it
 * is structurally impossible for this struct to hold secret material.
 */
typedef struct
{
  abdlop_params_srcptr tbox;
  abdlop_params_srcptr quad;
  lnp_quad_eval_params_srcptr quade;
  polyring_srcptr Rq;
  unsigned int d;
  unsigned int m1;
  unsigned int Z;
  unsigned int l;
  unsigned int lambda;
  unsigned int n;
  unsigned int n_;

  /* the stored credential (public commitment to the device key) */
  polyvec_t th;

  /* decode targets for the received proof */
  polyvec_t tA1, tB, hout, z1, z21, hint, z3, z4;
  poly_t cpoly;
  poly_t r0ii[FDB_NEQTOT];
  poly_ptr r0[FDB_NEQTOT];

  spolymat_t R2ii[FDB_NEQ]; /* the linear eqs have R2 = NULL */
  spolyvec_t r1ii[FDB_NEQTOT];
  spolymat_ptr R2[FDB_NEQTOT];
  spolyvec_ptr r1[FDB_NEQTOT];
  /* Em/vv entries and Ds/u are zero and passed to lnp-tbox as NULL */
  polymat_t Es0, Es1, Dm, A1, A2prime, Bmat, ARmat, AMmat;
  polymat_ptr Es[2], Em[2];
  polyvec_ptr vv[2];

  uint8_t seed[32]; /* the PUBLIC setup seed (part of the transcript) */
  int has_cred;     /* 1 once fdb_verifier_set_credential has succeeded */
  size_t credlen;   /* the one valid encoded credential length (fixed-width) */
  uint8_t hashv[32];
} fdb_verifier_state_struct;
typedef fdb_verifier_state_struct fdb_verifier_state_t[1];

/* Falcon-512 keypair (compressed encodings). */
void fdb_keygen (uint8_t sk[FDB_PRIVKEYLEN], uint8_t pk[FDB_PUBKEYLEN]);

/* Initialize a signer holding the given keypair. seed is the PUBLIC 32-byte
 * setup seed shared with the verifier (it expands to the commitment matrices
 * and AR/AM); it is not secret and must never be used as prover randomness. */
void fdb_signer_init (fdb_signer_state_t state, const uint8_t seed[32],
                      const uint8_t sk[FDB_PRIVKEYLEN],
                      const uint8_t pk[FDB_PUBKEYLEN]);
void fdb_signer_clear (fdb_signer_state_t state);

/* ISSUANCE: sample fresh secret randomness rc, compute the credential
 * commitment t_h = AR*rc + AM*h, and serialize t_h into cred (at most
 * FDB_CRED_MAXLEN bytes). rc is kept in the state and enters every later
 * proof's witness, so a second call invalidates credentials issued before it.
 * Returns 1. */
int fdb_signer_issue (fdb_signer_state_t state, uint8_t *cred,
                      size_t *credlen);

/* Blackbox-sign msg (a fresh salt is sampled, c = HashToPoint(salt||msg) is
 * derived internally), then prove in zero knowledge that the signature is
 * valid under the key committed by the last fdb_signer_issue. Outputs the
 * salt and the serialized commitment + proof (at most FDB_PROOF_MAXLEN
 * bytes). Requires a prior fdb_signer_issue. Returns 1 on success, 0 if no
 * credential has been issued yet or if the Falcon relation does not hold mod p
 * (the latter must not happen for a genuine signature). */
int fdb_signer_prove (fdb_signer_state_t state, uint8_t *proof,
                      size_t *prooflen, uint8_t salt[FDB_SALT_BYTES],
                      const uint8_t *msg, size_t msglen);

/* Initialize a verifier from the same public setup seed as the signer. */
void fdb_verifier_init (fdb_verifier_state_t state, const uint8_t seed[32]);
void fdb_verifier_clear (fdb_verifier_state_t state);

/* Store the credential received at issuance (the public commitment to h), from
 * its serialized wire form. Must be called before fdb_verifier_vrfy. Returns 1
 * on success, 0 on a malformed buffer. */
int fdb_verifier_set_credential (fdb_verifier_state_t state,
                                 const uint8_t *cred, size_t credlen);

/* Verify a proof for msg with the salt the signer returned, against the stored
 * credential. The challenge c = HashToPoint(salt||msg) is recomputed here.
 * Requires a prior fdb_verifier_set_credential (returns 0 without one).
 * Returns 1 if the proof is valid, 0 otherwise. */
int fdb_verifier_vrfy (fdb_verifier_state_t state, const uint8_t *proof,
                       size_t prooflen, const uint8_t *msg, size_t msglen,
                       const uint8_t salt[FDB_SALT_BYTES]);

#endif
