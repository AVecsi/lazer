#include "lazer.h"
#include "fdb-params.h"
#include "test.h"
#include <mpfr.h>
#include <time.h>

static double
wall (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/*
 * FULL Falcon-512 device-binding proof, bound to a COMMITTED public key.
 *
 * Three phases, two roles, talking only over serialized byte buffers:
 *
 *   - ISSUANCE (once, out of band): the holder samples fresh ternary
 *     randomness rc and publishes the credential commitment
 *
 *         t_h = AR*rc + AM*h        (over Rq; AR 8x16, AM 8x8 public)
 *
 *     The verifier stores t_h.  rc stays secret with the holder; it becomes
 *     part of every later proof's witness.  (t_h is hiding -- MLWE with the
 *     short rc -- so publishing it reveals nothing about h.)
 *
 *   - the SIGNER holds a Falcon-512 keypair (sk, pk) in a secure element and
 *     exposes only BLACKBOX signing: given a message, the SE samples a fresh
 *     40-byte salt, derives c = HashToPoint(salt||msg) as in plain Falcon, and
 *     returns a short (s1,s2) with s1 + s2*h = c (mod p=12289),
 *     ||(s1,s2)|| <= beta, together with the salt.  It then proves in ZERO
 *     KNOWLEDGE:
 *
 *         s1 + s2*h - c - p*k = 0     (8 quadratic block equations over Rp),
 *         AR*rc + AM*h - t_h  = 0     (8 linear block equations over Rq:
 *                                      the credential opens to THIS h),
 *         ||(s1,s2)||_2 <= beta,      ||rc||_2 <= sqrt(16*64),
 *         ||k||_inf <= B',            ||h||_inf <= (p-1)/2  (scaled rows of
 *                                      the same approximate-linf proof)
 *
 *     revealing neither h, the signature, nor rc (only c and t_h are
 *     public), and sends the resulting proof (with its ABDLOP commitment)
 *     to the verifier.  Because the SAME witness slots for h appear in the
 *     Falcon equations and in the opening equations, the proof shows the
 *     signature was made by the key committed in t_h -- not just any key.
 *
 *     The linf bound on h is NOT optional: without it the commitment is not
 *     binding mod p -- a cheater with its own key h* could open t_h as
 *     h' = h* + p*mu for an arbitrary mu mod q (p is invertible mod q) and
 *     the Falcon relation, which only sees h' mod p, would still close.
 *     Bounding |h|_inf ~ (p-1)/2 (up to the approximate-proof slack << q/p)
 *     forces h' == h (mod p) up to a short MSIS relation on [AR|AM].
 *
 *   - the VERIFIER never sees h, the signature, rc, or any other witness
 *     value.  It picks a MESSAGE and sends it to the signer; the signer
 *     returns the salt (with the proof).  The verifier recomputes
 *     c = HashToPoint(salt||msg) itself -- it never gets c directly and
 *     cannot choose it, matching a blackbox SE.  ALL public data is then a
 *     pure function of the public parameters, c, and the stored t_h, so the
 *     verifier derives it independently instead of trusting the signer: the
 *     commitment matrices (A1/A2prime/Bmat), AR/AM, the equations' R2/r1
 *     structure, AND the constant terms r0: r0[i] = -c_i for the Falcon
 *     equations (fdb_compute_r0_public, from the verifier's own c) and
 *     r0[NEQ+i] = -t_h[i] for the opening equations (from the verifier's own
 *     stored credential).  r0 is therefore NOT serialized; this is what binds
 *     the proof to the message AND to the committed key.  (An earlier version
 *     made r0 witness-derived and sent it on the wire, which was unsound --
 *     the equation became a tautology independent of c.  See
 *     falcon-devicebind-soundness-issue.md.)
 *
 * Deg-512 objects are the 8-block isoring representation.  RF = RP[X]/(X^8-Y)
 * with Y = X^8, so for s2 = sum_l s2iso[l] X^l and h = sum_k hiso[k] X^k the
 * quadratic term is the negacyclic convolution
 *   (s2*h)_iso[m] = sum_{l+k=m} hiso[k]*s2iso[l] + sum_{l+k=m+8} Y*hiso[k]*s2iso[l]
 * (coeff 1, resp. Y, in R2; validated against M_h*s2iso).  k is the mod-p
 * quotient (route b).
 *
 * Witness layout (m1 = 32 Ajtai/bounded, l = 16 BDLOP):
 *   s1[0..7]  = s1iso   s1[8..15] = s2iso   s1[16..31] = rc
 *   m[0..7]   = hiso    m[8..15]  = k
 */

#define NEQ 8    /* 8 quadratic block equations (Falcon relation) */
#define NLIN 8   /* 8 linear block equations (credential opening) */
#define NEQTOT (NEQ + NLIN)
#define RC_BLOCKS 16 /* ternary credential commitment randomness rc */
#define ANON_P 12289
#define ANON_DEG 64

/* |h|_inf <= (p-1)/2 = 6144 is proven through rows FSCALE*I of the Dm
 * selector: |FSCALE*h|_inf <= Bprime = 8958759 with
 * FSCALE = floor(Bprime/6144) = 1458 (1458*6144 = 8957952 <= Bprime). */
#define FDB_FSCALE 1458

/* Blackbox-signing model: the key lives in a secure element, so we can only
 * hand it a MESSAGE, not a challenge c.  The SE samples a fresh 40-byte salt,
 * derives c = HashToPoint(salt||msg) internally (plain Falcon), signs, and
 * returns the salt so both sides can recompute c.  The verifier picks the
 * message; c is a public function of (salt, msg) -- never chosen directly. */
#define FDB_MSG_BYTES 32
#define FDB_SALT_BYTES 40
#define FDB_PROOF_MAXLEN (1 << 20)

static const limb_t anon_q_limbs[] = { ANON_P };
static const int_t anon_q = { { (limb_t *)anon_q_limbs, 1, 0 } };
static const limb_t anon_inv2_limbs[] = { 6145UL };
static const int_t anon_inv2 = { { (limb_t *)anon_inv2_limbs, 1, 0 } };
static const limb_t anon_zero_limbs[] = { 0UL };
static const int_t anon_zero = { { (limb_t *)anon_zero_limbs, 1, 0 } };
static const polyring_t RP
    = { { anon_q, ANON_DEG, 14, 6, moduli_d64, 1, anon_zero, NULL, anon_inv2 } };
static const polyring_t RF
    = { { anon_q, 512, 14, 0, moduli_d64, 0, anon_zero, NULL, anon_inv2 } };

static void
_scatter_smat (spolymat_ptr R2, spolymat_ptr R2_, unsigned int m1,
               unsigned int Z, unsigned int l)
{
  const unsigned int nelems = R2_->nelems;
  unsigned int i, row, col;
  poly_ptr poly, poly2;
  (void)l;
  for (i = 0; i < nelems; i++)
    {
      poly = spolymat_get_elem (R2_, i);
      row = spolymat_get_row (R2_, i);
      col = spolymat_get_col (R2_, i);
      if (col >= 2 * m1)
        col += 2 * Z;
      if (row >= 2 * m1)
        row += 2 * Z;
      poly2 = spolymat_insert_elem (R2, row, col);
      poly_set (poly2, poly);
    }
  R2->sorted = 0;
  spolymat_sort (R2);
}

static void
_scatter_vec (spolyvec_ptr r1, spolyvec_ptr r1_, unsigned int m1,
              unsigned int Z)
{
  const unsigned int nelems = r1_->nelems;
  unsigned int i, elem;
  poly_ptr poly, poly2;
  for (i = 0; i < nelems; i++)
    {
      poly = spolyvec_get_elem (r1_, i);
      elem = spolyvec_get_elem_ (r1_, i);
      if (elem >= 2 * m1)
        elem += 2 * Z;
      poly2 = spolyvec_insert_elem (r1, elem);
      poly_set (poly2, poly);
    }
  r1->sorted = 1;
}

/* copy the coefficient VALUES of src into dst.  src/dst may live in different
 * rings (RP vs Rq) whose internal CRT/limb layouts are incompatible, so a raw
 * poly_set would copy garbage.  Both must be deg-64 and src already centered
 * (fromcrt+redc) into its signed small representative. */
static void
cpq (poly_ptr dst, poly_ptr src)
{
  int64_t c[ANON_DEG];
  poly_get_coeffvec_i64 (c, src);
  poly_set_coeffvec_i64 (dst, c);
}

/* multiply-by-x matrix over the isoring: M = lin_toisoring(x) for x in RF */
static void
mul_matrix (polymat_t M, poly_t x)
{
  polymat_t xmat;
  polyvec_t xvec, garb;
  polymat_alloc (xmat, RF, 1, 1);
  polyvec_alloc (xvec, RF, 1);
  polyvec_alloc (garb, RP, 8);
  polymat_set_elem (xmat, 0, 0, x);
  polyvec_set_elem (xvec, 0, x);
  lin_toisoring (M, garb, xmat, xvec);
  polyvec_free (garb);
  polyvec_free (xvec);
  polymat_free (xmat);
}

/* c = HashToPoint(salt || msg), as in plain Falcon.  Both the signer and the
 * verifier derive c this way from the public (salt, msg) -- c is never sent on
 * the wire, only the salt is (alongside the proof). */
static void
derive_challenge (int16_t cc16[512], const uint8_t salt[FDB_SALT_BYTES],
                  const uint8_t *msg, size_t msglen)
{
  falcon_hash_to_point (cc16, salt, FDB_SALT_BYTES, msg, msglen);
}

/*
 * SIGNER state: the Falcon keypair (held in plain) plus everything needed
 * to build the witness and the proof. Nothing here is ever read by the
 * verifier -- only the serialized credential (at issuance) and the proof
 * (out) cross the boundary.
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
  uint8_t sk[1281], pk[897];
  int16_t hc16[512], s1c16[512], s2c16[512];
  poly_t hf, cf, s1f, s2f;
  polymat_t Mh;
  polyvec_t hiso, ciso, s1iso, s2iso;

  /* credential: t_h = AR*rc + AM*h over Rq; rc is a long-lived secret */
  polyvec_t rc, th;

  /* witness + proof-output material */
  polyvec_t s1, s2, mvec, tA1, tA2, tB, hout, z1, z21, hint, z3, z4;
  poly_t cpoly;
  spolymat_t R2ii[NEQ]; /* the linear eqs have R2 = NULL */
  spolyvec_t r1ii[NEQTOT];
  spolymat_ptr R2[NEQTOT];
  spolyvec_ptr r1[NEQTOT];
  /* no r0: the signer never needs the equations' constant term (lnp_tbox_prove
   * works from the witness, and r0 is not serialized -- see fdb_encproof) */
  polymat_t Es0, Em0, Es1, Em1, Ds, Dm, A1, A2prime, Bmat, ARmat, AMmat;
  polyvec_t v0, v1, u;
  polymat_ptr Es[2], Em[2];
  polyvec_ptr vv[2];

  uint8_t hashp[32];
  double t_prove;
} fdb_signer_ctx_t[1];

/*
 * VERIFIER state: public data only.  There are no witness fields at all --
 * it is structurally impossible for this struct to hold secret material.
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
  poly_t r0ii[NEQTOT];
  poly_ptr r0[NEQTOT];

  spolymat_t R2ii[NEQ]; /* the linear eqs have R2 = NULL */
  spolyvec_t r1ii[NEQTOT];
  spolymat_ptr R2[NEQTOT];
  spolyvec_ptr r1[NEQTOT];
  polymat_t Es0, Em0, Es1, Em1, Ds, Dm, A1, A2prime, Bmat, ARmat, AMmat;
  polyvec_t v0, v1, u;
  polymat_ptr Es[2], Em[2];
  polyvec_ptr vv[2];

  uint8_t hashv[32];
  double t_verify;
} fdb_verifier_ctx_t[1];

/* ---- public equation structure: R2/r1 for the 8 quadratic (Falcon) block
 * equations and the 8 linear (credential opening) block equations, from the
 * negacyclic-convolution structure constants resp. the public AR/AM,
 * independent of the secret key h.  Identical computation on both the signer
 * and verifier side -- no secret data involved, so each side derives it
 * independently rather than one side handing the other a live pointer.
 *
 * local (n_) witness slot indices (m1 = 32):
 *   s1iso[i] = 2i,  s2iso[j] = 16+2j,  rc[j] = 32+2j,
 *   hiso[k]  = 64+2k,  k[i] = 80+2i                               ------- */
static void
build_equation_structure (spolymat_ptr R2[NEQTOT], spolyvec_ptr r1[NEQTOT],
                          spolymat_t R2ii[NEQ], spolyvec_t r1ii[NEQTOT],
                          polymat_t AR, polymat_t AM, polyring_srcptr Rq,
                          unsigned int m1, unsigned int Z, unsigned int l,
                          unsigned int n, unsigned int n_)
{
  spolymat_t R2_;
  spolyvec_t r1_;
  unsigned int i, j, kk;
  poly_ptr pe;

  spolymat_alloc (R2_, Rq, n_, n_, (n_ * n_ - n_) / 2 + n_);
  spolyvec_alloc (r1_, Rq, n_, n_);

  /* eq i (i < NEQ):  s1iso[i] + (s2*h)_iso[i] - c_i - p*k[i] = 0
   * (constant -c_i = r0[i] is public, added by the verifier -- not built
   * here). */
  for (i = 0; i < NEQ; i++)
    {
      spolymat_alloc (R2ii[i], Rq, n, n, (n * n - n) / 2 + n);
      spolyvec_alloc (r1ii[i], Rq, n, n);

      /* Quadratic term (s2*h)_iso[i].  RF = RP[X]/(X^8 - Y), Y = X^8, so with
       * s2 = sum_l s2iso[l] X^l, h = sum_k hiso[k] X^k:
       *   (s2*h)_iso[i] = sum_{l+k=i}   hiso[k]*s2iso[l]
       *                 + sum_{l+k=i+8} Y*hiso[k]*s2iso[l]
       * (verified against M_h*s2iso).  Couple s2iso[l]=slot 16+2l with
       * hiso[k]=slot 64+2k; coeff 1 when l+k=i, coeff Y (deg-1 monomial) on
       * the negacyclic wrap l+k=i+8.  The old Me[k] structure constants were
       * wrong -- they do not decompose M_h (see
       * falcon-devicebind-soundness-issue.md). */
      spolymat_set_empty (R2_);
      for (kk = 0; kk < 8; kk++)
        for (j = 0; j < 8; j++)
          {
            unsigned int sum = j + kk;
            if (sum != i && sum != i + 8)
              continue;
            pe = spolymat_insert_elem (R2_, 16 + 2 * j, 64 + 2 * kk);
            poly_set_zero (pe);
            if (sum == i)
              int_set_i64 (poly_get_coeff (pe, 0), 1); /* coeff 1 */
            else
              int_set_i64 (poly_get_coeff (pe, 1), 1); /* coeff Y */
          }
      spolymat_sort (R2_);

      spolyvec_set_empty (r1_);
      pe = spolyvec_insert_elem (r1_, 2 * i); /* + s1iso[i] */
      poly_set_one (pe);
      pe = spolyvec_insert_elem (r1_, 80 + 2 * i); /* - p*k[i] */
      poly_set_zero (pe);
      int_set_i64 (poly_get_coeff (pe, 0), -(int64_t)ANON_P);
      spolyvec_sort (r1_);

      spolymat_fromcrt (R2_);
      spolyvec_fromcrt (r1_);
      _scatter_smat (R2ii[i], R2_, m1, Z, l);
      _scatter_vec (r1ii[i], r1_, m1, Z);

      R2[i] = R2ii[i];
      r1[i] = r1ii[i];
    }

  /* eq NEQ+i (i < NLIN):  sum_j AR[i][j]*rc[j] + sum_k AM[i][k]*hiso[k]
   *                        - t_h[i] = 0
   * purely linear (R2 = NULL); the constant -t_h[i] = r0[NEQ+i] is public,
   * added by the verifier from its own stored credential. */
  for (i = 0; i < NLIN; i++)
    {
      spolyvec_alloc (r1ii[NEQ + i], Rq, n, n);

      spolyvec_set_empty (r1_);
      for (j = 0; j < RC_BLOCKS; j++)
        {
          pe = spolyvec_insert_elem (r1_, 32 + 2 * j); /* AR[i][j]*rc[j] */
          poly_set (pe, polymat_get_elem (AR, i, j));
        }
      for (kk = 0; kk < 8; kk++)
        {
          pe = spolyvec_insert_elem (r1_, 64 + 2 * kk); /* AM[i][k]*h[k] */
          poly_set (pe, polymat_get_elem (AM, i, kk));
        }
      spolyvec_sort (r1_);
      spolyvec_fromcrt (r1_);
      _scatter_vec (r1ii[NEQ + i], r1_, m1, Z);

      R2[NEQ + i] = NULL; /* no quadratic term */
      r1[NEQ + i] = r1ii[NEQ + i];
    }

  spolyvec_free (r1_);
  spolymat_free (R2_);
}

/* ---- norm-proof selector matrices: purely structural (which witness
 * slots count toward which norm bound), no secret dependency -- both sides
 * build these identically. ------------------------------------------------ */
static void
build_norm_selectors (polymat_t Es0, polymat_t Em0, polyvec_t v0,
                      polymat_t Es1, polymat_t Em1, polyvec_t v1,
                      polymat_t Ds, polymat_t Dm, polyvec_t u)
{
  unsigned int i;
  poly_ptr pe;

  /* l2 bound 0: ||(s1iso,s2iso)||_2 <= beta */
  polymat_set_zero (Es0);
  for (i = 0; i < 16; i++)
    poly_set_one (polymat_get_elem (Es0, i, i)); /* select s1[0..15] */
  polymat_set_zero (Em0);
  polyvec_set_zero (v0);

  /* l2 bound 1: ||rc||_2 <= sqrt(16*64) */
  polymat_set_zero (Es1);
  for (i = 0; i < RC_BLOCKS; i++)
    poly_set_one (polymat_get_elem (Es1, i, 16 + i)); /* select s1[16..31] */
  polymat_set_zero (Em1);
  polyvec_set_zero (v1);

  polymat_set_zero (Ds);
  polymat_set_zero (Dm);
  for (i = 0; i < 8; i++)
    poly_set_one (polymat_get_elem (Dm, i, 8 + i)); /* row i -> m[8+i]=k[i] */
  for (i = 0; i < 8; i++)
    {
      /* row 8+i -> FSCALE*m[i] = FSCALE*h[i]: |FSCALE*h|_inf <= Bprime
       * enforces |h|_inf <= (p-1)/2 (up to the approximate-proof slack),
       * which is what makes the credential commitment binding mod p (see
       * the header comment). */
      pe = polymat_get_elem (Dm, 8 + i, i);
      poly_set_zero (pe);
      int_set_i64 (poly_get_coeff (pe, 0), FDB_FSCALE);
    }
  polyvec_set_zero (u);
}

/* serialize the commitment + proof (mirrors lin-proofs.c's static
 * lnp_tbox_encproof; mutates its polyvec args in place, so call it last). */
static void
fdb_encproof (uint8_t *out, size_t *len, polyvec_t tA1, polyvec_t tB,
             polyvec_t hout, poly_t cpoly, polyvec_t z1,
             polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
             const lnp_tbox_params_t params)
{
  polyring_srcptr Rq = params->tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int d = Rq->d;
  INTVEC_T (coeffs, d, q->nlimbs);
  const unsigned int log2q = Rq->log2q;
  const unsigned int log2omega = params->quad_eval->quad_many->log2omega;
  const unsigned int D = params->quad_eval->quad_many->dcompress->D;
  const int64_t omega = params->quad_eval->quad_many->omega;
  coder_state_t cstate;
  size_t prooflen;
  INT_T (mod, q->nlimbs);

  /* r0 is NOT serialized: the constants -c (Falcon) and -t_h (opening) are
   * public and derived by the verifier itself (fdb_compute_r0_public resp.
   * the stored credential).  Sending them would let a dishonest signer choose
   * the equations' constant terms and break the binding to c and t_h (see
   * falcon-devicebind-soundness-issue.md). */
  coder_enc_begin (cstate, out);
  polyvec_fromcrt (tB);
  polyvec_mod (tB, tB);
  polyvec_redp (tB, tB);
  coder_enc_urandom3 (cstate, tB, q, log2q);
  polyvec_fromcrt (hout);
  polyvec_mod (hout, hout);
  polyvec_redp (hout, hout);
  coder_enc_urandom3 (cstate, hout, q, log2q);
  int_set_one (mod);
  int_lshift (mod, mod, log2q - D);
  polyvec_fromcrt (tA1);
  polyvec_mod (tA1, tA1);
  polyvec_redp (tA1, tA1);
  coder_enc_urandom3 (cstate, tA1, mod, log2q - D);

  int_set_i64 (mod, 2 * omega + 1);
  poly_fromcrt (cpoly);
  intvec_set (coeffs, poly_get_coeffvec (cpoly));
  intvec_redp (coeffs, coeffs, mod);
  coder_enc_urandom (cstate, coeffs, mod, log2omega);
  coder_enc_ghint3 (cstate, hint);
  polyvec_fromcrt (z1);
  polyvec_fromcrt (z21);
  polyvec_fromcrt (z3);
  polyvec_fromcrt (z4);
  polyvec_mod (z1, z1);
  polyvec_mod (z21, z21);
  polyvec_mod (z3, z3);
  polyvec_mod (z4, z4);
  polyvec_redc (z1, z1);
  polyvec_redc (z21, z21);
  polyvec_redc (z3, z3);
  polyvec_redc (z4, z4);
  coder_enc_grandom3 (cstate, z1, params->quad_eval->quad_many->log2stdev1);
  coder_enc_grandom3 (cstate, z21, params->quad_eval->quad_many->log2stdev2);
  coder_enc_grandom3 (cstate, z3, params->log2stdev3);
  coder_enc_grandom3 (cstate, z4, params->log2stdev4);
  coder_enc_end (cstate);

  prooflen = coder_get_offset (cstate) >> 3; /* bits -> bytes */
  if (len != NULL)
    *len = prooflen;
}

/* deserialize the commitment + proof (mirrors lin-proofs.c's static
 * lnp_tbox_decproof). Returns 1 on success, 0 on a malformed buffer. */
static int
fdb_decproof (size_t *len, const uint8_t *in, polyvec_t tA1, polyvec_t tB,
             polyvec_t hout, poly_t cpoly, polyvec_t z1,
             polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
             const lnp_tbox_params_t params)
{
  int_srcptr q = params->tbox->ring->q;
  const unsigned int log2q = params->tbox->ring->log2q;
  const unsigned int log2omega = params->quad_eval->quad_many->log2omega;
  const unsigned int D = params->quad_eval->quad_many->dcompress->D;
  const int64_t omega = params->quad_eval->quad_many->omega;
  coder_state_t cstate;
  intvec_ptr coeffs;
  size_t prooflen = 0;
  int succ = 0, rc;
  INT_T (mod, q->nlimbs);

  /* r0 is not on the wire (see fdb_encproof); the verifier derives it. */
  coder_dec_begin (cstate, in);

  rc = coder_dec_urandom3 (cstate, tB, q, log2q);
  if (rc != 0)
    goto ret;

  rc = coder_dec_urandom3 (cstate, hout, q, log2q);
  if (rc != 0)
    goto ret;

  int_set_one (mod);
  int_lshift (mod, mod, log2q - D);
  rc = coder_dec_urandom3 (cstate, tA1, mod, log2q - D);
  if (rc != 0)
    goto ret;

  int_set_i64 (mod, 2 * omega + 1);
  rc = coder_dec_urandom2 (cstate, cpoly, mod, log2omega);
  if (rc != 0)
    goto ret;
  coeffs = poly_get_coeffvec (cpoly);
  intvec_redc (coeffs, coeffs, mod);

  coder_dec_ghint3 (cstate, hint);

  coder_dec_grandom3 (cstate, z1, params->quad_eval->quad_many->log2stdev1);
  coder_dec_grandom3 (cstate, z21, params->quad_eval->quad_many->log2stdev2);
  coder_dec_grandom3 (cstate, z3, params->log2stdev3);
  coder_dec_grandom3 (cstate, z4, params->log2stdev4);

  rc = coder_dec_end (cstate);
  if (rc != 1)
    goto ret;

  prooflen = coder_get_offset (cstate) >> 3;
  succ = 1;
ret:
  if (len != NULL)
    *len = prooflen;
  return succ;
}

/* ==== signer =============================================================
 * Holds the Falcon-512 keypair in plain, signs whatever challenge it is
 * given, and builds the proof. */

static void
fdb_signer_keygen (fdb_signer_ctx_t s)
{
  falcon_keygen (s->sk, s->pk);
  falcon_decode_pubkey (s->hc16, s->pk);
  poly_set_coeffvec_i16 (s->hf, s->hc16);
}

/* isoring representations of the secret material (h, c, s1, s2) and M_h,
 * centered into their signed small representatives.  The mod-p quotient k
 * is computed later over Rq (integer arithmetic), NOT here over RP where it
 * would reduce to 0 (s1+s2h-c == 0 mod p). */
static void
build_isoring_reps (fdb_signer_ctx_t s)
{
  poly_toisoring (s->hiso, s->hf);
  poly_toisoring (s->ciso, s->cf);
  poly_toisoring (s->s1iso, s->s1f);
  poly_toisoring (s->s2iso, s->s2f);
  mul_matrix (s->Mh, s->hf);

  polyvec_fromcrt (s->s1iso);
  polyvec_redc (s->s1iso, s->s1iso);
  polyvec_fromcrt (s->s2iso);
  polyvec_redc (s->s2iso, s->s2iso);
  polyvec_fromcrt (s->hiso);
  polyvec_redc (s->hiso, s->hiso);
  polyvec_fromcrt (s->ciso);
  polyvec_redc (s->ciso, s->ciso);
  polymat_fromcrt (s->Mh);
  polymat_redc (s->Mh, s->Mh);
}

/* ==== issuance (once, out of band) ========================================
 * The holder samples fresh ternary commitment randomness rc and computes the
 * credential commitment t_h = AR*rc + AM*h over Rq.  t_h is public (the
 * verifier stores it); rc stays secret and is part of every later proof's
 * witness.  h enters in its centered isoring representation
 * (|h_i| <= (p-1)/2), matching the witness slots m[0..7]. */
static void
fdb_signer_issue (fdb_signer_ctx_t s)
{
  polymat_t ARc, AMc;
  polyvec_t hq;
  uint8_t rcseed[32];
  unsigned int i;
  INT_T (lo, s->Rq->q->nlimbs);
  INT_T (hi, s->Rq->q->nlimbs);

  /* centered isoring rep of h (idempotent; also rebuilt per-proof) */
  poly_toisoring (s->hiso, s->hf);
  polyvec_fromcrt (s->hiso);
  polyvec_redc (s->hiso, s->hiso);

  polyvec_alloc (hq, s->Rq, 8);
  for (i = 0; i < 8; i++)
    cpq (polyvec_get_elem (hq, i), polyvec_get_elem (s->hiso, i));

  bytes_urandom (rcseed, sizeof (rcseed)); /* rc is a fresh SECRET */
  int_set_i64 (lo, -1);
  int_set_i64 (hi, 1);
  polyvec_urandom_bnd (s->rc, lo, hi, rcseed, 0);

  /* t_h = AR*rc + AM*h.  polyvec_mul/addmul NTT-mutate their matrix and
   * vector args in place, so work on copies (rc must stay in its centered
   * coefficient representation for the witness). */
  polymat_alloc (ARc, s->Rq, NLIN, RC_BLOCKS);
  polymat_alloc (AMc, s->Rq, NLIN, 8);
  polymat_set (ARc, s->ARmat);
  polymat_set (AMc, s->AMmat);
  {
    polyvec_t rcc;
    polyvec_alloc (rcc, s->Rq, RC_BLOCKS);
    polyvec_set (rcc, s->rc);
    polyvec_mul (s->th, ARc, rcc);
    polyvec_addmul (s->th, AMc, hq, 0);
    polyvec_free (rcc);
  }
  polyvec_fromcrt (s->th);
  polyvec_mod (s->th, s->th);
  polyvec_redc (s->th, s->th);

  polymat_free (ARc);
  polymat_free (AMc);
  polyvec_free (hq);
}

/* witness: s1[0..7]=s1iso, s1[8..15]=s2iso, s1[16..31]=rc ; m[0..7]=hiso
 * (m[8..15]=k is set later, by compute_quotient) */
static void
build_witness (fdb_signer_ctx_t s)
{
  unsigned int blk;

  polyvec_set_zero (s->s1);
  polyvec_set_zero (s->mvec);
  for (blk = 0; blk < 8; blk++)
    {
      cpq (polyvec_get_elem (s->s1, blk), polyvec_get_elem (s->s1iso, blk));
      cpq (polyvec_get_elem (s->s1, 8 + blk), polyvec_get_elem (s->s2iso, blk));
      cpq (polyvec_get_elem (s->mvec, blk), polyvec_get_elem (s->hiso, blk));
    }
  for (blk = 0; blk < RC_BLOCKS; blk++)
    poly_set (polyvec_get_elem (s->s1, 16 + blk),
              polyvec_get_elem (s->rc, blk)); /* same ring Rq */
}

/* k = (s1iso + M_h*s2iso - ciso)/p computed over Rq: the integer product
 * M_h*s2iso ~ 2^31 (s2 is the SHORT Falcon signature) stays well below q, so
 * s1iso + M_h*s2iso - ciso is the true integer p*k (not reduced mod p).
 * Also completes the witness: writes k into s->mvec[8..15].
 * Returns 1 if the division is exact (relation holds mod p), 0 otherwise. */
static int
compute_quotient (fdb_signer_ctx_t s)
{
  polyring_srcptr Rq = s->Rq;
  polymat_t Mhq;
  polyvec_t s2q, prodq, ciq;
  int64_t pc[8 * ANON_DEG], kc[ANON_DEG];
  int64_t mk = 0;
  unsigned int i, j;
  int ok = 1;

  polymat_alloc (Mhq, Rq, 8, 8);
  polyvec_alloc (s2q, Rq, 8);
  polyvec_alloc (prodq, Rq, 8);
  polyvec_alloc (ciq, Rq, 8);
  for (i = 0; i < 8; i++)
    {
      for (j = 0; j < 8; j++)
        cpq (polymat_get_elem (Mhq, i, j), polymat_get_elem (s->Mh, i, j));
      cpq (polyvec_get_elem (s2q, i), polyvec_get_elem (s->s2iso, i));
      cpq (polyvec_get_elem (ciq, i), polyvec_get_elem (s->ciso, i));
    }
  polyvec_mul (prodq, Mhq, s2q); /* = M_h*s2iso over Rq (NTT-mutates Mhq) */
  polyvec_fromcrt (prodq);
  for (i = 0; i < 8; i++)
    {
      poly_add (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (s->s1, i), 0);
      poly_sub (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (ciq, i), 0);
    }
  polyvec_redc (prodq, prodq); /* centered; = p*k */
  polyvec_get_coeffvec_i64 (pc, prodq);
  for (i = 0; i < 8 * s->d; i++)
    if (pc[i] % ANON_P != 0)
      ok = 0;
  for (i = 0; i < 8; i++)
    {
      for (j = 0; j < s->d; j++)
        {
          int64_t a;
          kc[j] = pc[i * s->d + j] / ANON_P;
          a = kc[j] < 0 ? -kc[j] : kc[j];
          if (a > mk)
            mk = a;
        }
      poly_set_coeffvec_i64 (polyvec_get_elem (s->mvec, 8 + i), kc);
    }
  fprintf (stderr, "  |k|_inf = %lld  (Bprime=%d)  exact-div-by-p: %s\n",
           (long long)mk, 8958759, ok ? "yes" : "NO");
  polymat_free (Mhq);
  polyvec_free (s2q);
  polyvec_free (prodq);
  polyvec_free (ciq);
  return ok;
}

/* r0 for each of the 8 quadratic equations is the PUBLIC constant -c_i.
 *
 * With the corrected quadratic structure constants (see
 * build_equation_structure) the equation evaluates, at the honest witness, to
 *   <r1,s> + <s,R2 s> = s1iso[i] + (s2*h)_iso[i] - p*k[i] = ciso[i]
 * (the last step by the exact mod-p quotient k), so the block equation
 * s1 + (s2*h) - c - p*k = 0 closes exactly with r0[i] = -ciso[i].
 *
 * r0 is thus a public function of the challenge c alone -- it carries no
 * witness information and is computed identically by the signer and the
 * verifier (fdb_compute_r0_public), never transmitted.  This is what binds
 * the proof to the verifier's challenge; see
 * falcon-devicebind-soundness-issue.md. */
static void
fdb_compute_r0_public (poly_ptr r0[NEQ], polyvec_t ciso)
{
  unsigned int i;
  for (i = 0; i < NEQ; i++)
    {
      cpq (r0[i], polyvec_get_elem (ciso, i)); /* r0[i] = -ciso[i] */
      poly_neg_self (r0[i]);
    }
}

/* commitment randomness s2 ~ {-1,0,1} */
static void
sample_commitment_randomness (fdb_signer_ctx_t s, uint8_t seed[32])
{
  INT_T (lo, s->Rq->q->nlimbs);
  INT_T (hi, s->Rq->q->nlimbs);

  int_set_i64 (lo, -1);
  int_set_i64 (hi, 1);
  polyvec_urandom_bnd (s->s2, lo, hi, seed, 200);
}

/* l2 proof slack values: bound 0 is ||(s1iso,s2iso)||_2 <= beta, bound 1 is
 * ||rc||_2 <= sqrt(16*64).  The Es selectors themselves are public/structural
 * (see build_norm_selectors); only these slack values depend on the secret
 * witness.  Slack for bound i goes into extension slot s1[m1+i] as the binary
 * expansion of B_i^2 - ||part_i||^2. */
static void
setup_l2_slack (fdb_signer_ctx_t s, const lnp_tbox_params_t params)
{
  INT_T (l2sqr, 2 * s->Rq->q->nlimbs);
  INT_T (l2b, 2 * s->Rq->q->nlimbs);
  polyvec_t part, upsilon;

  polyvec_get_subvec (upsilon, s->s1, s->m1, s->Z, 1);

  polyvec_get_subvec (part, s->s1, 0, 16, 1);
  int_set (l2b, params->l2Bsqr[0]);
  polyvec_l2sqr (l2sqr, part);
  int_sub (l2b, l2b, l2sqr);
  int_binexp (polyvec_get_elem (upsilon, 0), NULL, l2b);

  polyvec_get_subvec (part, s->s1, 16, RC_BLOCKS, 1);
  int_set (l2b, params->l2Bsqr[1]);
  polyvec_l2sqr (l2sqr, part);
  int_sub (l2b, l2b, l2sqr);
  int_binexp (polyvec_get_elem (upsilon, 1), NULL, l2b);
}

static void
fdb_signer_init (fdb_signer_ctx_t s, const lnp_tbox_params_t params,
                 uint8_t seed[32])
{
  polyring_srcptr Rq;

  s->tbox = params->tbox;
  s->quad = params->quad_eval->quad_many;
  s->quade = params->quad_eval;
  s->Rq = s->tbox->ring;
  s->d = polyring_get_deg (s->Rq);
  s->m1 = s->tbox->m1 - params->Z; /* real bounded length = 32 */
  s->Z = params->Z;
  s->l = s->tbox->l; /* 16 */
  s->lambda = s->quade->lambda;
  s->n = 2 * (s->tbox->m1 + s->quad->l);
  s->n_ = 2 * (s->m1 + s->l);
  Rq = s->Rq;

  poly_alloc (s->hf, RF);
  poly_alloc (s->cf, RF);
  poly_alloc (s->s1f, RF);
  poly_alloc (s->s2f, RF);
  fdb_signer_keygen (s);

  polyvec_alloc (s->hiso, RP, 8);
  polyvec_alloc (s->ciso, RP, 8);
  polyvec_alloc (s->s1iso, RP, 8);
  polyvec_alloc (s->s2iso, RP, 8);
  polymat_alloc (s->Mh, RP, 8, 8);

  polyvec_alloc (s->rc, Rq, RC_BLOCKS);
  polyvec_alloc (s->th, Rq, NLIN);

  poly_alloc (s->cpoly, Rq);
  polyvec_alloc (s->s1, Rq, s->tbox->m1);
  polyvec_alloc (s->s2, Rq, s->tbox->m2);
  polyvec_alloc (s->mvec, Rq, s->tbox->l + s->tbox->lext);
  polyvec_alloc (s->tA1, Rq, s->tbox->kmsis);
  polyvec_alloc (s->tA2, Rq, s->tbox->kmsis);
  polyvec_alloc (s->tB, Rq, s->tbox->l + s->tbox->lext);
  polyvec_alloc (s->hout, Rq, s->lambda / 2);
  polyvec_alloc (s->z1, Rq, s->tbox->m1);
  polyvec_alloc (s->z21, Rq, s->tbox->m2 - s->tbox->kmsis);
  polyvec_alloc (s->hint, Rq, s->tbox->kmsis);
  polyvec_alloc (s->z3, Rq, 256 / s->d);
  polyvec_alloc (s->z4, Rq, 256 / s->d);

  polymat_alloc (s->A1, Rq, s->tbox->kmsis, s->tbox->m1);
  polymat_alloc (s->A2prime, Rq, s->tbox->kmsis, s->tbox->m2 - s->tbox->kmsis);
  polymat_alloc (s->Bmat, Rq, s->tbox->l + s->tbox->lext,
                s->tbox->m2 - s->tbox->kmsis);
  polymat_alloc (s->ARmat, Rq, NLIN, RC_BLOCKS);
  polymat_alloc (s->AMmat, Rq, NLIN, 8);
  polymat_alloc (s->Es0, Rq, params->n[0], s->m1);
  polymat_alloc (s->Em0, Rq, params->n[0], s->l);
  polyvec_alloc (s->v0, Rq, params->n[0]);
  polymat_alloc (s->Es1, Rq, params->n[1], s->m1);
  polymat_alloc (s->Em1, Rq, params->n[1], s->l);
  polyvec_alloc (s->v1, Rq, params->n[1]);
  polymat_alloc (s->Ds, Rq, params->nprime, s->m1);
  polymat_alloc (s->Dm, Rq, params->nprime, s->l);
  polyvec_alloc (s->u, Rq, params->nprime);
  s->Es[0] = s->Es0;
  s->Em[0] = s->Em0;
  s->vv[0] = s->v0;
  s->Es[1] = s->Es1;
  s->Em[1] = s->Em1;
  s->vv[1] = s->v1;

  abdlop_keygen (s->A1, s->A2prime, s->Bmat, seed, s->tbox); /* public setup */
  polymat_urandom (s->ARmat, Rq->q, Rq->log2q, seed, 100); /* public setup */
  polymat_urandom (s->AMmat, Rq->q, Rq->log2q, seed, 101);
  build_equation_structure (s->R2, s->r1, s->R2ii, s->r1ii, s->ARmat,
                            s->AMmat, Rq, s->m1, s->Z, s->l, s->n, s->n_);
  build_norm_selectors (s->Es0, s->Em0, s->v0, s->Es1, s->Em1, s->v1, s->Ds,
                        s->Dm, s->u);
}

/* BLACKBOX-sign the given message (SE samples the salt, derives c, returns
 * the salt in `salt`), then derive c = HashToPoint(salt||msg), build the
 * witness and the proof, and serialize the commitment + proof to
 * `proof`/`*prooflen`.  Returns 0 if the relation/iso sanity check fails
 * (should not happen for a genuine Falcon signature), 1 on success. */
static int
fdb_signer_prove (fdb_signer_ctx_t s, uint8_t *proof, size_t *prooflen,
                  const uint8_t *msg, size_t msglen,
                  uint8_t salt[FDB_SALT_BYTES],
                  const lnp_tbox_params_t params, uint8_t seed[32])
{
  int16_t cc16[512];
  int64_t cf64[512];
  unsigned int i;
  double t0, t1;

  /* blackbox SE: message in -> (salt, s1, s2) out; the key never leaves. */
  falcon_sign_message (salt, s->s1c16, s->s2c16, msg, msglen, s->sk);

  /* recompute the challenge c the SE hashed to (public: salt + msg) */
  derive_challenge (cc16, salt, msg, msglen);
  for (i = 0; i < 512; i++)
    cf64[i] = cc16[i];
  poly_set_coeffvec_i64 (s->cf, cf64);

  poly_set_coeffvec_i16 (s->s1f, s->s1c16);
  poly_set_coeffvec_i16 (s->s2f, s->s2c16);

  build_isoring_reps (s);
  build_witness (s);
  if (!compute_quotient (s))
    {
      fprintf (stderr, "  [WARN] s1+s2h-c not 0 mod p (relation/iso mismatch)\n");
      return 0;
    }

  /* r0 is not needed on the signer side: lnp_tbox_prove does not take the
   * input equations' constant term (it works from the committed witness), and
   * r0 is not serialized -- the verifier derives -c and -t_h itself. */
  sample_commitment_randomness (s, seed);
  setup_l2_slack (s, params);

  memset (s->hashp, 0xff, 32);
  t0 = wall ();
  abdlop_commit (s->tA1, s->tA2, s->tB, s->s1, s->mvec, s->s2, s->A1,
                 s->A2prime, s->Bmat, s->tbox);
  lnp_tbox_prove (s->hashp, s->tB, s->hout, s->cpoly, s->z1, s->z21, s->hint,
                  s->z3, s->z4, s->s1, s->mvec, s->s2, s->tA2, s->A1,
                  s->A2prime, s->Bmat, s->R2, s->r1, NEQTOT, NULL, NULL, NULL,
                  0, s->Es, s->Em, s->vv, NULL, NULL, NULL, s->Ds, s->Dm,
                  s->u, seed, params);
  t1 = wall ();
  s->t_prove = t1 - t0;

  fdb_encproof (proof, prooflen, s->tA1, s->tB, s->hout, s->cpoly,
               s->z1, s->z21, s->hint, s->z3, s->z4, params);
  return 1;
}

/* ==== verifier ============================================================
 * Public data only: never sees the Falcon key, the signature, rc, or any
 * other witness value. */

static void
fdb_verifier_init (fdb_verifier_ctx_t v, const lnp_tbox_params_t params,
                   uint8_t seed[32])
{
  polyring_srcptr Rq;
  unsigned int i;

  v->tbox = params->tbox;
  v->quad = params->quad_eval->quad_many;
  v->quade = params->quad_eval;
  v->Rq = v->tbox->ring;
  v->d = polyring_get_deg (v->Rq);
  v->m1 = v->tbox->m1 - params->Z;
  v->Z = params->Z;
  v->l = v->tbox->l;
  v->lambda = v->quade->lambda;
  v->n = 2 * (v->tbox->m1 + v->quad->l);
  v->n_ = 2 * (v->m1 + v->l);
  Rq = v->Rq;

  polyvec_alloc (v->th, Rq, NLIN);

  poly_alloc (v->cpoly, Rq);
  polyvec_alloc (v->tA1, Rq, v->tbox->kmsis);
  polyvec_alloc (v->tB, Rq, v->tbox->l + v->tbox->lext);
  polyvec_alloc (v->hout, Rq, v->lambda / 2);
  polyvec_alloc (v->z1, Rq, v->tbox->m1);
  polyvec_alloc (v->z21, Rq, v->tbox->m2 - v->tbox->kmsis);
  polyvec_alloc (v->hint, Rq, v->tbox->kmsis);
  polyvec_alloc (v->z3, Rq, 256 / v->d);
  polyvec_alloc (v->z4, Rq, 256 / v->d);

  polymat_alloc (v->A1, Rq, v->tbox->kmsis, v->tbox->m1);
  polymat_alloc (v->A2prime, Rq, v->tbox->kmsis, v->tbox->m2 - v->tbox->kmsis);
  polymat_alloc (v->Bmat, Rq, v->tbox->l + v->tbox->lext,
                v->tbox->m2 - v->tbox->kmsis);
  polymat_alloc (v->ARmat, Rq, NLIN, RC_BLOCKS);
  polymat_alloc (v->AMmat, Rq, NLIN, 8);
  polymat_alloc (v->Es0, Rq, params->n[0], v->m1);
  polymat_alloc (v->Em0, Rq, params->n[0], v->l);
  polyvec_alloc (v->v0, Rq, params->n[0]);
  polymat_alloc (v->Es1, Rq, params->n[1], v->m1);
  polymat_alloc (v->Em1, Rq, params->n[1], v->l);
  polyvec_alloc (v->v1, Rq, params->n[1]);
  polymat_alloc (v->Ds, Rq, params->nprime, v->m1);
  polymat_alloc (v->Dm, Rq, params->nprime, v->l);
  polyvec_alloc (v->u, Rq, params->nprime);
  v->Es[0] = v->Es0;
  v->Em[0] = v->Em0;
  v->vv[0] = v->v0;
  v->Es[1] = v->Es1;
  v->Em[1] = v->Em1;
  v->vv[1] = v->v1;

  for (i = 0; i < NEQTOT; i++)
    {
      poly_alloc (v->r0ii[i], Rq);
      v->r0[i] = v->r0ii[i];
    }

  abdlop_keygen (v->A1, v->A2prime, v->Bmat, seed, v->tbox); /* public setup */
  polymat_urandom (v->ARmat, Rq->q, Rq->log2q, seed, 100); /* public setup */
  polymat_urandom (v->AMmat, Rq->q, Rq->log2q, seed, 101);
  build_equation_structure (v->R2, v->r1, v->R2ii, v->r1ii, v->ARmat,
                            v->AMmat, Rq, v->m1, v->Z, v->l, v->n, v->n_);
  build_norm_selectors (v->Es0, v->Em0, v->v0, v->Es1, v->Em1, v->v1, v->Ds,
                        v->Dm, v->u);
}

/* the opening equations' constant terms r0[NEQ+i] = -t_h[i], from the
 * verifier's OWN stored credential (never taken from the signer's proof). */
static void
fdb_verifier_refresh_credential_r0 (fdb_verifier_ctx_t v)
{
  unsigned int i;
  for (i = 0; i < NLIN; i++)
    {
      poly_set (v->r0[NEQ + i], polyvec_get_elem (v->th, i));
      poly_neg_self (v->r0[NEQ + i]);
    }
}

/* store the credential t_h received at issuance (public commitment to h) */
static void
fdb_verifier_set_credential (fdb_verifier_ctx_t v, polyvec_t th)
{
  polyvec_set (v->th, th);
  fdb_verifier_refresh_credential_r0 (v);
}

/* pick a fresh random message for the wire.  The verifier chooses only the
 * message; the challenge c is derived (by both sides) from HashToPoint of the
 * salt the SE returns -- it is never chosen directly. */
static void
fdb_verifier_new_message (uint8_t msg[FDB_MSG_BYTES])
{
  bytes_urandom (msg, FDB_MSG_BYTES);
}

/* deserialize the received commitment + proof and check it against this
 * verifier's own independently derived public state.  r0[0..NEQ) = -c is
 * derived here from c = HashToPoint(salt||msg) -- the verifier recomputes c
 * itself from the message it chose and the salt returned by the SE (never
 * taken from the signer's proof); r0[NEQ..NEQTOT) = -t_h comes from the
 * stored credential.  This is what binds the proof to the message AND to the
 * committed key. */
static int
fdb_verifier_verify (fdb_verifier_ctx_t v, const uint8_t *proof,
                     size_t prooflen, const uint8_t *msg, size_t msglen,
                     const uint8_t salt[FDB_SALT_BYTES],
                     const lnp_tbox_params_t params)
{
  double t1, t2;
  size_t declen;
  int b;
  int16_t cc16[512];
  int64_t cf64[512];
  poly_t cf;
  polyvec_t ciso;
  unsigned int i;

  t1 = wall ();
  b = fdb_decproof (&declen, proof, v->tA1, v->tB, v->hout, v->cpoly,
                    v->z1, v->z21, v->hint, v->z3, v->z4, params);
  if (!b || declen != prooflen)
    return 0;

  /* r0 = -c, from c = HashToPoint(salt||msg) recomputed by the verifier */
  poly_alloc (cf, RF);
  polyvec_alloc (ciso, RP, 8);
  derive_challenge (cc16, salt, msg, msglen);
  for (i = 0; i < 512; i++)
    cf64[i] = cc16[i];
  poly_set_coeffvec_i64 (cf, cf64);
  poly_toisoring (ciso, cf);
  polyvec_fromcrt (ciso);
  polyvec_redc (ciso, ciso);
  fdb_compute_r0_public (v->r0, ciso);
  polyvec_free (ciso);
  poly_free (cf);

  /* fdb_decproof leaves values in their encoded (redp) representation;
   * lnp_tbox_verify expects the centered one (mirrors lin-proofs.c's
   * _lin_verifier_verify post-decode reduction). */
  polyvec_mod (v->hout, v->hout);
  polyvec_redc (v->hout, v->hout);
  poly_mod (v->cpoly, v->cpoly);
  poly_redc (v->cpoly, v->cpoly);
  polyvec_mod (v->z1, v->z1);
  polyvec_redc (v->z1, v->z1);
  polyvec_mod (v->z21, v->z21);
  polyvec_redc (v->z21, v->z21);
  polyvec_mod (v->z3, v->z3);
  polyvec_redc (v->z3, v->z3);
  polyvec_mod (v->z4, v->z4);
  polyvec_redc (v->z4, v->z4);

  memset (v->hashv, 0xff, 32);
  b = lnp_tbox_verify (v->hashv, v->hout, v->cpoly, v->z1, v->z21, v->hint,
                       v->z3, v->z4, v->tA1, v->tB, v->A1, v->A2prime,
                       v->Bmat, v->R2, v->r1, v->r0, NEQTOT, NULL, NULL, NULL,
                       0, v->Es, v->Em, v->vv, NULL, NULL, NULL, v->Ds,
                       v->Dm, v->u, params);
  t2 = wall ();
  v->t_verify = t2 - t1;
  return b;
}

/* ---- honest-run report: hash check + serialized proof size --------------- */
static int
report_honest_result (fdb_signer_ctx_t s, fdb_verifier_ctx_t v,
                      size_t prooflen, int bres)
{
  bres = bres && (memcmp (s->hashp, v->hashv, 32) == 0);
  fprintf (stderr,
           "  proof size = %zu bytes (%.2f KiB)   prove = %.3f s   "
           "verify = %.3f s\n",
           prooflen, prooflen / 1024.0, s->t_prove, v->t_verify);
  return bres;
}

static int
run (uint8_t seed[32], const lnp_tbox_params_t params)
{
  fdb_signer_ctx_t signer;
  fdb_verifier_ctx_t verifier;
  uint8_t msg[FDB_MSG_BYTES];
  uint8_t salt[FDB_SALT_BYTES];
  static uint8_t proof[FDB_PROOF_MAXLEN];
  size_t prooflen;
  int bres;

  fdb_signer_init (signer, params, seed);
  fdb_verifier_init (verifier, params, seed);

  /* issuance (once): holder computes t_h = AR*rc + AM*h and hands the
   * PUBLIC t_h to the verifier, which stores it as the credential. */
  fdb_signer_issue (signer);
  fdb_verifier_set_credential (verifier, signer->th);

  /* verifier -> wire: message */
  fdb_verifier_new_message (msg);

  /* signer -> wire: commitment + proof + salt (r0, c, and t_h's opening are
   * NOT sent) */
  if (!fdb_signer_prove (signer, proof, &prooflen, msg, FDB_MSG_BYTES, salt,
                         params, seed))
    return -1;

  /* honest: verify against the message the proof was made for -> accept */
  bres = fdb_verifier_verify (verifier, proof, prooflen, msg, FDB_MSG_BYTES,
                              salt, params);
  bres = report_honest_result (signer, verifier, prooflen, bres);

  /* soundness / binding: verify the SAME proof (and salt) against a DIFFERENT
   * message -> must reject.  The verifier derives c' = HashToPoint(salt||msg')
   * and r0 = -c', so the committed witness no longer satisfies
   * s1 + (s2*h) - c' - p*k = 0 and verification must fail.  This exercises the
   * reject path that the earlier (tautological-r0) construction could not; see
   * falcon-devicebind-soundness-issue.md. */
  {
    uint8_t msg2[FDB_MSG_BYTES];
    int bad;
    fdb_verifier_new_message (msg2);
    bad = fdb_verifier_verify (verifier, proof, prooflen, msg2, FDB_MSG_BYTES,
                               salt, params);
    if (bad != 0)
      {
        fprintf (stderr,
                 "  [FAIL] proof accepted under a DIFFERENT message -- not "
                 "bound to the message!\n");
        bres = 0;
      }
    else
      fprintf (stderr,
               "  [OK] proof rejected under a different message\n");
  }

  /* binding to the COMMITTED KEY: verify the same proof against a TAMPERED
   * credential t_h' != t_h -> must reject.  The verifier's opening equations
   * get r0 = -t_h', so the committed witness (rc, h) no longer satisfies
   * AR*rc + AM*h - t_h' = 0.  This is the committed-public-key binding: a
   * proof made for one credential does not verify against another. */
  {
    int bad;
    poly_ptr t0 = polyvec_get_elem (verifier->th, 0);
    INT_T (one, verifier->Rq->q->nlimbs);
    int_set_i64 (one, 1);
    int_add (poly_get_coeff (t0, 0), poly_get_coeff (t0, 0), one);
    fdb_verifier_refresh_credential_r0 (verifier);
    bad = fdb_verifier_verify (verifier, proof, prooflen, msg, FDB_MSG_BYTES,
                               salt, params);
    if (bad != 0)
      {
        fprintf (stderr,
                 "  [FAIL] proof accepted under a DIFFERENT credential -- not "
                 "bound to the committed key!\n");
        bres = 0;
      }
    else
      fprintf (stderr,
               "  [OK] proof rejected under a different credential\n");
  }
  return bres;
}

int
main (void)
{
  uint8_t seed[32];
  lazer_init ();
  bytes_urandom (seed, sizeof (seed));

  fprintf (stderr,
           "FULL Falcon-512 device-binding proof (committed public key)\n");
  TEST_EXPECT (run (seed, fdb_param) == 1);
  fprintf (stderr,
           "[OK] honest Falcon device-binding proof verifies against the "
           "committed key\n");

  mpfr_free_cache ();
  TEST_PASS ();
}
