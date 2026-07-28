#include "fdb-params.h"
#include "lazer.h"
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
 *     The verifier receives t_h in serialized form (like everything else
 *     that crosses the boundary) and stores it.  rc stays secret with the
 *     holder; it becomes part of every later proof's witness.  (t_h is
 *     hiding -- MLWE with the short rc -- so publishing it reveals nothing
 *     about h.)
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
 *         ||(k, FSCALE*h)||_inf <= B' (one approximate-linf proof; its
 *                                      scaled rows bound |h|_inf)
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
 *     The proof extracts |h'|_inf <= psi*B'/FSCALE << q, so any second
 *     opening of t_h is a SHORT solution on [AR|AM]: binding reduces to
 *     MSIS (see fdb-params.sage for the calibration of FSCALE and B').
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
 *   (s2*h)_iso[m] = sum_{l+k=m} hiso[k]*s2iso[l] + sum_{l+k=m+8}
 * Y*hiso[k]*s2iso[l] (coeff 1, resp. Y, in R2; validated against M_h*s2iso).
 * k is the mod-p quotient (route b).
 *
 * Witness layout (m1 = 32 Ajtai/bounded, l = 16 BDLOP):
 *   s1[0..7]  = s1iso   s1[8..15] = s2iso   s1[16..31] = rc
 *   m[0..7]   = hiso    m[8..15]  = k
 */

#define NEQ 8  /* 8 quadratic block equations (Falcon relation) */
#define NLIN 8 /* 8 linear block equations (credential opening) */
#define NEQTOT (NEQ + NLIN)
#define RC_BLOCKS 16 /* ternary credential commitment randomness rc */
#define ANON_P 12289
#define ANON_DEG 64

/* Witness block offsets -- the single source for the layout
 *   s1 = (s1iso, s2iso, rc)   m = (hiso, k)
 * (see the header comment).  EVAR_* map a block's slot to its index among
 * the quadratic-equation variables, where every slot contributes an
 * (x, sigma(x)) pair (so indices double) and the BDLOP slots follow the
 * FDB_M1 real Ajtai slots. */
#define S1OFF_S1ISO 0
#define S1OFF_S2ISO 8
#define S1OFF_RC (S1OFF_S2ISO + 8)
#define FDB_M1 (S1OFF_RC + RC_BLOCKS) /* real (bounded) Ajtai length = 32 */
#define MOFF_HISO 0
#define MOFF_K 8
#define EVAR_S1(off) (2 * (off))
#define EVAR_M(off) (2 * (FDB_M1 + (off)))

/* |h|_inf is proven through rows FSCALE*I of the Dm selector: the
 * approximate-linf proof on (k, FSCALE*h) extracts |FSCALE*h|_inf <=
 * psi*Bprime, i.e. |h|_inf <= psi*Bprime/FSCALE -- short enough that any
 * second opening of the credential commitment is a short MSIS solution on
 * [AR|AM].  FSCALE and Bprime are calibrated in fdb-params.sage (Bprime is
 * the l2 budget of the whole vector (k, FSCALE*h), sizing stdev4); keep
 * these two defines in sync with the values there.  FDB_BPRIME is only
 * used for diagnostics -- the generated params carry its effects. */
#define FDB_FSCALE 64
#define FDB_BPRIME 9021921

/* Blackbox-signing model: the key lives in a secure element, so we can only
 * hand it a MESSAGE, not a challenge c.  The SE samples a fresh 40-byte salt,
 * derives c = HashToPoint(salt||msg) internally (plain Falcon), signs, and
 * returns the salt so both sides can recompute c.  The verifier picks the
 * message; c is a public function of (salt, msg) -- never chosen directly. */
#define FDB_MSG_BYTES 32
#define FDB_SALT_BYTES 40
#define FDB_PROOF_MAXLEN (1 << 20)
#define FDB_CRED_MAXLEN (1 << 13) /* NLIN * 64 coeffs * 51 bits < 8 KiB */

static const limb_t anon_q_limbs[] = { ANON_P };
static const int_t anon_q = { { (limb_t *)anon_q_limbs, 1, 0 } };
static const limb_t anon_inv2_limbs[] = { 6145UL };
static const int_t anon_inv2 = { { (limb_t *)anon_inv2_limbs, 1, 0 } };
static const limb_t anon_zero_limbs[] = { 0UL };
static const int_t anon_zero = { { (limb_t *)anon_zero_limbs, 1, 0 } };
static const polyring_t RP = { { anon_q, ANON_DEG, 14, 6, moduli_d64, 1,
                                 anon_zero, NULL, anon_inv2 } };
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
  /* Em/vv entries and Ds/u are zero and passed to lnp-tbox as NULL */
  polymat_t Es0, Es1, Dm, A1, A2prime, Bmat, ARmat, AMmat;
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
  /* Em/vv entries and Ds/u are zero and passed to lnp-tbox as NULL */
  polymat_t Es0, Es1, Dm, A1, A2prime, Bmat, ARmat, AMmat;
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
 * independently rather than one side handing the other a live pointer
 * (both call fdb_public_setup).
 *
 * local (n_) witness slot indices come from the EVAR_S1/EVAR_M layout
 * macros (e.g. s1iso[i] = EVAR_S1 (S1OFF_S1ISO + i)).            ------- */
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
            /* R2[s2iso[j], hiso[kk]] = gamma: adds gamma*s2iso[j]*hiso[kk]
             * to the equation */
            pe = spolymat_insert_elem (R2_, EVAR_S1 (S1OFF_S2ISO + j),
                                       EVAR_M (MOFF_HISO + kk));
            poly_set_zero (pe);
            if (sum == i)
              int_set_i64 (poly_get_coeff (pe, 0), 1); /* gamma = 1 */
            else
              int_set_i64 (poly_get_coeff (pe, 1), 1); /* gamma = Y (wrap) */
          }
      spolymat_sort (R2_);

      spolyvec_set_empty (r1_);
      /* r1[s1iso[i]] = 1 */
      pe = spolyvec_insert_elem (r1_, EVAR_S1 (S1OFF_S1ISO + i));
      poly_set_one (pe);
      /* r1[k[i]] = -p */
      pe = spolyvec_insert_elem (r1_, EVAR_M (MOFF_K + i));
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
          /* r1[rc[j]] = AR[i][j]: adds AR[i][j]*rc[j] to the equation */
          pe = spolyvec_insert_elem (r1_, EVAR_S1 (S1OFF_RC + j));
          poly_set (pe, polymat_get_elem (AR, i, j));
        }
      for (kk = 0; kk < 8; kk++)
        {
          /* r1[hiso[kk]] = AM[i][kk]: adds AM[i][kk]*hiso[kk] */
          pe = spolyvec_insert_elem (r1_, EVAR_M (MOFF_HISO + kk));
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
 * build these identically.
 *
 * lnp-tbox proves, for the committed witness (s1, m):
 *   exact l2 bound i:   ||Es_i*s1 + Em_i*m + v_i||_2  <= sqrt(l2Bsqr[i])
 *   approximate linf:   ||Ds*s1  + Dm*m  + u||_inf    <= Bprime (with slack)
 * so a selector row picks (a scalar multiple of) one witness block and the
 * norm is taken over the whole selected vector.  Here:
 *   Es0*s1 = (s1iso, s2iso)            -> bound beta   (Falcon signature)
 *   Es1*s1 = rc                        -> bound sqrt(16*64) (ternary rc)
 *   Dm*m   = (k, FSCALE*h)             -> bound Bprime
 * (Em0/Em1/Ds/v0/v1/u are zero: no BDLOP slot enters an l2 bound and no
 * Ajtai slot enters the linf bound.  lnp_tbox_prove/verify take NULL for
 * zero operands, so those are never allocated.) -------------------------- */
static void
build_norm_selectors (polymat_t Es0, polymat_t Es1, polymat_t Dm)
{
  unsigned int i;
  poly_ptr pe;

  /* l2 bound 0: ||(s1iso,s2iso)||_2 <= beta */
  polymat_set_zero (Es0);
  for (i = 0; i < S1OFF_RC; i++)
    /* Es0[i][i] = 1  =>  (Es0*s1)[i] = s1[i]  (i.e. s1iso,s2iso) */
    poly_set_one (polymat_get_elem (Es0, i, i));

  /* l2 bound 1: ||rc||_2 <= sqrt(16*64) */
  polymat_set_zero (Es1);
  for (i = 0; i < RC_BLOCKS; i++)
    /* Es1[i][rc[i]] = 1  =>  (Es1*s1)[i] = rc[i] */
    poly_set_one (polymat_get_elem (Es1, i, S1OFF_RC + i));

  polymat_set_zero (Dm);
  for (i = 0; i < 8; i++)
    /* Dm[i][k[i]] = 1  =>  (Dm*m)[i] = k[i] */
    poly_set_one (polymat_get_elem (Dm, i, MOFF_K + i));
  for (i = 0; i < 8; i++)
    {
      /* Dm[8+i][hiso[i]] = FSCALE  =>  (Dm*m)[8+i] = FSCALE*h[i]:
       * |FSCALE*h|_inf <= psi*Bprime bounds |h|_inf, which is what makes
       * the credential commitment binding (see the header comment and
       * fdb-params.sage). */
      pe = polymat_get_elem (Dm, 8 + i, MOFF_HISO + i);
      poly_set_zero (pe);
      int_set_i64 (poly_get_coeff (pe, 0), FDB_FSCALE);
    }
}

/* ---- public setup, shared verbatim by both roles: the commitment matrices,
 * AR/AM, the equations' R2/r1 structure and the norm selectors are all pure
 * functions of (seed, params).  Factored into one routine so the signer and
 * the verifier cannot drift apart -- each side calls this instead of
 * trusting data derived by the other. ------------------------------------ */
static void
fdb_public_setup (polymat_t A1, polymat_t A2prime, polymat_t Bmat,
                  polymat_t ARmat, polymat_t AMmat, spolymat_ptr R2[NEQTOT],
                  spolyvec_ptr r1[NEQTOT], spolymat_t R2ii[NEQ],
                  spolyvec_t r1ii[NEQTOT], polymat_t Es0, polymat_t Es1,
                  polymat_t Dm, abdlop_params_srcptr tbox, polyring_srcptr Rq,
                  unsigned int m1, unsigned int Z, unsigned int l,
                  unsigned int n, unsigned int n_, uint8_t seed[32])
{
  abdlop_keygen (A1, A2prime, Bmat, seed, tbox);
  /* domains 100/101 separate AR/AM from abdlop_keygen's seed expansions */
  polymat_urandom (ARmat, Rq->q, Rq->log2q, seed, 100);
  polymat_urandom (AMmat, Rq->q, Rq->log2q, seed, 101);
  build_equation_structure (R2, r1, R2ii, r1ii, ARmat, AMmat, Rq, m1, Z, l, n,
                            n_);
  build_norm_selectors (Es0, Es1, Dm);
}

/* serialize the commitment + proof (mirrors lin-proofs.c's static
 * lnp_tbox_encproof; mutates its polyvec args in place, so call it last). */
static void
fdb_encproof (uint8_t *out, size_t *len, polyvec_t tA1, polyvec_t tB,
              polyvec_t hout, poly_t cpoly, polyvec_t z1, polyvec_t z21,
              polyvec_t hint, polyvec_t z3, polyvec_t z4,
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

/* serialize the credential t_h (NLIN Rq polynomials): even the issuance
 * data crosses the signer/verifier boundary only as bytes, exercising the
 * same canonical wire encoding a real deployment would use.  Mutates th
 * into its positive (redp) representation, like fdb_encproof's tB. */
static void
fdb_enccred (uint8_t *out, size_t *len, polyvec_t th, polyring_srcptr Rq)
{
  coder_state_t cstate;

  coder_enc_begin (cstate, out);
  polyvec_fromcrt (th);
  polyvec_mod (th, th);
  polyvec_redp (th, th);
  coder_enc_urandom3 (cstate, th, Rq->q, Rq->log2q);
  coder_enc_end (cstate);
  *len = coder_get_offset (cstate) >> 3; /* bits -> bytes */
}

/* deserialize a received credential into th (left in the encoded redp
 * representation).  Returns 1 on success, 0 on a malformed buffer. */
static int
fdb_deccred (size_t *len, const uint8_t *in, polyvec_t th, polyring_srcptr Rq)
{
  coder_state_t cstate;
  int rc;

  coder_dec_begin (cstate, in);
  rc = coder_dec_urandom3 (cstate, th, Rq->q, Rq->log2q);
  if (rc != 0)
    return 0;
  if (coder_dec_end (cstate) != 1)
    return 0;
  *len = coder_get_offset (cstate) >> 3;
  return 1;
}

/* deserialize the commitment + proof (mirrors lin-proofs.c's static
 * lnp_tbox_decproof). Returns 1 on success, 0 on a malformed buffer. */
static int
fdb_decproof (size_t *len, const uint8_t *in, polyvec_t tA1, polyvec_t tB,
              polyvec_t hout, poly_t cpoly, polyvec_t z1, polyvec_t z21,
              polyvec_t hint, polyvec_t z3, polyvec_t z4,
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
  falcon_keygen (s->sk, s->pk);           /* (sk, pk): Falcon-512 keypair */
  falcon_decode_pubkey (s->hc16, s->pk);  /* hc16 = h, coeffs in [0,p) */
  poly_set_coeffvec_i16 (s->hf, s->hc16); /* hf = h as an RF element */
}

/* v <- uniform ternary {-1,0,1}^(len*d) from (seed, dom).  Used for the
 * two long-lived secrets sampled in this file (rc and the commitment
 * randomness s2) -- one implementation so the sampling convention cannot
 * silently diverge between them. */
static void
sample_ternary (polyvec_t v, polyring_srcptr Rq, const uint8_t seed[32],
                uint32_t dom)
{
  INT_T (lo, Rq->q->nlimbs);
  INT_T (hi, Rq->q->nlimbs);

  int_set_i64 (lo, -1);
  int_set_i64 (hi, 1);
  polyvec_urandom_bnd (v, lo, hi, seed, dom);
}

/* hiso = iso(h), centered: the 8-block isoring rep of the deg-512 key h
 * over RP with coefficients in [-(p-1)/2, (p-1)/2].  The ONE recipe used
 * both at issuance (h as committed in t_h) and at prove time (h as placed
 * in the witness) -- they must agree or the opening equations do not
 * close. */
static void
compute_hiso (fdb_signer_ctx_t s)
{
  poly_toisoring (s->hiso, s->hf);
  polyvec_fromcrt (s->hiso);
  polyvec_redc (s->hiso, s->hiso);
}

/* isoring representations of the secret material (h, c, s1, s2) and M_h,
 * centered into their signed small representatives.  The mod-p quotient k
 * is computed later over Rq (integer arithmetic), NOT here over RP where it
 * would reduce to 0 (s1+s2h-c == 0 mod p). */
static void
build_isoring_reps (fdb_signer_ctx_t s)
{
  compute_hiso (s);                  /* hiso  = iso(h)   (8 RP blocks) */
  poly_toisoring (s->ciso, s->cf);   /* ciso  = iso(c)                 */
  poly_toisoring (s->s1iso, s->s1f); /* s1iso = iso(s1)                */
  poly_toisoring (s->s2iso, s->s2f); /* s2iso = iso(s2)                */
  mul_matrix (s->Mh,
              s->hf); /* M_h: 8x8 RP matrix with M_h*iso(x) = iso(h*x) */

  /* center everything: coefficients into [-(p-1)/2, (p-1)/2] */
  polyvec_fromcrt (s->s1iso);
  polyvec_redc (s->s1iso, s->s1iso);
  polyvec_fromcrt (s->s2iso);
  polyvec_redc (s->s2iso, s->s2iso);
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

  /* hiso = iso(h), centered (the same recipe the witness uses) */
  compute_hiso (s);

  /* hq = hiso lifted into Rq (same integer coefficient values) */
  polyvec_alloc (hq, s->Rq, 8);
  for (i = 0; i < 8; i++)
    cpq (polyvec_get_elem (hq, i), polyvec_get_elem (s->hiso, i));

  bytes_urandom (rcseed, sizeof (rcseed)); /* rc is a fresh SECRET */
  /* rc <- uniform {-1,0,1}^(16*64)  (ternary commitment randomness) */
  sample_ternary (s->rc, s->Rq, rcseed, 0);

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
    /* th = AR * rc          (8x16 matrix-vector product over Rq) */
    polyvec_mul (s->th, ARc, rcc);
    /* th = th + AM * hq  =  AR*rc + AM*h */
    polyvec_addmul (s->th, AMc, hq, 0);
    polyvec_free (rcc);
  }
  /* th <- centered coefficient rep mod q */
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
      /* s1[blk]    = s1iso[blk]  (lift RP -> Rq) */
      cpq (polyvec_get_elem (s->s1, blk), polyvec_get_elem (s->s1iso, blk));
      /* s1[8+blk]  = s2iso[blk] */
      cpq (polyvec_get_elem (s->s1, S1OFF_S2ISO + blk),
           polyvec_get_elem (s->s2iso, blk));
      /* m[blk]     = hiso[blk] */
      cpq (polyvec_get_elem (s->mvec, MOFF_HISO + blk),
           polyvec_get_elem (s->hiso, blk));
    }
  /* s1[16+blk] = rc[blk]  (already over Rq) */
  for (blk = 0; blk < RC_BLOCKS; blk++)
    poly_set (polyvec_get_elem (s->s1, S1OFF_RC + blk),
              polyvec_get_elem (s->rc, blk));
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
  /* lift M_h, s2iso, ciso from RP into Rq (same integer values) */
  for (i = 0; i < 8; i++)
    {
      for (j = 0; j < 8; j++)
        cpq (polymat_get_elem (Mhq, i, j), polymat_get_elem (s->Mh, i, j));
      cpq (polyvec_get_elem (s2q, i), polyvec_get_elem (s->s2iso, i));
      cpq (polyvec_get_elem (ciq, i), polyvec_get_elem (s->ciso, i));
    }
  /* prodq = M_h * s2iso  = iso(h*s2) as INTEGERS (no mod-p reduction:
   * |coeffs| ~ 2^31 << q)  (NTT-mutates Mhq) */
  polyvec_mul (prodq, Mhq, s2q);
  polyvec_fromcrt (prodq);
  for (i = 0; i < 8; i++)
    {
      /* prodq[i] = prodq[i] + s1iso[i] */
      poly_add (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (s->s1, i), 0);
      /* prodq[i] = prodq[i] - ciso[i]   => prodq = s1 + s2*h - c = p*k */
      poly_sub (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (ciq, i), 0);
    }
  polyvec_redc (prodq, prodq); /* centered; = p*k */
  polyvec_get_coeffvec_i64 (pc, prodq);
  /* check p | (s1 + s2*h - c) coefficient-wise (Falcon relation mod p) */
  for (i = 0; i < 8 * s->d; i++)
    if (pc[i] % ANON_P != 0)
      ok = 0;
  for (i = 0; i < 8; i++)
    {
      for (j = 0; j < s->d; j++)
        {
          int64_t a;
          /* k[i]_j = (s1 + s2*h - c)_j / p   (exact integer division) */
          kc[j] = pc[i * s->d + j] / ANON_P;
          a = kc[j] < 0 ? -kc[j] : kc[j];
          if (a > mk)
            mk = a; /* mk = ||k||_inf so far */
        }
      /* m[8+i] = k[i]  (quotient goes into the BDLOP part of the witness) */
      poly_set_coeffvec_i64 (polyvec_get_elem (s->mvec, MOFF_K + i), kc);
    }
  fprintf (stderr, "  |k|_inf = %lld  (Bprime=%d)  exact-div-by-p: %s\n",
           (long long)mk, FDB_BPRIME, ok ? "yes" : "NO");
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
      cpq (r0[i],
           polyvec_get_elem (ciso, i)); /* r0[i] = ciso[i] (lift to Rq) */
      poly_neg_self (r0[i]);            /* r0[i] = -ciso[i] */
    }
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

  /* upsilon = s1[m1..m1+Z): the Z extension slots holding the slack values */
  polyvec_get_subvec (upsilon, s->s1, s->m1, s->Z, 1);

  /* part = (s1iso, s2iso) = s1[0..15] */
  polyvec_get_subvec (part, s->s1, S1OFF_S1ISO, S1OFF_RC, 1);
  int_set (l2b, params->l2Bsqr[0]); /* l2b  = beta^2 */
  polyvec_l2sqr (l2sqr, part);      /* l2sqr = ||(s1iso,s2iso)||_2^2 */
  int_sub (l2b, l2b, l2sqr);        /* l2b  = beta^2 - ||.||^2  (>= 0) */
  /* upsilon[0] = binary expansion of the slack (proves ||.||^2 <= beta^2) */
  int_binexp (polyvec_get_elem (upsilon, 0), NULL, l2b);

  /* part = rc = s1[16..31] */
  polyvec_get_subvec (part, s->s1, S1OFF_RC, RC_BLOCKS, 1);
  int_set (l2b, params->l2Bsqr[1]); /* l2b  = 16*64 */
  polyvec_l2sqr (l2sqr, part);      /* l2sqr = ||rc||_2^2 */
  int_sub (l2b, l2b, l2sqr);        /* l2b  = 16*64 - ||rc||^2  (>= 0) */
  /* upsilon[1] = binary expansion of the slack (proves ||rc||^2 <= 16*64) */
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
  polymat_alloc (s->Es1, Rq, params->n[1], s->m1);
  polymat_alloc (s->Dm, Rq, params->nprime, s->l);
  s->Es[0] = s->Es0;
  s->Em[0] = NULL; /* zero operands: lnp-tbox takes NULL */
  s->vv[0] = NULL;
  s->Es[1] = s->Es1;
  s->Em[1] = NULL;
  s->vv[1] = NULL;

  fdb_public_setup (s->A1, s->A2prime, s->Bmat, s->ARmat, s->AMmat, s->R2,
                    s->r1, s->R2ii, s->r1ii, s->Es0, s->Es1, s->Dm, s->tbox,
                    Rq, s->m1, s->Z, s->l, s->n, s->n_, seed);
}

/* BLACKBOX-sign the given message (SE samples the salt, derives c, returns
 * the salt in `salt`), then derive c = HashToPoint(salt||msg), build the
 * witness and the proof, and serialize the commitment + proof to
 * `proof`/`*prooflen`.  Returns 0 if the relation/iso sanity check fails
 * (should not happen for a genuine Falcon signature), 1 on success. */
static int
fdb_signer_prove (fdb_signer_ctx_t s, uint8_t *proof, size_t *prooflen,
                  const uint8_t *msg, size_t msglen,
                  uint8_t salt[FDB_SALT_BYTES], const lnp_tbox_params_t params)
{
  int16_t cc16[512];
  int64_t cf64[512];
  uint8_t secseed[32];
  unsigned int i;
  double t0, t1;

  /* blackbox SE: message in -> (salt, s1, s2) out; the key never leaves.
   * (s1, s2) short with s1 + s2*h = HashToPoint(salt||msg) (mod p). */
  falcon_sign_message (salt, s->s1c16, s->s2c16, msg, msglen, s->sk);

  /* recompute the challenge c the SE hashed to (public: salt + msg) */
  derive_challenge (cc16, salt, msg, msglen); /* c = HashToPoint(salt||msg) */
  for (i = 0; i < 512; i++)
    cf64[i] = cc16[i];
  poly_set_coeffvec_i64 (s->cf, cf64); /* cf = c as an RF element */

  poly_set_coeffvec_i16 (s->s1f, s->s1c16); /* s1f = s1 as an RF element */
  poly_set_coeffvec_i16 (s->s2f, s->s2c16); /* s2f = s2 as an RF element */

  build_isoring_reps (s);
  build_witness (s);
  if (!compute_quotient (s))
    {
      fprintf (stderr,
               "  [WARN] s1+s2h-c not 0 mod p (relation/iso mismatch)\n");
      return 0;
    }

  /* r0 is not needed on the signer side: lnp_tbox_prove does not take the
   * input equations' constant term (it works from the committed witness), and
   * r0 is not serialized -- the verifier derives -c and -t_h itself. */

  /* the prover's randomness -- the commitment randomness s2 and (inside
   * lnp_tbox_prove) the Gaussian masks y1/y3/y4 -- must be FRESH AND SECRET.
   * It must never derive from the public setup seed the verifier also
   * holds: with a known seed, z1 = y1 + c*s1 hands the whole witness to
   * anyone who can recompute y1. */
  bytes_urandom (secseed, sizeof (secseed));
  sample_ternary (s->s2, s->Rq, secseed, 200); /* commitment randomness */
  setup_l2_slack (s, params);

  memset (s->hashp, 0xff, 32);
  t0 = wall ();
  abdlop_commit (s->tA1, s->tA2, s->tB, s->s1, s->mvec, s->s2, s->A1,
                 s->A2prime, s->Bmat, s->tbox);
  lnp_tbox_prove (s->hashp, s->tB, s->hout, s->cpoly, s->z1, s->z21, s->hint,
                  s->z3, s->z4, s->s1, s->mvec, s->s2, s->tA2, s->A1,
                  s->A2prime, s->Bmat, s->R2, s->r1, NEQTOT, NULL, NULL, NULL,
                  0, s->Es, s->Em, s->vv, NULL, NULL, NULL, NULL, s->Dm, NULL,
                  secseed, params);
  t1 = wall ();
  s->t_prove = t1 - t0;

  fdb_encproof (proof, prooflen, s->tA1, s->tB, s->hout, s->cpoly, s->z1,
                s->z21, s->hint, s->z3, s->z4, params);
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
  polymat_alloc (v->Es1, Rq, params->n[1], v->m1);
  polymat_alloc (v->Dm, Rq, params->nprime, v->l);
  v->Es[0] = v->Es0;
  v->Em[0] = NULL; /* zero operands: lnp-tbox takes NULL */
  v->vv[0] = NULL;
  v->Es[1] = v->Es1;
  v->Em[1] = NULL;
  v->vv[1] = NULL;

  for (i = 0; i < NEQTOT; i++)
    {
      poly_alloc (v->r0ii[i], Rq);
      v->r0[i] = v->r0ii[i];
    }

  fdb_public_setup (v->A1, v->A2prime, v->Bmat, v->ARmat, v->AMmat, v->R2,
                    v->r1, v->R2ii, v->r1ii, v->Es0, v->Es1, v->Dm, v->tbox,
                    Rq, v->m1, v->Z, v->l, v->n, v->n_, seed);
}

/* the opening equations' constant terms r0[NEQ+i] = -t_h[i], from the
 * verifier's OWN stored credential (never taken from the signer's proof). */
static void
fdb_verifier_refresh_credential_r0 (fdb_verifier_ctx_t v)
{
  unsigned int i;
  for (i = 0; i < NLIN; i++)
    {
      poly_set (v->r0[NEQ + i], polyvec_get_elem (v->th, i)); /* r0 = t_h[i] */
      poly_neg_self (v->r0[NEQ + i]); /* r0 = -t_h[i] */
    }
}

/* store the credential t_h received at issuance (public commitment to h),
 * from its serialized wire form.  Returns 1 on success, 0 on a malformed
 * buffer. */
static int
fdb_verifier_set_credential (fdb_verifier_ctx_t v, const uint8_t *cred,
                             size_t credlen)
{
  size_t declen;

  if (!fdb_deccred (&declen, cred, v->th, v->Rq) || declen != credlen)
    return 0;
  /* decoded values are in the positive (redp) representation; center them */
  polyvec_mod (v->th, v->th);
  polyvec_redc (v->th, v->th);
  fdb_verifier_refresh_credential_r0 (v);
  return 1;
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
  b = fdb_decproof (&declen, proof, v->tA1, v->tB, v->hout, v->cpoly, v->z1,
                    v->z21, v->hint, v->z3, v->z4, params);
  if (!b || declen != prooflen)
    return 0;

  /* r0 = -c, from c = HashToPoint(salt||msg) recomputed by the verifier */
  poly_alloc (cf, RF);
  polyvec_alloc (ciso, RP, 8);
  derive_challenge (cc16, salt, msg, msglen); /* c = HashToPoint(salt||msg) */
  for (i = 0; i < 512; i++)
    cf64[i] = cc16[i];
  poly_set_coeffvec_i64 (cf, cf64); /* cf = c as an RF element */
  poly_toisoring (ciso, cf);        /* ciso = iso(c) (8 RP blocks) */
  polyvec_fromcrt (ciso);
  polyvec_redc (ciso, ciso);           /* centered rep */
  fdb_compute_r0_public (v->r0, ciso); /* r0[i] = -ciso[i], i < NEQ */
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
                       v->z3, v->z4, v->tA1, v->tB, v->A1, v->A2prime, v->Bmat,
                       v->R2, v->r1, v->r0, NEQTOT, NULL, NULL, NULL, 0, v->Es,
                       v->Em, v->vv, NULL, NULL, NULL, NULL, v->Dm, NULL,
                       params);
  t2 = wall ();
  v->t_verify = t2 - t1;
  return b;
}

/* ---- honest-run report: hash check + serialized proof size ---------------
 */
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
  static uint8_t cred[FDB_CRED_MAXLEN];
  size_t prooflen, credlen;
  int bres;

  fdb_signer_init (signer, params, seed);
  fdb_verifier_init (verifier, params, seed);

  /* issuance (once): holder computes t_h = AR*rc + AM*h and sends the
   * PUBLIC t_h -- serialized, like everything crossing the boundary -- to
   * the verifier, which stores it as the credential. */
  fdb_signer_issue (signer);
  fdb_enccred (cred, &credlen, signer->th, signer->Rq);
  if (!fdb_verifier_set_credential (verifier, cred, credlen))
    return -1;

  /* verifier -> wire: message */
  fdb_verifier_new_message (msg);

  /* signer -> wire: commitment + proof + salt (r0, c, and t_h's opening are
   * NOT sent) */
  if (!fdb_signer_prove (signer, proof, &prooflen, msg, FDB_MSG_BYTES, salt,
                         params))
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
      fprintf (stderr, "  [OK] proof rejected under a different message\n");
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
    /* t_h[0] += 1  (any t_h' != t_h) */
    int_add (poly_get_coeff (t0, 0), poly_get_coeff (t0, 0), one);
    fdb_verifier_refresh_credential_r0 (verifier); /* r0[NEQ+i] = -t_h'[i] */
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
      fprintf (stderr, "  [OK] proof rejected under a different credential\n");
    /* restore the honest credential from its wire form -- leave the
     * verifier reusable for any checks added after this block */
    if (!fdb_verifier_set_credential (verifier, cred, credlen))
      bres = 0;
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
