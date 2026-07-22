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
 * FULL Falcon-512 device-binding proof.
 *
 * A Secure Element holds a Falcon-512 key (h = public key) and signs a verifier
 * challenge c: it returns a short (s1,s2) with s1 + s2*h = c (mod p=12289),
 * ||(s1,s2)|| <= beta.  A credential commits h.  We prove in ZERO KNOWLEDGE:
 *
 *     s1 + s2*h - c - p*k = 0     (8 block equations over Rp),
 *     ||(s1,s2)||_2 <= beta,      ||k||_inf <= B'
 *
 * revealing neither h nor the signature (only c is public).  Deg-512 objects are
 * the 8-block isoring representation; multiply-by-h is the matrix M_h (validated
 * in devicebind-isoring-test), so the quadratic term (s2*h)_iso[i] =
 * sum_{j,k} M_e[k][i][j] * h_iso[k] * s2_iso[j], with M_e[k]=lin_toisoring(e_k).
 * k is the mod-p quotient (route b).
 */

#define NEQ 8       /* 8 quadratic block equations */
#define ANON_P 12289
#define ANON_DEG 64

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

/* serialized proof size in bytes: replicates lin-proofs.c's static
 * lnp_tbox_encproof (mutates its polyvec args in place, so call it last). */
static size_t
fdb_proofsize (polyvec_t tA1, polyvec_t tB, polyvec_t h, poly_t c,
               polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3,
               polyvec_t z4, const lnp_tbox_params_t params)
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
  static uint8_t buf[1 << 20];

  coder_enc_begin (cstate, buf);
  polyvec_fromcrt (tB);
  polyvec_mod (tB, tB);
  polyvec_redp (tB, tB);
  coder_enc_urandom3 (cstate, tB, q, log2q);
  polyvec_fromcrt (h);
  polyvec_mod (h, h);
  polyvec_redp (h, h);
  coder_enc_urandom3 (cstate, h, q, log2q);
  int_set_one (mod);
  int_lshift (mod, mod, log2q - D);
  polyvec_fromcrt (tA1);
  polyvec_mod (tA1, tA1);
  polyvec_redp (tA1, tA1);
  coder_enc_urandom3 (cstate, tA1, mod, log2q - D);
  int_set_i64 (mod, 2 * omega + 1);
  poly_fromcrt (c);
  intvec_set (coeffs, poly_get_coeffvec (c));
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
  prooflen = coder_get_offset (cstate);
  return prooflen >> 3; /* bits -> bytes */
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

/* All per-run state, threaded through the step functions below in place of a
 * single monolithic run(). Everything here is a fixed-size (array-of-1)
 * lazer type, so it is safe as a struct member; the few VLA-sized INT_T()
 * temporaries stay local to whichever step function needs them. */
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

  /* Falcon material */
  int16_t hc16[512], cc16[512], s1c16[512], s2c16[512];
  poly_t hf, cf, s1f, s2f, ef;
  polymat_t Mh, Me[8];
  polyvec_t hiso, ciso, s1iso, s2iso, ev;

  /* proof material */
  polyvec_t s1, s2, mvec, tA1, tA2, tB, hout, z1, z21, hint, z3, z4, s, tmp;
  polyvec_t vival;
  poly_t cpoly;
  spolymat_t R2_, R2ii[NEQ];
  spolyvec_t r1_, r1ii[NEQ];
  poly_t r0ii[NEQ];
  spolymat_ptr R2[NEQ];
  spolyvec_ptr r1[NEQ];
  poly_ptr r0[NEQ];
  polymat_t Es0, Em0, Ds, Dm, A1, A2prime, Bmat;
  polyvec_t v0, u;
  polymat_ptr Es[1], Em[1];
  polyvec_ptr vv[1];

  uint8_t hashp[32], hashv[32];
  double t_prove, t_verify;
} fdb_ctx_t[1];

static void
fdb_ctx_init_dims (fdb_ctx_t ctx, const lnp_tbox_params_t params)
{
  ctx->tbox = params->tbox;
  ctx->quad = params->quad_eval->quad_many;
  ctx->quade = params->quad_eval;
  ctx->Rq = ctx->tbox->ring;
  ctx->d = polyring_get_deg (ctx->Rq);
  ctx->m1 = ctx->tbox->m1 - params->Z; /* real bounded length = 16 */
  ctx->Z = params->Z;
  ctx->l = ctx->tbox->l; /* 16 */
  ctx->lambda = ctx->quade->lambda;
  ctx->n = 2 * (ctx->tbox->m1 + ctx->quad->l);
  ctx->n_ = 2 * (ctx->m1 + ctx->l);
}

/* ---- Falcon keygen, challenge, sign ------------------------------------- */
static void
falcon_sign_challenge (fdb_ctx_t ctx)
{
  static uint8_t sk[1281], pk[897];
  int64_t cf64[512];
  unsigned int i;

  falcon_keygen (sk, pk);
  falcon_decode_pubkey (ctx->hc16, pk);
  poly_alloc (ctx->hf, RF);
  poly_alloc (ctx->cf, RF);
  poly_alloc (ctx->s1f, RF);
  poly_alloc (ctx->s2f, RF);
  poly_alloc (ctx->ef, RF);
  poly_set_coeffvec_i16 (ctx->hf, ctx->hc16);

  /* challenge c: uniform in [0,p) (stand-in for HashToPoint) */
  for (i = 0; i < 512; i++)
    {
      uint8_t b2[2];
      bytes_urandom (b2, 2);
      ctx->cc16[i] = (int16_t)((((unsigned)b2[0] << 8) | b2[1]) % ANON_P);
      cf64[i] = ctx->cc16[i];
    }
  poly_set_coeffvec_i64 (ctx->cf, cf64);

  /* SE signs: (s1,s2) with s1 + s2*h = c */
  falcon_preimage_sample (ctx->s1c16, ctx->s2c16, ctx->cc16, sk);
  poly_set_coeffvec_i16 (ctx->s1f, ctx->s1c16);
  poly_set_coeffvec_i16 (ctx->s2f, ctx->s2c16);
}

/* ---- isoring representations, M_h/M_e[k], and centering ----------------- */
static void
build_isoring_reps (fdb_ctx_t ctx)
{
  unsigned int i, j, kk, blk;

  polyvec_alloc (ctx->hiso, RP, 8);
  polyvec_alloc (ctx->ciso, RP, 8);
  polyvec_alloc (ctx->s1iso, RP, 8);
  polyvec_alloc (ctx->s2iso, RP, 8);
  polyvec_alloc (ctx->ev, RP, 8);
  poly_toisoring (ctx->hiso, ctx->hf);
  poly_toisoring (ctx->ciso, ctx->cf);
  poly_toisoring (ctx->s1iso, ctx->s1f);
  poly_toisoring (ctx->s2iso, ctx->s2f);

  /* M_h and the 8 structure matrices M_e[k] = lin_toisoring(e_k) */
  polymat_alloc (ctx->Mh, RP, 8, 8);
  mul_matrix (ctx->Mh, ctx->hf);
  for (kk = 0; kk < 8; kk++)
    {
      polyvec_set_zero (ctx->ev);
      poly_set_one (polyvec_get_elem (ctx->ev, kk));
      poly_fromisoring (ctx->ef, ctx->ev);
      polymat_alloc (ctx->Me[kk], RP, 8, 8);
      mul_matrix (ctx->Me[kk], ctx->ef);
      polymat_fromcrt (ctx->Me[kk]);
      polymat_redc (ctx->Me[kk], ctx->Me[kk]); /* structure constants gamma in {0,+-1} */
    }
  /* sanity: report the largest |gamma| (expected 1 for the block-negacyclic iso) */
  {
    int64_t gmax = 0, gc[ANON_DEG];
    for (kk = 0; kk < 8; kk++)
      for (i = 0; i < 8; i++)
        for (j = 0; j < 8; j++)
          {
            poly_get_coeffvec_i64 (gc, polymat_get_elem (ctx->Me[kk], i, j));
            for (blk = 0; blk < ctx->d; blk++)
              {
                int64_t a = gc[blk] < 0 ? -gc[blk] : gc[blk];
                if (a > gmax)
                  gmax = a;
              }
          }
    fprintf (stderr, "  max|gamma| = %lld (expect 1)\n", (long long)gmax);
  }

  /* center the isoring reps and M_h into their signed small representatives.
   * The mod-p quotient k is computed later over Rq (integer arithmetic), NOT
   * here over RP where it would reduce to 0 (s1+s2h-c == 0 mod p). */
  polyvec_fromcrt (ctx->s1iso);
  polyvec_redc (ctx->s1iso, ctx->s1iso);
  polyvec_fromcrt (ctx->s2iso);
  polyvec_redc (ctx->s2iso, ctx->s2iso);
  polyvec_fromcrt (ctx->hiso);
  polyvec_redc (ctx->hiso, ctx->hiso);
  polyvec_fromcrt (ctx->ciso);
  polyvec_redc (ctx->ciso, ctx->ciso);
  polymat_fromcrt (ctx->Mh);
  polymat_redc (ctx->Mh, ctx->Mh);
}

/* ---- allocate proof objects ---------------------------------------------- */
static void
alloc_proof_objects (fdb_ctx_t ctx, const lnp_tbox_params_t params)
{
  polyring_srcptr Rq = ctx->Rq;
  unsigned int i;

  poly_alloc (ctx->cpoly, Rq);
  polyvec_alloc (ctx->s1, Rq, ctx->tbox->m1);
  polyvec_alloc (ctx->s2, Rq, ctx->tbox->m2);
  polyvec_alloc (ctx->mvec, Rq, ctx->tbox->l + ctx->tbox->lext);
  polyvec_alloc (ctx->tA1, Rq, ctx->tbox->kmsis);
  polyvec_alloc (ctx->tA2, Rq, ctx->tbox->kmsis);
  polyvec_alloc (ctx->tB, Rq, ctx->tbox->l + ctx->tbox->lext);
  polyvec_alloc (ctx->hout, Rq, ctx->lambda / 2);
  polyvec_alloc (ctx->z1, Rq, ctx->tbox->m1);
  polyvec_alloc (ctx->z21, Rq, ctx->tbox->m2 - ctx->tbox->kmsis);
  polyvec_alloc (ctx->hint, Rq, ctx->tbox->kmsis);
  polyvec_alloc (ctx->z3, Rq, 256 / ctx->d);
  polyvec_alloc (ctx->z4, Rq, 256 / ctx->d);
  polyvec_alloc (ctx->s, Rq, ctx->n_);
  polyvec_alloc (ctx->tmp, Rq, ctx->n_);
  polyvec_alloc (ctx->vival, Rq, params->n[0]);
  polymat_alloc (ctx->A1, Rq, ctx->tbox->kmsis, ctx->tbox->m1);
  polymat_alloc (ctx->A2prime, Rq, ctx->tbox->kmsis, ctx->tbox->m2 - ctx->tbox->kmsis);
  polymat_alloc (ctx->Bmat, Rq, ctx->tbox->l + ctx->tbox->lext,
                 ctx->tbox->m2 - ctx->tbox->kmsis);
  polymat_alloc (ctx->Es0, Rq, params->n[0], ctx->m1);
  polymat_alloc (ctx->Em0, Rq, params->n[0], ctx->l);
  polyvec_alloc (ctx->v0, Rq, params->n[0]);
  polymat_alloc (ctx->Ds, Rq, params->nprime, ctx->m1);
  polymat_alloc (ctx->Dm, Rq, params->nprime, ctx->l);
  polyvec_alloc (ctx->u, Rq, params->nprime);
  spolymat_alloc (ctx->R2_, Rq, ctx->n_, ctx->n_,
                  (ctx->n_ * ctx->n_ - ctx->n_) / 2 + ctx->n_);
  spolyvec_alloc (ctx->r1_, Rq, ctx->n_, ctx->n_);
  for (i = 0; i < NEQ; i++)
    {
      spolymat_alloc (ctx->R2ii[i], Rq, ctx->n, ctx->n,
                       (ctx->n * ctx->n - ctx->n) / 2 + ctx->n);
      spolyvec_alloc (ctx->r1ii[i], Rq, ctx->n, ctx->n);
      poly_alloc (ctx->r0ii[i], Rq);
      ctx->R2[i] = ctx->R2ii[i];
      ctx->r1[i] = ctx->r1ii[i];
      ctx->r0[i] = ctx->r0ii[i];
    }
  ctx->Es[0] = ctx->Es0;
  ctx->Em[0] = ctx->Em0;
  ctx->vv[0] = ctx->v0;
}

/* ---- witness: s1[0..7]=s1iso, s1[8..15]=s2iso ; m[0..7]=hiso
 * (m[8..15]=k is set later, by compute_quotient) ---------------------------- */
static void
build_witness (fdb_ctx_t ctx)
{
  unsigned int blk;

  polyvec_set_zero (ctx->s1);
  polyvec_set_zero (ctx->mvec);
  for (blk = 0; blk < 8; blk++)
    {
      cpq (polyvec_get_elem (ctx->s1, blk), polyvec_get_elem (ctx->s1iso, blk));
      cpq (polyvec_get_elem (ctx->s1, 8 + blk), polyvec_get_elem (ctx->s2iso, blk));
      cpq (polyvec_get_elem (ctx->mvec, blk), polyvec_get_elem (ctx->hiso, blk));
    }
}

/* k = (s1iso + M_h*s2iso - ciso)/p computed over Rq: the integer product
 * M_h*s2iso ~ 2^31 (s2 is the SHORT Falcon signature) stays well below q, so
 * s1iso + M_h*s2iso - ciso is the true integer p*k (not reduced mod p).
 * Also completes the witness: writes k into ctx->mvec[8..15].
 * Returns 1 if the division is exact (relation holds mod p), 0 otherwise. */
static int
compute_quotient (fdb_ctx_t ctx)
{
  polyring_srcptr Rq = ctx->Rq;
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
        cpq (polymat_get_elem (Mhq, i, j), polymat_get_elem (ctx->Mh, i, j));
      cpq (polyvec_get_elem (s2q, i), polyvec_get_elem (ctx->s2iso, i));
      cpq (polyvec_get_elem (ciq, i), polyvec_get_elem (ctx->ciso, i));
    }
  polyvec_mul (prodq, Mhq, s2q); /* = M_h*s2iso over Rq (NTT-mutates Mhq) */
  polyvec_fromcrt (prodq);
  for (i = 0; i < 8; i++)
    {
      poly_add (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (ctx->s1, i), 0);
      poly_sub (polyvec_get_elem (prodq, i), polyvec_get_elem (prodq, i),
                polyvec_get_elem (ciq, i), 0);
    }
  polyvec_redc (prodq, prodq); /* centered; = p*k */
  polyvec_get_coeffvec_i64 (pc, prodq);
  for (i = 0; i < 8 * ctx->d; i++)
    if (pc[i] % ANON_P != 0)
      ok = 0;
  for (i = 0; i < 8; i++)
    {
      for (j = 0; j < ctx->d; j++)
        {
          int64_t a;
          kc[j] = pc[i * ctx->d + j] / ANON_P;
          a = kc[j] < 0 ? -kc[j] : kc[j];
          if (a > mk)
            mk = a;
        }
      poly_set_coeffvec_i64 (polyvec_get_elem (ctx->mvec, 8 + i), kc);
    }
  fprintf (stderr, "  |k|_inf = %lld  (Bprime=%d)  exact-div-by-p: %s\n",
           (long long)mk, 8958759, ok ? "yes" : "NO");
  polymat_free (Mhq);
  polyvec_free (s2q);
  polyvec_free (prodq);
  polyvec_free (ciq);
  return ok;
}

/* ---- commitment randomness s2 ~ {-1,0,1} --------------------------------- */
static void
sample_commitment_randomness (fdb_ctx_t ctx, uint8_t seed[32])
{
  INT_T (lo, ctx->Rq->q->nlimbs);
  INT_T (hi, ctx->Rq->q->nlimbs);

  int_set_i64 (lo, -1);
  int_set_i64 (hi, 1);
  polyvec_urandom_bnd (ctx->s2, lo, hi, seed, 200);
}

/* ---- local witness s = (<s1_real>,<m_real>) ------------------------------ */
static void
build_local_witness (fdb_ctx_t ctx)
{
  polyvec_t s1sub, msub, asub, aauto, bsub, bauto;

  polyvec_get_subvec (s1sub, ctx->s1, 0, ctx->m1, 1);
  polyvec_get_subvec (msub, ctx->mvec, 0, ctx->l, 1);
  polyvec_get_subvec (asub, ctx->s, 0, ctx->m1, 2);
  polyvec_get_subvec (aauto, ctx->s, 1, ctx->m1, 2);
  polyvec_set (asub, s1sub);
  polyvec_auto (aauto, s1sub);
  polyvec_get_subvec (bsub, ctx->s, ctx->m1 * 2, ctx->l, 2);
  polyvec_get_subvec (bauto, ctx->s, ctx->m1 * 2 + 1, ctx->l, 2);
  polyvec_set (bsub, msub);
  polyvec_auto (bauto, msub);
}

/* ---- 8 quadratic equations ------------------------------------------------
 * eq i:  s1iso[i] + sum_{j,k} Me[k][i][j]*s2iso[j]*hiso[k] - c_i - p*k_i = 0
 * local indices: s1iso[i]=2i, s2iso[j]=16+2j, hiso[k]=32+2k, kiso[i]=48+2i */
static void
build_quadratic_equations (fdb_ctx_t ctx)
{
  unsigned int i, j, kk;
  poly_ptr pe;

  for (i = 0; i < NEQ; i++)
    {
      spolymat_set_empty (ctx->R2_);
      for (j = 0; j < 8; j++)
        for (kk = 0; kk < 8; kk++)
          {
            poly_ptr g = polymat_get_elem (ctx->Me[kk], i, j); /* = gamma_{i,j,k} */
            pe = spolymat_insert_elem (ctx->R2_, 16 + 2 * j, 32 + 2 * kk);
            cpq (pe, g);
          }
      spolymat_sort (ctx->R2_);

      spolyvec_set_empty (ctx->r1_);
      pe = spolyvec_insert_elem (ctx->r1_, 2 * i); /* + s1iso[i] */
      poly_set_one (pe);
      pe = spolyvec_insert_elem (ctx->r1_, 48 + 2 * i); /* - p*k[i] */
      poly_set_zero (pe);
      int_set_i64 (poly_get_coeff (pe, 0), -(int64_t)ANON_P);
      spolyvec_sort (ctx->r1_);

      /* r0_i = -(r1_.s + s.R2_.s) = -c_i */
      polyvec_dot2 (ctx->r0ii[i], ctx->r1_, ctx->s);
      polyvec_mulsparse (ctx->tmp, ctx->R2_, ctx->s);
      polyvec_fromcrt (ctx->tmp);
      poly_adddot (ctx->r0ii[i], ctx->s, ctx->tmp, 0);
      poly_neg_self (ctx->r0ii[i]);
      poly_fromcrt (ctx->r0ii[i]);

      spolymat_fromcrt (ctx->R2_);
      spolyvec_fromcrt (ctx->r1_);
      _scatter_smat (ctx->R2ii[i], ctx->R2_, ctx->m1, ctx->Z, ctx->l);
      _scatter_vec (ctx->r1ii[i], ctx->r1_, ctx->m1, ctx->Z);
    }
}

/* corrupt the public challenge c (r0[0]) so verification must reject */
static void
corrupt_challenge (fdb_ctx_t ctx, uint8_t seed[32])
{
  poly_t e;
  poly_alloc (e, ctx->Rq);
  poly_brandom (e, 1, seed, 999);
  poly_add (ctx->r0ii[0], ctx->r0ii[0], e, 0);
  poly_free (e);
}

/* ---- l2 proof: ||(s1iso,s2iso)||_2 <= beta -------------------------------- */
static void
setup_l2_proof (fdb_ctx_t ctx, const lnp_tbox_params_t params)
{
  INT_T (l2sqr, 2 * ctx->Rq->q->nlimbs);
  INT_T (l2b, 2 * ctx->Rq->q->nlimbs);
  polyvec_t upsilon;
  unsigned int i;

  polymat_set_zero (ctx->Es0);
  for (i = 0; i < 16; i++)
    poly_set_one (polymat_get_elem (ctx->Es0, i, i)); /* select s1[0..15] */
  polymat_set_zero (ctx->Em0);
  polyvec_set_zero (ctx->v0);
  for (i = 0; i < 16; i++)
    poly_set (polyvec_get_elem (ctx->vival, i), polyvec_get_elem (ctx->s1, i));
  int_set (l2b, params->l2Bsqr[0]);
  polyvec_l2sqr (l2sqr, ctx->vival);
  int_sub (l2b, l2b, l2sqr);
  polyvec_get_subvec (upsilon, ctx->s1, ctx->m1, ctx->Z, 1);
  int_binexp (polyvec_get_elem (upsilon, 0), NULL, l2b);
}

/* ---- linf proof: ||k||_inf <= B' (k = m[8..15]) --------------------------- */
static void
setup_linf_proof (fdb_ctx_t ctx)
{
  unsigned int i;

  polymat_set_zero (ctx->Ds);
  polymat_set_zero (ctx->Dm);
  for (i = 0; i < 8; i++)
    poly_set_one (polymat_get_elem (ctx->Dm, i, 8 + i)); /* row i -> m[8+i]=k[i] */
  polyvec_set_zero (ctx->u);
}

/* ---- prove --------------------------------------------------------------- */
static void
fdb_prove (fdb_ctx_t ctx, const lnp_tbox_params_t params, uint8_t seed[32])
{
  double t0, t1;

  abdlop_keygen (ctx->A1, ctx->A2prime, ctx->Bmat, seed, ctx->tbox); /* public setup, untimed */
  memset (ctx->hashp, 0xff, 32);
  t0 = wall ();
  abdlop_commit (ctx->tA1, ctx->tA2, ctx->tB, ctx->s1, ctx->mvec, ctx->s2,
                 ctx->A1, ctx->A2prime, ctx->Bmat, ctx->tbox);
  lnp_tbox_prove (ctx->hashp, ctx->tB, ctx->hout, ctx->cpoly, ctx->z1, ctx->z21,
                  ctx->hint, ctx->z3, ctx->z4, ctx->s1, ctx->mvec, ctx->s2,
                  ctx->tA2, ctx->A1, ctx->A2prime, ctx->Bmat, ctx->R2, ctx->r1,
                  NEQ, NULL, NULL, NULL, 0, ctx->Es, ctx->Em, ctx->vv, NULL,
                  NULL, NULL, ctx->Ds, ctx->Dm, ctx->u, seed, params);
  t1 = wall ();
  ctx->t_prove = t1 - t0;
}

/* ---- verify -------------------------------------------------------------- */
static int
fdb_verify (fdb_ctx_t ctx, const lnp_tbox_params_t params)
{
  double t1, t2;
  int bres;

  t1 = wall ();
  memset (ctx->hashv, 0xff, 32);
  bres = lnp_tbox_verify (ctx->hashv, ctx->hout, ctx->cpoly, ctx->z1, ctx->z21,
                          ctx->hint, ctx->z3, ctx->z4, ctx->tA1, ctx->tB,
                          ctx->A1, ctx->A2prime, ctx->Bmat, ctx->R2, ctx->r1,
                          ctx->r0, NEQ, NULL, NULL, NULL, 0, ctx->Es, ctx->Em,
                          ctx->vv, NULL, NULL, NULL, ctx->Ds, ctx->Dm, ctx->u,
                          params);
  t2 = wall ();
  ctx->t_verify = t2 - t1;
  return bres;
}

/* ---- honest-run report: hash check + serialized proof size --------------- */
static int
report_honest_result (fdb_ctx_t ctx, const lnp_tbox_params_t params, int bres)
{
  size_t sz;

  bres = bres && (memcmp (ctx->hashp, ctx->hashv, 32) == 0);
  /* encoder mutates tB/hout/cpoly/tA1/z*, so measure size last */
  sz = fdb_proofsize (ctx->tA1, ctx->tB, ctx->hout, ctx->cpoly, ctx->z1,
                       ctx->z21, ctx->hint, ctx->z3, ctx->z4, params);
  fprintf (stderr,
           "  proof size = %zu bytes (%.2f KiB)   prove = %.3f s   "
           "verify = %.3f s\n",
           sz, sz / 1024.0, ctx->t_prove, ctx->t_verify);
  return bres;
}

static int
run (uint8_t seed[32], const lnp_tbox_params_t params, int tamper)
{
  fdb_ctx_t ctx;
  int bres;

  fdb_ctx_init_dims (ctx, params);

  falcon_sign_challenge (ctx);
  build_isoring_reps (ctx);
  alloc_proof_objects (ctx, params);
  build_witness (ctx);

  if (!compute_quotient (ctx))
    {
      fprintf (stderr, "  [WARN] s1+s2h-c not 0 mod p (relation/iso mismatch)\n");
      return -1;
    }

  sample_commitment_randomness (ctx, seed); /* commitment randomness s2 */
  build_local_witness (ctx);
  build_quadratic_equations (ctx);
  if (tamper)
    corrupt_challenge (ctx, seed);
  setup_l2_proof (ctx, params);
  setup_linf_proof (ctx);

  fdb_prove (ctx, params, seed);
  bres = fdb_verify (ctx, params);
  if (!tamper)
    bres = report_honest_result (ctx, params, bres);
  return bres;
}

int
main (void)
{
  uint8_t seed[32];
  lazer_init ();
  bytes_urandom (seed, sizeof (seed));

  fprintf (stderr, "FULL Falcon-512 device-binding proof\n");
  TEST_EXPECT (run (seed, fdb_param, 0) == 1);
  fprintf (stderr, "[OK] honest Falcon device-binding proof verifies\n");
  TEST_EXPECT (run (seed, fdb_param, 1) == 0);
  fprintf (stderr, "[OK] tampered challenge rejected\n");

  mpfr_free_cache ();
  TEST_PASS ();
}
