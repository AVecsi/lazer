/*
 * Anonymous credentials, C port of python/anon_cred/anon_cred.py.
 * See anoncred.h for the protocol overview and API.
 */

#include "anoncred.h"
#include "anoncred-params.h" /* defines lin_params_t p1_param, p2_param */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Statement ring Rp = Z_12289[X]/(X^64+1) and the Falcon ring (deg 512),
 * constructed exactly as lazer.py's polyring_t(deg, 12289):
 *   { q, deg, coeffbits, log2d, moduli, nmoduli, Pmodq, Ppmodq, inv2 }
 * deg 64: log2d=6, moduli_d64, nmoduli=1 (one CRT modulus suffices since
 * min_P=(q-1)^2*64*128+1 < moduli_d64[0]). deg 512 is only a coefficient
 * container for the isoring maps (nmoduli=0). */

#define ANON_DEG 64
#define ANON_MOD 12289
#define ANON_COEFFBITS 14 /* (12289).bit_length() */

static const limb_t anon_q_limbs[] = { ANON_MOD };
static const int_t anon_q = { { (limb_t *)anon_q_limbs, 1, 0 } };
static const limb_t anon_inv2_limbs[] = { 6145UL }; /* 2^-1 mod 12289 */
static const int_t anon_inv2 = { { (limb_t *)anon_inv2_limbs, 1, 0 } };
static const limb_t anon_zero_limbs[] = { 0UL };
static const int_t anon_zero = { { (limb_t *)anon_zero_limbs, 1, 0 } };

static const polyring_t RP
    = { { anon_q, ANON_DEG, ANON_COEFFBITS, 6, moduli_d64, 1, anon_zero, NULL,
          anon_inv2 } };
static const polyring_t RF
    = { { anon_q, 512, ANON_COEFFBITS, 0, moduli_d64, 0, anon_zero, NULL,
          anon_inv2 } };

#define ANON_WL2 109     /* l2(r1,r2) <= 109 */
#define ANON_LOGSIGMA 1  /* gaussian sigma = 1.55 * 2^1 */
#define ANON_SIG_LOG2O 7 /* coder grandom log2o for s1,s2 = ceil(log2(165/1.55)) */

/* ------------------------------------------------------------------ */
/* helpers */

/* SHAKE128 of the single byte b (matches hashlib.shake_128(bytes([b]))). */
static void
anon_ppseed (uint8_t out[32], uint8_t b)
{
  shake128_state_t st;
  shake128_init (st);
  shake128_absorb (st, &b, 1);
  shake128_squeeze (st, out, 32);
  shake128_clear (st);
}

/* AR=urandom(8x16,dom1), AM=urandom(8x8,dom2), ATAU=urandom(8x8,dom3),
 * B1=identity, all over Rp from BLINDSIGPP = shake128(0x00). */
static void
anon_pubmats (polymat_t AR, polymat_t AM, polymat_t ATAU, polymat_t B1)
{
  uint8_t pp[32];
  unsigned int i;

  anon_ppseed (pp, 0x00);
  polymat_urandom (AR, anon_q, ANON_COEFFBITS, pp, 1);
  polymat_urandom (AM, anon_q, ANON_COEFFBITS, pp, 2);
  polymat_urandom (ATAU, anon_q, ANON_COEFFBITS, pp, 3);

  polymat_set_zero (B1);
  for (i = 0; i < 8; i++)
    int_set_i64 (poly_get_coeff (polymat_get_elem (B1, i, i), 0), 1);
}

/* B2 = falcon_decode_pk(pk, Rp): 8x8 block matrix over Rp for multiplication
 * by the (automorphism-permuted) Falcon public key. */
static void
anon_decode_pk (polymat_t B2, const uint8_t pk[ANONCRED_PUBKEYLEN])
{
  int16_t h[512];
  poly_t pkf;
  polymat_t pkmat;
  polyvec_t pkvec, garb;

  falcon_decode_pubkey (h, pk);
  poly_alloc (pkf, RF);
  poly_set_coeffvec_i16 (pkf, h);

  polymat_alloc (pkmat, RF, 1, 1);
  polyvec_alloc (pkvec, RF, 1);
  polyvec_alloc (garb, RP, 8);
  polymat_set_elem (pkmat, 0, 0, pkf);
  polyvec_set_elem (pkvec, 0, pkf);

  lin_toisoring (B2, garb, pkmat, pkvec);

  polyvec_free (garb);
  polyvec_free (pkvec);
  polymat_free (pkmat);
  poly_free (pkf);
}

/* polyvec(Rp,dim) of binary polynomials from bytes, like polyvec_t(Rp,dim,b):
 * coeff j of poly i is bit (7 - j%8) of byte[i*8 + j/8]. */
static void
anon_bytes_to_polyvec (polyvec_t v, const uint8_t *bytes, unsigned int dim)
{
  int16_t c[ANON_DEG];
  unsigned int i, j;

  for (i = 0; i < dim; i++)
    {
      for (j = 0; j < ANON_DEG; j++)
        c[j] = (bytes[i * 8 + j / 8] >> (7 - (j & 7))) & 1;
      poly_set_coeffvec_i16 (polyvec_get_elem (v, i), c);
    }
}

/* r <- gaussian over Rp^16, resampled until l2(r)^2 <= l2bound. */
static void
anon_grandom_l2 (polyvec_t r, unsigned int log2o, const uint8_t seed[32],
                 int64_t l2bound)
{
  INT_T (l2, 2);
  INT_T (bnd, 2);
  uint32_t dom = 0;

  int_set_i64 (bnd, l2bound);
  polyvec_grandom (r, log2o, seed, dom);
  polyvec_l2sqr (l2, r);
  while (int_gt (l2, bnd))
    {
      dom++;
      polyvec_grandom (r, log2o, seed, dom);
      polyvec_l2sqr (l2, r);
    }
}

/* dst[col0 + 0..ncols) <- columns of src (optionally negated). */
static void
anon_copy_cols (polymat_t dst, unsigned int col0, const polymat_t src,
                unsigned int ncols, int negate)
{
  polyvec_t col;
  unsigned int c;

  polyvec_alloc (col, RP, polymat_get_nrows (src));
  for (c = 0; c < ncols; c++)
    {
      polymat_get_col (col, src, c);
      if (negate)
        polyvec_neg_self (col);
      polymat_set_col (dst, col, col0 + c);
    }
  polyvec_free (col);
}

/* dst[pos0 + 0..n) <- elements of src. */
static void
anon_copy_elems (polyvec_t dst, unsigned int pos0, const polyvec_t src,
                 unsigned int n)
{
  unsigned int i;
  for (i = 0; i < n; i++)
    polyvec_set_elem (dst, pos0 + i, polyvec_get_elem (src, i));
}

/* Matrix-vector product into r, on a throwaway copy of the matrix:
 * polyvec_mul converts its matrix argument to NTT form in place, so this
 * keeps persistent (statement) matrices in coefficient form. */
static void
anon_matvec (polyvec_t r, const polymat_t mat, polyvec_t vec)
{
  polymat_t c;
  polymat_alloc (c, RP, polymat_get_nrows (mat), polymat_get_ncols (mat));
  polymat_set (c, mat);
  polyvec_mul (r, c, vec);
  polymat_free (c);
}

/* ------------------------------------------------------------------ */
/* keygen */

void
anoncred_keygen (uint8_t sk[ANONCRED_PRIVKEYLEN],
                 uint8_t pk[ANONCRED_PUBKEYLEN])
{
  falcon_keygen (sk, pk);
}

/* ------------------------------------------------------------------ */
/* user */

void
anoncred_user_init (anoncred_user_state_t st,
                    const uint8_t pk[ANONCRED_PUBKEYLEN])
{
  uint8_t p1pp[32], p2pp[32];

  polymat_alloc (st->AR, RP, 8, 16);
  polymat_alloc (st->AM, RP, 8, 8);
  polymat_alloc (st->ATAU, RP, 8, 8);
  polymat_alloc (st->B1, RP, 8, 8);
  polymat_alloc (st->B2, RP, 8, 8);
  polyvec_alloc (st->r, RP, 16);
  polyvec_alloc (st->m, RP, 8);

  anon_pubmats (st->AR, st->AM, st->ATAU, st->B1);
  anon_decode_pk (st->B2, pk);

  anon_ppseed (p1pp, 0x01);
  anon_ppseed (p2pp, 0x02);
  lin_prover_init (st->p1, p1pp, p1_param);
  lin_prover_init (st->p2, p2pp, p2_param);
}

void
anoncred_user_clear (anoncred_user_state_t st)
{
  lin_prover_clear (st->p1);
  lin_prover_clear (st->p2);
  polyvec_free (st->r);
  polyvec_free (st->m);
  polymat_free (st->AR);
  polymat_free (st->AM);
  polymat_free (st->ATAU);
  polymat_free (st->B1);
  polymat_free (st->B2);
}

void
anoncred_user_maskmsg (anoncred_user_state_t st, uint8_t *masked_msg,
                       size_t *masked_msglen,
                       const uint8_t msg[ANONCRED_MSGLEN])
{
  polyvec_t t, tmp, u, w;
  polymat_t A;
  coder_state_t cstate;
  uint8_t seed[32], coins[32];
  size_t tlen, prooflen;

  polyvec_alloc (t, RP, 8);
  polyvec_alloc (tmp, RP, 8);
  polyvec_alloc (u, RP, 8);
  polyvec_alloc (w, RP, 24);
  polymat_alloc (A, RP, 8, 24);

  /* message m (saved for the disclosure proof) */
  anon_bytes_to_polyvec (st->m, msg, 8);

  /* r <- gaussian, l2(r) <= 109 */
  bytes_urandom (seed, sizeof (seed));
  anon_grandom_l2 (st->r, ANON_LOGSIGMA, seed, (int64_t)ANON_WL2 * ANON_WL2);

  /* t = AR*r + AM*m */
  anon_matvec (t, st->AR, st->r);
  anon_matvec (tmp, st->AM, st->m);
  polyvec_add (t, t, tmp, 0);

  /* encode t (coder_enc_urandom needs coeffs in [0,q)) */
  polyvec_redp (t, t);
  coder_enc_begin (cstate, masked_msg);
  coder_enc_urandom3 (cstate, t, anon_q, ANON_COEFFBITS);
  coder_enc_end (cstate);
  tlen = coder_get_offset (cstate) >> 3;

  /* P1: prove [AR,AM]*(r,m) - t = 0, i.e. A w + u = 0 with u = -t */
  anon_copy_cols (A, 0, st->AR, 16, 0);
  anon_copy_cols (A, 16, st->AM, 8, 0);
  polyvec_redc (u, t); /* centered representative, matches decoded t */
  polyvec_neg_self (u);
  anon_copy_elems (w, 0, st->r, 16);
  anon_copy_elems (w, 16, st->m, 8);

  lin_prover_set_statement (st->p1, A, u);
  lin_prover_set_witness (st->p1, w);
  bytes_urandom (coins, sizeof (coins));
  lin_prover_prove (st->p1, masked_msg + tlen, &prooflen, coins);

  *masked_msglen = tlen + prooflen;

  polymat_free (A);
  polyvec_free (w);
  polyvec_free (u);
  polyvec_free (tmp);
  polyvec_free (t);
}

int
anoncred_user_sign (anoncred_user_state_t st, uint8_t *sig, size_t *siglen,
                    const uint8_t *blindsig, UNUSED size_t blindsiglen,
                    const unsigned int *pub_mvec, unsigned int npub)
{
  polyvec_t s1, s2, tau, w, u, mpriv, zcol;
  polymat_t A, AMpriv;
  coder_state_t cstate;
  uint8_t tau_[64], coins[32];
  unsigned int k;
  int rc, rv = 0;

  polyvec_alloc (s1, RP, 8);
  polyvec_alloc (s2, RP, 8);
  polyvec_alloc (tau, RP, 8);
  polyvec_alloc (w, RP, 48);
  polyvec_alloc (u, RP, 8);
  polyvec_alloc (mpriv, RP, 8);
  polyvec_alloc (zcol, RP, 8);
  polymat_alloc (A, RP, 8, 48);
  polymat_alloc (AMpriv, RP, 8, 8);

  /* decode blindsig: tau (64 bytes), s1, s2 (grandom) */
  coder_dec_begin (cstate, blindsig);
  rc = coder_dec_bytes (cstate, tau_, sizeof (tau_));
  coder_dec_grandom3 (cstate, s1, ANON_SIG_LOG2O);
  coder_dec_grandom3 (cstate, s2, ANON_SIG_LOG2O);
  if (rc != 0)
    goto out;
  if (coder_dec_end (cstate) != 1)
    goto out;

  anon_bytes_to_polyvec (tau, tau_, 8);

  /* AM_priv = AM with public columns zeroed; m_priv = m with public polys
   * zeroed; u = AM_pub * m_pub (= 0 if nothing disclosed). */
  polyvec_set_zero (zcol);
  polymat_set (AMpriv, st->AM);
  polyvec_set (mpriv, st->m);
  for (k = 0; k < npub; k++)
    {
      polymat_set_col (AMpriv, zcol, pub_mvec[k]);
      polyvec_set_elem (mpriv, pub_mvec[k], polyvec_get_elem (zcol, 0));
    }

  if (npub == 0)
    {
      polyvec_set_zero (u);
    }
  else
    {
      polymat_t AMpub;
      polyvec_t mpub, col;
      polymat_alloc (AMpub, RP, 8, npub);
      polyvec_alloc (mpub, RP, npub);
      polyvec_alloc (col, RP, 8);
      for (k = 0; k < npub; k++)
        {
          polymat_get_col (col, st->AM, pub_mvec[k]);
          polymat_set_col (AMpub, col, k);
          polyvec_set_elem (mpub, k, polyvec_get_elem (st->m, pub_mvec[k]));
        }
      polyvec_mul (u, AMpub, mpub); /* AMpub is a temp, ok to NTT-mutate */
      polyvec_free (col);
      polyvec_free (mpub);
      polymat_free (AMpub);
    }

  /* A = [AR, ATAU, -B1, -B2, AM_priv]; w = (r, tau, s1, s2, m_priv) */
  anon_copy_cols (A, 0, st->AR, 16, 0);
  anon_copy_cols (A, 16, st->ATAU, 8, 0);
  anon_copy_cols (A, 24, st->B1, 8, 1);
  anon_copy_cols (A, 32, st->B2, 8, 1);
  anon_copy_cols (A, 40, AMpriv, 8, 0);
  anon_copy_elems (w, 0, st->r, 16);
  anon_copy_elems (w, 16, tau, 8);
  anon_copy_elems (w, 24, s1, 8);
  anon_copy_elems (w, 32, s2, 8);
  anon_copy_elems (w, 40, mpriv, 8);

  lin_prover_set_statement (st->p2, A, u);
  lin_prover_set_witness (st->p2, w);
  bytes_urandom (coins, sizeof (coins));
  lin_prover_prove (st->p2, sig, siglen, coins);

  rv = 1;
out:
  polymat_free (AMpriv);
  polymat_free (A);
  polyvec_free (zcol);
  polyvec_free (mpriv);
  polyvec_free (u);
  polyvec_free (w);
  polyvec_free (tau);
  polyvec_free (s2);
  polyvec_free (s1);
  return rv;
}

/* ------------------------------------------------------------------ */
/* signer */

void
anoncred_signer_init (anoncred_signer_state_t st,
                      const uint8_t pk[ANONCRED_PUBKEYLEN],
                      const uint8_t sk[ANONCRED_PRIVKEYLEN])
{
  polymat_t B1;
  uint8_t p1pp[32];
  (void)pk;

  polymat_alloc (st->AR, RP, 8, 16);
  polymat_alloc (st->AM, RP, 8, 8);
  polymat_alloc (st->ATAU, RP, 8, 8);
  polymat_alloc (B1, RP, 8, 8);
  anon_pubmats (st->AR, st->AM, st->ATAU, B1);
  polymat_free (B1);

  memcpy (st->privkey, sk, ANONCRED_PRIVKEYLEN);

  anon_ppseed (p1pp, 0x01);
  lin_verifier_init (st->p1, p1pp, p1_param);
}

void
anoncred_signer_clear (anoncred_signer_state_t st)
{
  lin_verifier_clear (st->p1);
  polymat_free (st->AR);
  polymat_free (st->AM);
  polymat_free (st->ATAU);
}

int
anoncred_signer_sign (anoncred_signer_state_t st, uint8_t *blindsig,
                      size_t *blindsiglen, const uint8_t *masked_msg,
                      UNUSED size_t masked_msglen)
{
  polyvec_t t, u, target, tau, s1v, s2v;
  polymat_t A;
  coder_state_t cstate;
  uint8_t tau_[64];
  int16_t s1[512], s2[512], tt[512];
  int64_t coeffs[512];
  poly_t tf, s1f, s2f;
  size_t off, prooflen;
  unsigned int i;
  int rc, b, rv = 0;

  polyvec_alloc (t, RP, 8);
  polyvec_alloc (u, RP, 8);
  polyvec_alloc (target, RP, 8);
  polyvec_alloc (tau, RP, 8);
  polyvec_alloc (s1v, RP, 8);
  polyvec_alloc (s2v, RP, 8);
  polymat_alloc (A, RP, 8, 24);
  poly_alloc (tf, RF);
  poly_alloc (s1f, RF);
  poly_alloc (s2f, RF);

  /* decode masked message t, then center it */
  coder_dec_begin (cstate, masked_msg);
  rc = coder_dec_urandom3 (cstate, t, anon_q, ANON_COEFFBITS);
  if (rc != 0)
    goto out;
  if (coder_dec_end (cstate) != 1)
    goto out;
  off = coder_get_offset (cstate) >> 3;
  polyvec_redc (t, t);

  /* verify P1: [AR,AM]*(r,m) - t = 0 */
  anon_copy_cols (A, 0, st->AR, 16, 0);
  anon_copy_cols (A, 16, st->AM, 8, 0);
  polyvec_set (u, t);
  polyvec_neg_self (u);
  lin_verifier_set_statement (st->p1, A, u);
  b = lin_verifier_verify (st->p1, masked_msg + off, &prooflen);
  if (b != 1)
    goto out;

  /* tau <- random binary; target = ATAU*tau + t */
  bytes_urandom (tau_, sizeof (tau_));
  anon_bytes_to_polyvec (tau, tau_, 8);
  anon_matvec (target, st->ATAU, tau);
  polyvec_add (target, target, t, 0);

  /* falcon preimage: (s1,s2) with s1 + h*s2 = target.
   * target (Rp^8) -> Falcon poly (deg 512); s1,s2 -> isoring (Rp^8). */
  poly_fromisoring (tf, target);
  poly_redc (tf, tf);
  poly_get_coeffvec_i64 (coeffs, tf);
  for (i = 0; i < 512; i++)
    tt[i] = (int16_t)coeffs[i];

  falcon_preimage_sample (s1, s2, tt, st->privkey);

  poly_set_coeffvec_i16 (s1f, s1);
  poly_set_coeffvec_i16 (s2f, s2);
  poly_toisoring (s1v, s1f);
  poly_toisoring (s2v, s2f);

  /* encode blindsig: tau (bytes), s1, s2 (grandom) */
  coder_enc_begin (cstate, blindsig);
  coder_enc_bytes (cstate, tau_, sizeof (tau_));
  coder_enc_grandom3 (cstate, s1v, ANON_SIG_LOG2O);
  coder_enc_grandom3 (cstate, s2v, ANON_SIG_LOG2O);
  coder_enc_end (cstate);
  *blindsiglen = coder_get_offset (cstate) >> 3;

  rv = 1;
out:
  poly_free (s2f);
  poly_free (s1f);
  poly_free (tf);
  polymat_free (A);
  polyvec_free (s2v);
  polyvec_free (s1v);
  polyvec_free (tau);
  polyvec_free (target);
  polyvec_free (u);
  polyvec_free (t);
  return rv;
}

/* ------------------------------------------------------------------ */
/* verifier */

void
anoncred_verifier_init (anoncred_verifier_state_t st,
                        const uint8_t pk[ANONCRED_PUBKEYLEN])
{
  uint8_t p2pp[32];

  polymat_alloc (st->AR, RP, 8, 16);
  polymat_alloc (st->AM, RP, 8, 8);
  polymat_alloc (st->ATAU, RP, 8, 8);
  polymat_alloc (st->B1, RP, 8, 8);
  polymat_alloc (st->B2, RP, 8, 8);

  anon_pubmats (st->AR, st->AM, st->ATAU, st->B1);
  anon_decode_pk (st->B2, pk);

  anon_ppseed (p2pp, 0x02);
  lin_verifier_init (st->p2, p2pp, p2_param);
}

void
anoncred_verifier_clear (anoncred_verifier_state_t st)
{
  lin_verifier_clear (st->p2);
  polymat_free (st->AR);
  polymat_free (st->AM);
  polymat_free (st->ATAU);
  polymat_free (st->B1);
  polymat_free (st->B2);
}

int
anoncred_verifier_vrfy (anoncred_verifier_state_t st,
                        const uint8_t pub_msg[ANONCRED_MSGLEN],
                        const unsigned int *pub_mvec, unsigned int npub,
                        const uint8_t *sig, size_t siglen)
{
  polyvec_t m, u, zcol;
  polymat_t A, AMpriv;
  unsigned int k;
  size_t len;
  int b;
  (void)siglen;

  polyvec_alloc (m, RP, 8);
  polyvec_alloc (u, RP, 8);
  polyvec_alloc (zcol, RP, 8);
  polymat_alloc (A, RP, 8, 48);
  polymat_alloc (AMpriv, RP, 8, 8);

  anon_bytes_to_polyvec (m, pub_msg, 8);

  polyvec_set_zero (zcol);
  polymat_set (AMpriv, st->AM);
  for (k = 0; k < npub; k++)
    polymat_set_col (AMpriv, zcol, pub_mvec[k]);

  if (npub == 0)
    {
      polyvec_set_zero (u);
    }
  else
    {
      polymat_t AMpub;
      polyvec_t mpub, col;
      polymat_alloc (AMpub, RP, 8, npub);
      polyvec_alloc (mpub, RP, npub);
      polyvec_alloc (col, RP, 8);
      for (k = 0; k < npub; k++)
        {
          polymat_get_col (col, st->AM, pub_mvec[k]);
          polymat_set_col (AMpub, col, k);
          polyvec_set_elem (mpub, k, polyvec_get_elem (m, pub_mvec[k]));
        }
      polyvec_mul (u, AMpub, mpub);
      polyvec_free (col);
      polyvec_free (mpub);
      polymat_free (AMpub);
    }

  anon_copy_cols (A, 0, st->AR, 16, 0);
  anon_copy_cols (A, 16, st->ATAU, 8, 0);
  anon_copy_cols (A, 24, st->B1, 8, 1);
  anon_copy_cols (A, 32, st->B2, 8, 1);
  anon_copy_cols (A, 40, AMpriv, 8, 0);

  lin_verifier_set_statement (st->p2, A, u);
  b = lin_verifier_verify (st->p2, sig, &len);

  polymat_free (AMpriv);
  polymat_free (A);
  polyvec_free (zcol);
  polyvec_free (u);
  polyvec_free (m);
  return b;
}
