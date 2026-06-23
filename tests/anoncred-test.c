#include "test.h"

#include "anoncred.h"

/* Randomized end-to-end test of the anoncred API. Varies the two
 * in-practice-arbitrary inputs: msg (random bytes) and pub_mvec (random
 * subset of {0..7}, including the empty and full edge cases). Keys, r and
 * tau are already random inside the library. Every honest run must verify;
 * flipping a bit in a disclosed block must be rejected (negative control). */

/* deterministic spread of disclosure counts: none, all, and partials */
static const unsigned int NPUB[] = { 0, 8, 1, 3, 5, 7 };
#define ITERS ((int)(sizeof (NPUB) / sizeof (NPUB[0])))

static void
zero_out_blocks (uint8_t out[ANONCRED_MSGLEN], const uint8_t *in,
                 const unsigned int *idx, unsigned int n)
{
  unsigned int i;
  memcpy (out, in, ANONCRED_MSGLEN);
  for (i = 0; i < n; i++)
    memset (out + idx[i] * 8, 0, 8);
}

/* Fisher-Yates a permutation of {0..7}; pub = first npub, priv = rest. */
static void
random_split (unsigned int npub, unsigned int *pub, unsigned int *priv,
              unsigned int *npriv)
{
  unsigned int perm[ANONCRED_NMSG], i, j, t;
  for (i = 0; i < ANONCRED_NMSG; i++)
    perm[i] = i;
  for (i = ANONCRED_NMSG - 1; i > 0; i--)
    {
      j = (unsigned int)rand () % (i + 1);
      t = perm[i];
      perm[i] = perm[j];
      perm[j] = t;
    }
  for (i = 0; i < npub; i++)
    pub[i] = perm[i];
  *npriv = 0;
  for (i = npub; i < ANONCRED_NMSG; i++)
    priv[(*npriv)++] = perm[i];
}

/* Full honest run; returns the verifier result (1 == verified). If corrupt
 * is set, one disclosed block of the public message is flipped (must fail). */
static int
run_once (const uint8_t *msg, const unsigned int *pub, unsigned int npub,
          const unsigned int *priv, unsigned int npriv, int corrupt)
{
  static uint8_t sk[ANONCRED_PRIVKEYLEN], pk[ANONCRED_PUBKEYLEN];
  static uint8_t masked_msg[ANONCRED_MASKEDMSGLEN_MAX];
  static uint8_t blindsig[ANONCRED_BLINDSIGLEN_MAX];
  static uint8_t sig[ANONCRED_SIGLEN_MAX];
  uint8_t msg_pub[ANONCRED_MSGLEN];
  size_t mlen = 0, blen = 0, slen = 0;
  anoncred_user_state_t user;
  anoncred_signer_state_t signer;
  anoncred_verifier_state_t verifier;
  int rc, ok = 0;

  anoncred_keygen (sk, pk);
  anoncred_user_init (user, pk);
  anoncred_signer_init (signer, pk, sk);
  anoncred_verifier_init (verifier, pk);

  anoncred_user_maskmsg (user, masked_msg, &mlen, msg);
  rc = anoncred_signer_sign (signer, blindsig, &blen, masked_msg, mlen);
  TEST_ASSERT (rc == 1); /* signer must accept an honest masked message */
  rc = anoncred_user_sign (user, sig, &slen, blindsig, blen, pub, npub);
  TEST_ASSERT (rc == 1); /* blindsig must decode */

  zero_out_blocks (msg_pub, msg, priv, npriv);
  if (corrupt)
    msg_pub[pub[0] * 8] ^= 0x01;
  ok = anoncred_verifier_vrfy (verifier, msg_pub, pub, npub, sig, slen);

  anoncred_user_clear (user);
  anoncred_signer_clear (signer);
  anoncred_verifier_clear (verifier);
  return ok;
}

int
main (void)
{
  int i;

  lazer_init ();

  for (i = 0; i < ITERS; i++)
    {
      uint8_t msg[ANONCRED_MSGLEN];
      unsigned int pub[ANONCRED_NMSG], priv[ANONCRED_NMSG], npriv;
      unsigned int npub = NPUB[i];

      bytes_urandom (msg, sizeof (msg));
      random_split (npub, pub, priv, &npriv);

      /* honest run must verify */
      TEST_EXPECT (run_once (msg, pub, npub, priv, npriv, 0) == 1);

      /* negative control (only meaningful when something is disclosed) */
      if (npub > 0)
        TEST_EXPECT (run_once (msg, pub, npub, priv, npriv, 1) != 1);

      fprintf (stderr, "[OK] iter %d: npub=%u\n", i, npub);
    }

  TEST_PASS ();
}
