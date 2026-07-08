#include "test.h"

#include "anoncred.h"

/* Randomized end-to-end test of the tiered anoncred API (Option C / IRMA-fit).
 * For each tier it varies the secret, the issuer blocks, and pub_mvec (random
 * subset of the tier's issuer block indices, incl. empty and full). Every
 * honest run must verify; flipping a bit in a disclosed block must be
 * rejected. Runs natively (large main stack). */

/* out[nmsg_bytes] <- full, but only the 8-byte blocks at idx[] kept. */
static void
disclosed_blocks (uint8_t *out, unsigned int nmsg, const uint8_t *full,
                  const unsigned int *idx, unsigned int n)
{
  unsigned int i;
  memset (out, 0, (size_t)nmsg * 8);
  for (i = 0; i < n; i++)
    memcpy (out + idx[i] * 8, full + idx[i] * 8, 8);
}

/* Fisher-Yates over the tier's issuer block indices {NSECRET..NSECRET+cap-1};
 * pub = first npub of them (the secret blocks are never disclosed). */
static void
random_split (unsigned int npub, unsigned int cap, unsigned int *pub)
{
  unsigned int *perm = malloc (cap * sizeof (unsigned int));
  unsigned int i, j, t;
  for (i = 0; i < cap; i++)
    perm[i] = ANONCRED_NSECRET + i;
  for (i = cap - 1; i > 0; i--)
    {
      j = (unsigned int)rand () % (i + 1);
      t = perm[i];
      perm[i] = perm[j];
      perm[j] = t;
    }
  for (i = 0; i < npub; i++)
    pub[i] = perm[i];
  free (perm);
}

/* Full honest run at a tier; returns the verifier result (1 == verified). If
 * corrupt is set, one disclosed block of the public message is flipped. */
static int
run_once (unsigned int tier, const uint8_t *secret, const uint8_t *pub_msg,
          const unsigned int *pub, unsigned int npub, int corrupt)
{
  unsigned int cap = anoncred_tier_npub (tier);
  unsigned int nmsg = ANONCRED_NSECRET + cap;
  static uint8_t sk[ANONCRED_PRIVKEYLEN], pk[ANONCRED_PUBKEYLEN];
  static uint8_t masked_msg[ANONCRED_MASKEDMSGLEN_MAX];
  static uint8_t blindsig[ANONCRED_BLINDSIGLEN_MAX];
  static uint8_t sig[ANONCRED_SIGLEN_MAX];
  uint8_t *full = malloc ((size_t)nmsg * 8);
  uint8_t *msg_pub = malloc ((size_t)nmsg * 8);
  size_t mlen = 0, blen = 0, slen = 0;
  anoncred_user_state_t user;
  anoncred_signer_state_t signer;
  anoncred_verifier_state_t verifier;
  int rc, ok = 0;

  memcpy (full, secret, ANONCRED_SECRETLEN);
  memcpy (full + ANONCRED_SECRETLEN, pub_msg, (size_t)cap * 8);

  anoncred_keygen (sk, pk);
  anoncred_user_init (user, pk, tier);
  anoncred_signer_init (signer, pk, sk);
  anoncred_verifier_init (verifier, pk, tier);

  anoncred_user_maskmsg (user, masked_msg, &mlen, secret);
  rc = anoncred_signer_sign (signer, blindsig, &blen, masked_msg, mlen, pub_msg,
                             tier);
  TEST_ASSERT (rc == 1);
  rc = anoncred_user_sign (user, sig, &slen, pub_msg, blindsig, blen, pub, npub);
  TEST_ASSERT (rc == 1);

  disclosed_blocks (msg_pub, nmsg, full, pub, npub);
  if (corrupt && npub > 0)
    msg_pub[pub[0] * 8] ^= 0x01;
  ok = anoncred_verifier_vrfy (verifier, msg_pub, pub, npub, sig, slen);

  anoncred_user_clear (user);
  anoncred_signer_clear (signer);
  anoncred_verifier_clear (verifier);
  free (full);
  free (msg_pub);
  return ok;
}

int
main (void)
{
  unsigned int tier;

  lazer_init ();

  for (tier = 0; tier < ANONCRED_NTIERS; tier++)
    {
      unsigned int cap = anoncred_tier_npub (tier);
      unsigned int npubs[3] = { 0, cap, (unsigned int)rand () % (cap + 1) };
      unsigned int which;
      uint8_t secret[ANONCRED_SECRETLEN];
      uint8_t *pub_msg = malloc ((size_t)cap * 8);
      unsigned int *pub = malloc (cap * sizeof (unsigned int));

      for (which = 0; which < 3; which++)
        {
          unsigned int npub = npubs[which];
          bytes_urandom (secret, sizeof (secret));
          bytes_urandom (pub_msg, (size_t)cap * 8);
          random_split (npub, cap, pub);

          TEST_EXPECT (run_once (tier, secret, pub_msg, pub, npub, 0) == 1);
          if (npub > 0)
            TEST_EXPECT (run_once (tier, secret, pub_msg, pub, npub, 1) != 1);

          fprintf (stderr, "[OK] tier %u (cap %u): npub=%u\n", tier, cap, npub);
        }

      free (pub_msg);
      free (pub);
    }

  TEST_PASS ();
}
