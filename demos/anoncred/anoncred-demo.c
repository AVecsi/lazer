#include "anoncred.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Tiered Option C / IRMA-fit demo. The message blocks are the user's secret
 * (the first ANONCRED_NSECRET blocks) followed by the issuer-controlled blocks
 * (metadata + public attributes). Credential size is dynamic: the smallest
 * tier whose capacity covers the public-attribute count is used; unused issuer
 * blocks are zero. The user commits only the secret; the issuer adds its blocks
 * when signing. At disclosure any subset of issuer blocks may be revealed; the
 * secret stays hidden. */

/* out[nmsg*8] <- full, but only the 8-byte blocks at idx[] kept. */
static void
disclosed_blocks (uint8_t *out, unsigned int nmsg, const uint8_t *full,
                  const unsigned int *idx, unsigned int n)
{
  unsigned int i;
  memset (out, 0, (size_t)nmsg * 8);
  for (i = 0; i < n; i++)
    memcpy (out + idx[i] * 8, full + idx[i] * 8, 8);
}

static double
now (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}

int
main (void)
{
  const unsigned int nPublic = 16; /* requested public attributes */
  static uint8_t sk[ANONCRED_PRIVKEYLEN], pk[ANONCRED_PUBKEYLEN];
  static uint8_t masked_msg[ANONCRED_MASKEDMSGLEN_MAX];
  static uint8_t blindsig[ANONCRED_BLINDSIGLEN_MAX];
  static uint8_t sig[ANONCRED_SIGLEN_MAX];
  uint8_t secret[ANONCRED_SECRETLEN];
  uint8_t *pub_msg, *full, *msg_pub;
  size_t masked_msglen = 0, blindsiglen = 0, siglen = 0;
  double t0, t1, s0, s1;
  unsigned int i, cap, nmsg;
  int tier, rc;

  anoncred_user_state_t user;
  anoncred_signer_state_t signer;
  anoncred_verifier_state_t verifier;

  lazer_init ();

  printf ("lazer anonymous credentials demo (C, tiered Option C)\n");
  printf ("-----------------------------------------------------\n\n");

  tier = anoncred_tier_for_npub (nPublic);
  if (tier < 0)
    {
      printf ("no tier for %u public attributes (max %u)\n", nPublic,
              ANONCRED_NPUB_MAX);
      return 1;
    }
  cap = anoncred_tier_npub ((unsigned int)tier);
  nmsg = ANONCRED_NSECRET + cap;
  printf ("public attributes: %u -> tier %d (capacity %u, total %u blocks)\n\n",
          nPublic, tier, cap, nmsg);

  pub_msg = malloc ((size_t)cap * 8);
  full = malloc ((size_t)nmsg * 8);
  msg_pub = malloc ((size_t)nmsg * 8);

  for (i = 0; i < ANONCRED_SECRETLEN; i++)
    secret[i] = (uint8_t)((i % 8) * 0x22 + 0x01);
  memset (pub_msg, 0, (size_t)cap * 8);
  for (i = 0; i < nPublic * 8; i++)
    pub_msg[i] = (uint8_t)((i % 8) * 0x11 + 0x03);
  memcpy (full, secret, ANONCRED_SECRETLEN);
  memcpy (full + ANONCRED_SECRETLEN, pub_msg, (size_t)cap * 8);

  /* disclose two issuer blocks (indices >= ANONCRED_NSECRET) */
  const unsigned int pub_mvec[] = { ANONCRED_NSECRET, ANONCRED_NSECRET + 3 };
  const unsigned int npub = 2;

  anoncred_keygen (sk, pk);

  printf ("Initialize user, signer (issuer), verifier ... ");
  anoncred_user_init (user, pk, (unsigned int)tier);
  anoncred_signer_init (signer, pk, sk);
  anoncred_verifier_init (verifier, pk, (unsigned int)tier);
  printf ("[OK]\n\n");

  t0 = now ();
  printf ("User commits its secret ... ");
  fflush (stdout);
  anoncred_user_maskmsg (user, masked_msg, &masked_msglen, secret);
  printf ("[OK]  (masked: %zu bytes)\n", masked_msglen);

  printf ("Issuer checks P1, adds its blocks, blind-signs ... ");
  fflush (stdout);
  rc = anoncred_signer_sign (signer, blindsig, &blindsiglen, masked_msg,
                             masked_msglen, pub_msg, (unsigned int)tier);
  if (rc != 1)
    {
      printf ("masked credentials are invalid.\n");
      return 1;
    }
  printf ("[OK]  (blindsig: %zu bytes)\n", blindsiglen);
  t1 = now ();

  s0 = now ();
  printf ("User outputs a disclosure proof revealing chosen issuer blocks ... ");
  fflush (stdout);
  rc = anoncred_user_sign (user, sig, &siglen, pub_msg, blindsig, blindsiglen,
                           pub_mvec, npub);
  if (rc != 1)
    {
      printf ("decoding failed.\n");
      return 1;
    }
  printf ("[OK]  (proof: %zu bytes)\n", siglen);

  printf ("Verifier verifies the disclosure proof ... ");
  fflush (stdout);
  disclosed_blocks (msg_pub, nmsg, full, pub_mvec, npub);
  rc = anoncred_verifier_vrfy (verifier, msg_pub, pub_mvec, npub, sig, siglen);
  s1 = now ();
  if (rc != 1)
    {
      printf ("signature invalid.\n");
      return 1;
    }
  printf ("[OK]\n\n");

  printf ("Issue time: %.3f s\n", t1 - t0);
  printf ("Show time:  %.3f s\n", s1 - s0);

  anoncred_user_clear (user);
  anoncred_signer_clear (signer);
  anoncred_verifier_clear (verifier);
  free (pub_msg);
  free (full);
  free (msg_pub);
  return 0;
}
