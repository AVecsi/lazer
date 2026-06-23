#include "anoncred.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* zero out the 8-byte blocks of msg at the indices in idx[] (C port of
 * zero_out_bytes(msg, priv_mvec, deg//8)). */
static void
zero_out_blocks (uint8_t out[ANONCRED_MSGLEN], const uint8_t *in,
                 const unsigned int *idx, unsigned int n)
{
  unsigned int i;
  memcpy (out, in, ANONCRED_MSGLEN);
  for (i = 0; i < n; i++)
    memset (out + idx[i] * 8, 0, 8);
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
  static uint8_t sk[ANONCRED_PRIVKEYLEN], pk[ANONCRED_PUBKEYLEN];
  static uint8_t masked_msg[ANONCRED_MASKEDMSGLEN_MAX];
  static uint8_t blindsig[ANONCRED_BLINDSIGLEN_MAX];
  static uint8_t sig[ANONCRED_SIGLEN_MAX];
  uint8_t msg[ANONCRED_MSGLEN];
  uint8_t msg_pub[ANONCRED_MSGLEN];
  size_t masked_msglen = 0, blindsiglen = 0, siglen = 0;
  double t0, t1;
  unsigned int i;

  /* disclosed message indices and their complement */
  const unsigned int pub_mvec[] = { 0, 4, 5 };
  const unsigned int npub = 3;
  unsigned int priv_mvec[ANONCRED_NMSG], npriv = 0;
  int rc;

  anoncred_user_state_t user;
  anoncred_signer_state_t signer;
  anoncred_verifier_state_t verifier;

  lazer_init ();

  printf ("lazer anonymous credentials demo (C)\n");
  printf ("--------------------------\n\n");

  /* message: 64 bytes 0x0123456789abcdef repeated, as in anon_cred.py */
  for (i = 0; i < ANONCRED_MSGLEN; i++)
    msg[i] = (uint8_t)((i % 8) * 0x22 + 0x01); /* arbitrary fixed content */

  /* priv_mvec = {0..7} \ pub_mvec */
  for (i = 0; i < ANONCRED_NMSG; i++)
    {
      unsigned int j, ispub = 0;
      for (j = 0; j < npub; j++)
        if (pub_mvec[j] == i)
          ispub = 1;
      if (!ispub)
        priv_mvec[npriv++] = i;
    }

  anoncred_keygen (sk, pk);

  printf ("Initialize user with public key ... ");
  anoncred_user_init (user, pk);
  printf ("[OK]\n\n");

  printf ("Initialize signer with public and private key ... ");
  anoncred_signer_init (signer, pk, sk);
  printf ("[OK]\n\n");

  printf ("Initialize verifier with public key ... ");
  anoncred_verifier_init (verifier, pk);
  printf ("[OK]\n\n");

  t0 = now ();
  printf ("User outputs masked credentials (incl. proof of well-formedness) ... ");
  fflush (stdout);
  anoncred_user_maskmsg (user, masked_msg, &masked_msglen, msg);
  printf ("[OK]\n");
  printf ("masked credentials (t,P1): %zu bytes\n\n", masked_msglen);

  printf ("Signer checks the proof and outputs blinded credentials ... ");
  fflush (stdout);
  rc = anoncred_signer_sign (signer, blindsig, &blindsiglen, masked_msg,
                             masked_msglen);
  if (rc != 1)
    {
      printf ("masked credentials are invalid.\n");
      return 1;
    }
  printf ("[OK]\n");
  t1 = now ();
  printf ("blind credentials (tau,s1,s2): %zu bytes\n\n", blindsiglen);

  printf ("User outputs a signature on the hidden credentials ... ");
  fflush (stdout);
  double s0 = now ();
  rc = anoncred_user_sign (user, sig, &siglen, blindsig, blindsiglen,
                           pub_mvec, npub);
  if (rc != 1)
    {
      printf ("decoding failed.\n");
      return 1;
    }
  printf ("[OK]\n");
  printf ("signature (P2): %zu bytes\n\n", siglen);

  printf ("Verifier verifies the signature of the blinded credentials ... ");
  fflush (stdout);
  zero_out_blocks (msg_pub, msg, priv_mvec, npriv);
  rc = anoncred_verifier_vrfy (verifier, msg_pub, pub_mvec, npub, sig, siglen);
  double s1 = now ();
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
  return 0;
}
