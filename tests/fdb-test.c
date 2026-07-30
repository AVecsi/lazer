#include "fdb.h"
#include "test.h"
#include <mpfr.h>
#include <string.h>
#include <time.h>

/*
 * End-to-end test of the Falcon device-binding API (src/fdb.h), using only its
 * public entry points -- no state internals are touched, so this doubles as the
 * usage example for the API.
 *
 * Everything crossing the signer/verifier boundary is a byte buffer: the
 * serialized credential t_h at issuance, and the (salt, proof) pair per
 * signature.  The verifier holds public data only.
 *
 * Covered:
 *   honest run                     -> accept
 *   proof under a different message    -> reject (bound to the message)
 *   proof under a different credential -> reject (bound to the committed key)
 *   malformed / wrong-length credential -> rejected at set_credential
 *   prove before issue, verify before set_credential -> rejected
 */

#define FDB_MSG_BYTES 32

static double
wall (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* honest run + the two binding properties. */
static int
run (const uint8_t seed[32])
{
  fdb_signer_state_t signer;
  fdb_verifier_state_t verifier;
  uint8_t sk[FDB_PRIVKEYLEN], pk[FDB_PUBKEYLEN];
  uint8_t msg[FDB_MSG_BYTES], msg2[FDB_MSG_BYTES];
  uint8_t salt[FDB_SALT_BYTES];
  static uint8_t proof[FDB_PROOF_MAXLEN];
  static uint8_t cred[FDB_CRED_MAXLEN], cred2[FDB_CRED_MAXLEN];
  size_t prooflen, credlen, cred2len;
  double t0, t1, t2;
  int bres = 1;

  fdb_keygen (sk, pk);
  fdb_signer_init (signer, seed, sk, pk);
  fdb_verifier_init (verifier, seed);

  /* issuance (once): the holder computes t_h = AR*rc + AM*h and sends the
   * PUBLIC t_h -- serialized, like everything crossing the boundary -- to the
   * verifier, which stores it as the credential. */
  if (!fdb_signer_issue (signer, cred, &credlen))
    return 0;
  if (!fdb_verifier_set_credential (verifier, cred, credlen))
    return 0;

  /* verifier -> wire: message.  The verifier chooses only the message; the
   * challenge c is derived (by both sides) from HashToPoint of the salt the
   * signer returns -- it is never chosen directly. */
  bytes_urandom (msg, sizeof (msg));

  /* signer -> wire: commitment + proof + salt (r0, c, and t_h's opening are
   * NOT sent) */
  t0 = wall ();
  if (!fdb_signer_prove (signer, proof, &prooflen, salt, msg, sizeof (msg)))
    return 0;
  t1 = wall ();

  /* honest: verify against the message the proof was made for -> accept */
  bres = fdb_verifier_vrfy (verifier, proof, prooflen, msg, sizeof (msg),
                            salt);
  t2 = wall ();
  fprintf (stderr,
           "  proof size = %zu bytes (%.2f KiB)   prove = %.3f s   "
           "verify = %.3f s\n",
           prooflen, prooflen / 1024.0, t1 - t0, t2 - t1);
  if (!bres)
    fprintf (stderr, "  [FAIL] honest proof did not verify\n");

  /* soundness / binding: verify the SAME proof (and salt) against a DIFFERENT
   * message -> must reject.  The verifier derives c' = HashToPoint(salt||msg')
   * and r0 = -c', so the committed witness no longer satisfies
   * s1 + (s2*h) - c' - p*k = 0 and verification must fail.  See
   * falcon-devicebind-soundness-issue.md. */
  bytes_urandom (msg2, sizeof (msg2));
  if (fdb_verifier_vrfy (verifier, proof, prooflen, msg2, sizeof (msg2), salt)
      != 0)
    {
      fprintf (stderr, "  [FAIL] proof accepted under a DIFFERENT message -- "
                       "not bound to the message!\n");
      bres = 0;
    }
  else
    fprintf (stderr, "  [OK] proof rejected under a different message\n");

  /* binding to the COMMITTED KEY: verify the same proof against a DIFFERENT
   * credential -> must reject.  Re-issuing draws fresh randomness rc, so
   * t_h' != t_h commits to the same key under a different opening; the
   * verifier's opening equations get r0 = -t_h', which the proof's committed
   * (rc, h) no longer satisfies. */
  if (!fdb_signer_issue (signer, cred2, &cred2len))
    return 0;
  if (!fdb_verifier_set_credential (verifier, cred2, cred2len))
    return 0;
  if (fdb_verifier_vrfy (verifier, proof, prooflen, msg, sizeof (msg), salt)
      != 0)
    {
      fprintf (stderr, "  [FAIL] proof accepted under a DIFFERENT credential "
                       "-- not bound to the committed key!\n");
      bres = 0;
    }
  else
    fprintf (stderr, "  [OK] proof rejected under a different credential\n");

  /* the credential encoding is fixed-width, so a truncated or padded buffer is
   * rejected outright (before any decoding) */
  if (fdb_verifier_set_credential (verifier, cred, credlen - 1) != 0
      || fdb_verifier_set_credential (verifier, cred, credlen + 1) != 0)
    {
      fprintf (stderr, "  [FAIL] wrong-length credential accepted\n");
      bres = 0;
    }
  else
    fprintf (stderr, "  [OK] wrong-length credential rejected\n");

  fdb_signer_clear (signer);
  fdb_verifier_clear (verifier);
  return bres;
}

/* API misuse must fail cleanly, not read uninitialized state: proving before
 * issuance (rc unset) and verifying before a credential is stored (t_h and the
 * opening equations' r0 unset) both return 0. */
static int
run_guards (const uint8_t seed[32])
{
  fdb_signer_state_t signer;
  fdb_verifier_state_t verifier;
  uint8_t sk[FDB_PRIVKEYLEN], pk[FDB_PUBKEYLEN];
  uint8_t msg[FDB_MSG_BYTES], salt[FDB_SALT_BYTES];
  static uint8_t proof[FDB_PROOF_MAXLEN];
  static uint8_t cred[FDB_CRED_MAXLEN];
  size_t prooflen, credlen;
  int bres = 1;

  fdb_keygen (sk, pk);
  fdb_signer_init (signer, seed, sk, pk);
  fdb_verifier_init (verifier, seed);
  bytes_urandom (msg, sizeof (msg));

  if (fdb_signer_prove (signer, proof, &prooflen, salt, msg, sizeof (msg))
      != 0)
    {
      fprintf (stderr, "  [FAIL] prove succeeded before issuance\n");
      bres = 0;
    }

  /* issue and prove, so the credential-less verifier gets a genuine proof */
  if (!fdb_signer_issue (signer, cred, &credlen))
    return 0;
  if (!fdb_signer_prove (signer, proof, &prooflen, salt, msg, sizeof (msg)))
    return 0;
  if (fdb_verifier_vrfy (verifier, proof, prooflen, msg, sizeof (msg), salt)
      != 0)
    {
      fprintf (stderr, "  [FAIL] verify succeeded without a credential\n");
      bres = 0;
    }
  if (bres)
    fprintf (stderr, "  [OK] prove-before-issue and verify-before-credential "
                     "both rejected\n");

  /* and the same proof does verify once the credential is in place */
  if (!fdb_verifier_set_credential (verifier, cred, credlen))
    return 0;
  if (fdb_verifier_vrfy (verifier, proof, prooflen, msg, sizeof (msg), salt)
      != 1)
    {
      fprintf (stderr, "  [FAIL] proof did not verify after the credential "
                       "was stored\n");
      bres = 0;
    }

  fdb_signer_clear (signer);
  fdb_verifier_clear (verifier);
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
  TEST_EXPECT (run (seed) == 1);
  TEST_EXPECT (run_guards (seed) == 1);
  fprintf (stderr,
           "[OK] honest Falcon device-binding proof verifies against the "
           "committed key\n");

  mpfr_free_cache ();
  TEST_PASS ();
}
