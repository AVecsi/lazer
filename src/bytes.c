#include "lazer.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Bionic only declares/exports getentropy(2) from API level 28 onward. When
 * building for an older Android platform, fall back to /dev/urandom (always
 * available) so the library links and runs on API < 28 devices. */
#if defined(__ANDROID__) && defined(__ANDROID_API__) && __ANDROID_API__ < 28
#include <errno.h>
#include <fcntl.h>
static int
_lazer_getentropy (void *buf, size_t n)
{
  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  size_t off = 0;
  while (off < n)
    {
      ssize_t r = read (fd, (uint8_t *)buf + off, n - off);
      if (r <= 0)
        {
          if (r < 0 && errno == EINTR)
            continue;
          close (fd);
          return -1;
        }
      off += (size_t)r;
    }
  close (fd);
  return 0;
}
#define getentropy _lazer_getentropy
#endif

static inline int ishexdigit (const int);
static inline uint8_t hexdigit2bits (int);
static int bits2hexdigit (uint8_t);

void
bytes_urandom (uint8_t *bytes, const size_t len)
{
  size_t off;

  /* getentropy(2) rejects requests larger than 256 bytes, so chunk. Larger
   * single requests arise from the bigger LNP parameter sets (e.g. the larger
   * anoncred tiers). */
  for (off = 0; off < len; off += 256)
    {
      size_t chunk = len - off < 256 ? len - off : 256;
      int rv = getentropy (bytes + off, chunk);
      ERR (rv != 0, "getentropy failed (size %llu).\n",
           (unsigned long long)chunk);
    }
}

size_t
bytes_out_str (FILE *stream, const uint8_t *bytes, size_t len)
{
  const uint8_t *in = bytes;
  size_t i;
  int c;

  for (i = 0; i < len; i++)
    {
      c = bits2hexdigit (in[i] >> 4);
      if (UNLIKELY (fputc (c, stream) != c))
        return 0;

      c = bits2hexdigit (in[i] & 0xf);
      if (UNLIKELY (fputc (c, stream) != c))
        return 0;
    }
  return 2 * len;
}

size_t
bytes_inp_str (uint8_t *bytes, size_t len, FILE *stream)
{
  size_t i = 0;
  int c;

  do
    {
      c = fgetc (stream);
    }
  while (isspace (c));
  ungetc (c, stream);

  for (; i < 2 * len; i += 2)
    {
      c = fgetc (stream);
      if (UNLIKELY (!ishexdigit (c)))
        goto err;

      bytes[i / 2] = hexdigit2bits (c) << 4;

      c = fgetc (stream);
      if (UNLIKELY (!ishexdigit (c)))
        goto err;

      bytes[i / 2] += hexdigit2bits (c);
    }

  return 2 * len;
err:
  ungetc (c, stream);
  return 0;
}

size_t
bytes_out_raw (FILE *stream, const uint8_t *bytes, size_t len)
{
  return fwrite (bytes, 1, len, stream);
}

size_t
bytes_inp_raw (uint8_t *bytes, size_t len, FILE *stream)
{
  return fread (bytes, 1, len, stream);
}

void
bytes_clear (uint8_t *bytes, const size_t nbytes)
{
  explicit_bzero (bytes, nbytes);
}

static inline int
ishexdigit (const int d)
{
  return ((d >= '0' && d <= '9') || (d >= 'A' && d <= 'F')
          || (d >= 'a' && d <= 'f'));
}

static inline uint8_t
hexdigit2bits (int d)
{
  const int noff = '0' - 0;
  const int uoff = 'A' - 10;
  const int loff = 'a' - 10;

  return (d >= 'a' ? d - loff : (d >= 'A' ? d - uoff : d - noff));
}

static inline int
bits2hexdigit (uint8_t b)
{
  const char noff = '0' - 0;
  const char loff = 'a' - 10;

  return (b >= 10 ? b + loff : b + noff);
}
