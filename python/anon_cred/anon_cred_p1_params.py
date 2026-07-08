# Create a header file with LNP proof system parameters for
# proving knowledge of a witness w in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. w satisfies a linear relation over Rp: Aw + t = 0
#   2. each element in a partition of w either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound

vname = "p1_param"       # variable name

deg   = 64               # ring Rp degree d
mod   = 12289             # ring Rp modulus p
# Option C (IRMA-fit): the user commits ONLY its secret blocks. A = [AR | AM_secret]
# in Rp^(8, 16 + NSECRET) with NSECRET = 4 (256-bit link secret). The issuer adds
# its public/metadata blocks homomorphically after verifying this proof.
dim   = (8,20)             # dimensions of A in Rp^(m,n): AR(16) + AM_secret(4)

wpart = [ list(range(0,16)), list(range(16,20)) ]  # partition of w    : [r1,r2], [secret (4 blocks)]
wl2   = [   109,     0 ]  # l2-norm bounds    : l2(r1,r2) <= 109
wbin  = [     0,     1 ]  # binary coeffs     : secret is binary
#wrej  = [     0,     1 ]  # rejection sampling: on secret only

# Optional: some linf-norm bound on w.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
wlinf = 19 # optional linf: some linf-norm bound on w.

# Keep the whole witness in the Ajtai part (avoid the unreliable lin BDLOP m-partition).
no_bdlop = True
