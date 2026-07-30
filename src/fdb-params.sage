# Parameters for the FULL Falcon-512 device-binding proof with credential
# binding (committed public key).
# Statement over Rp = Z_12289[X]/(X^64+1), 8-block isoring rep of deg-512:
#
#     s1 + s2*h - c - p*k = 0        (8 quadratic block equations),
#     AR*rc + AM*h - t_h  = 0        (8 linear block equations over Rq:
#                                     opening of the credential commitment),
#     ||(s1,s2)||_2 <= beta,  ||rc||_2 <= sqrt(16*64),
#     ||(k, FSCALE*h)||_inf <= B'    (one approximate-linf proof; its scaled
#                                     rows bound |h|_inf <= psi*B'/FSCALE)
#
# witness:  s1_iso(8), s2_iso(8)  bounded (Ajtai, the Falcon signature)
#           rc(16)                bounded ternary (credential commitment
#                                 randomness)                     -> m1 = 32
#           h_iso(8), k(8)        BDLOP: hidden key + quotient    -> l = 16
# bounds: beta = sqrt(34034726) (Falcon), rc ternary -> l2^2 <= 16*64.

name = "fdb_param"

log2q = 51
d = 64

m1 = 32                        # s1_iso(8) + s2_iso(8) + rc(16)
alpha = sqrt(34034726 + 16*64) # l2(s1) <= sqrt(beta^2 + l2(rc)^2)
l = 16                         # h_iso(8) + k(8)

nbin = 0

n = [16, 16]                   # two l2 proofs: (s1_iso,s2_iso) and rc
B = [sqrt(34034726), sqrt(16*64)]

# Approximate-linf proof over the 16-block vector v = (k, FSCALE*h).
#
# The codegen uses Bprime as the l2 budget of the WHOLE vector (alpha4 =
# Bprime sizes stdev4 and the bimodal rejection sampling on z4), so
# completeness needs ||(k, FSCALE*h)||_2 <= Bprime for every honest witness
# (worst case, not just typical):
#   ||h||_2 <= sqrt(512)*(p-1)/2                        (h centered mod p)
#   |k|_inf <= (beta*||h||_2 + |s1|_inf + |c|_inf)/p    (per-coefficient
#              bound on (s1 + s2*h - c)/p; |s1|_inf, |c|_inf <= (p-1)/2)
# Soundness extracts |v|_inf <= psi*Bprime with psi = 2*gamma4*sqrt(377*2*128)
# ~ 3107 (see lnp-tbox-codegen.sage), hence
#   |k|_inf <= psi*Bprime:        p*psi*Bprime + beta*sqrt(512)*|h'|_inf
#                                 < q/2 keeps s1 + s2*h - c - p*k = 0
#                                 wrap-free over Z, so it holds mod p
#                                 (q ~ 2^51: margin ~ 2.8x);
#   |h|_inf <= psi*Bprime/FSCALE ~ 2^28.7:  any second opening of t_h is
#                                 that short, so binding reduces to MSIS on
#                                 [AR|AM] (with the exact ternary l2 bound
#                                 on rc keeping the instance unbalanced-hard).
# FSCALE trades the two: larger FSCALE cannot push |h|'s bound below
# psi*||h||_2 (the h rows then dominate Bprime), but inflates Bprime and so
# k's bound, eating the wrap-free margin.  FSCALE = 64 already makes the h
# rows dominate the l2 budget (the k term is < 2% of Bprime).
# Keep FSCALE/Bprime in sync with FDB_FSCALE (and the Bprime budget) in fdb.c.
FSCALE = 64
Bh2 = sqrt(512) * 6144                               # worst-case ||h||_2
Kinf = (sqrt(34034726) * Bh2 + 6144 + 6144) / 12289  # worst-case |k|_inf
nprime = 16                    # linf proof over k(8) and FSCALE*h(8)
Bprime = ceil(sqrt((FSCALE * Bh2)^2 + 512 * Kinf^2))
print(f"# Bprime = {Bprime}", file=sys.stderr)
