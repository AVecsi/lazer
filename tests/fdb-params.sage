# Parameters for the FULL Falcon-512 device-binding proof with credential
# binding (committed public key).
# Statement over Rp = Z_12289[X]/(X^64+1), 8-block isoring rep of deg-512:
#
#     s1 + s2*h - c - p*k = 0        (8 quadratic block equations),
#     AR*rc + AM*h - t_h  = 0        (8 linear block equations over Rq:
#                                     opening of the credential commitment),
#     ||(s1,s2)||_2 <= beta,  ||rc||_2 <= sqrt(16*64),  ||k||_inf <= B',
#     ||h||_inf <= (p-1)/2  (via the scaled rows of the same linf proof)
#
# witness:  s1_iso(8), s2_iso(8)  bounded (Ajtai, the Falcon signature)
#           rc(16)                bounded ternary (credential commitment
#                                 randomness)                     -> m1 = 32
#           h_iso(8), k(8)        BDLOP: hidden key + quotient    -> l = 16
# bounds: beta = sqrt(34034726) (Falcon), rc ternary -> l2^2 <= 16*64,
# quotient linf bound ~ anoncred's approximate-infinity bound; h is bounded
# by (p-1)/2 through rows FSCALE*I of Dm with FSCALE = floor(Bprime/6144).

name = "fdb_param"

log2q = 51
d = 64

m1 = 32                        # s1_iso(8) + s2_iso(8) + rc(16)
alpha = sqrt(34034726 + 16*64) # l2(s1) <= sqrt(beta^2 + l2(rc)^2)
l = 16                         # h_iso(8) + k(8)

nbin = 0

n = [16, 16]                   # two l2 proofs: (s1_iso,s2_iso) and rc
B = [sqrt(34034726), sqrt(16*64)]

nprime = 16                    # linf proof over k(8) and FSCALE*h(8)
Bprime = 8958759               # bound (from anoncred P2 approx-inf)
