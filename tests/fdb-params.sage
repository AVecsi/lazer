# Parameters for the FULL Falcon-512 device-binding proof.
# Statement over Rp = Z_12289[X]/(X^64+1), 8-block isoring rep of deg-512:
#
#     s1 + s2*h - c - p*k = 0   (8 block equations),  ||(s1,s2)||_2 <= beta,
#                                                     ||k||_inf <= B'
#
# witness:  s1_iso(8), s2_iso(8)  bounded (Ajtai, the Falcon signature) -> m1 = 16
#           h_iso(8), k(8)        unbounded (BDLOP): hidden key + quotient -> l = 16
# bounds mirror anoncred's P2 (same Falcon relation): beta = sqrt(34034726),
# quotient linf bound ~ anoncred's approximate-infinity bound.

name = "fdb_param"

log2q = 51
d = 64

m1 = 16                        # s1_iso(8) + s2_iso(8)
alpha = sqrt(34034726)         # l2(s1) <= beta (Falcon signature norm)
l = 16                         # h_iso(8) + k(8)

nbin = 0

n = [16]                       # one l2 proof over (s1_iso, s2_iso) ...
B = [sqrt(34034726)]           # ... bound beta

nprime = 8                     # one linf proof over the 8-block quotient k ...
Bprime = 8958759               # ... bound (from anoncred P2 approx-inf)
