from math import sqrt

# Tiered disclosure proof (Option C, IRMA-fit). Tier: 32 public attributes.
# Witness: [r(16) | tau(8) | s1,s2(16) | msg(36)] = 76.
# msg = NSECRET(4) secret blocks + 32 issuer blocks.
vname = "p2_param_32"

deg   = 64
mod   = 12289
dim   = (8,76)

wpart = [ list(range(0,16)), list(range(16,24)), list(range(24,40)), list(range(40,76)) ]
wl2   = [   109,   0, sqrt(34034726), 0 ]
wbin  = [     0,   1,              0, 1 ]

wlinf = 5833

# Keep the whole witness in the Ajtai part (avoid the unreliable lin BDLOP m-partition).
no_bdlop = True
