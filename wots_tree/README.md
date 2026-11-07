# wots_tree

A tree of 8 WOTS+ one-time keys, built from FIPS 205's components (WOTS+,
the XMSS tree, `PRF_msg` and `H_msg` at SLH-DSA-SHA2-128f's parameters)
through `slh-dsa`'s `hazmat` API. A signature is 625 bytes; a public key is
`PK.seed || root`, 32 bytes.

Each leaf must sign at most one message. This is not SLH-DSA and is not
NIST-approved as a whole; see [SPEC.md](SPEC.md) for what is standard and
what is not.
