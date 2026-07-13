# CPace

Python implementation of [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/), the balanced composable password-authenticated key exchange (PAKE) recommended by the CFRG, in its **CPACE-X25519-SHA512** cipher suite, with the draft's optional explicit mutual key confirmation.

A PAKE lets two parties who share a low-entropy secret (a PIN, a short password) derive a strong shared key over an insecure channel, such that an active attacker gets exactly one online password guess per protocol run and learns nothing usable for offline brute-force.

Implemented and reviewed against draft-irtf-cfrg-cpace revision 21; all known-answer tests from the draft's `testvectors.json` pass, including the full invalid-point rejection set.

## Install

```
pip install cpace
```

## Security considerations

- **Anonymous unless you supply identities.** With the default empty `ad`/`peer_ad`, a verifying confirmation tag proves the peer used the same password — not *which* peer. To authenticate identities, bind them into `ci` and/or `ad`/`peer_ad`; what an identity is and how it is checked is the application's responsibility — the library only guarantees the run fails unless both sides agree on the bytes. As a baseline, `verify()` rejects a peer that merely reflects your own share and tag back, so confirmation cannot be satisfied by echoing your own messages.
- **Timing side channels.** The password-dependent Elligator2 map is branchless (no secret-dependent branches or memory indexing), but it runs on CPython big integers, whose arithmetic is not constant-time. The draft requires the mapping to execute in constant time; that guarantee is not achievable in pure Python. This is a deliberate trade-off: it is fine for rate-limited, short-lived secrets (device-pairing PINs with attempt lockout), but reconsider before using this library with long-term passwords against an attacker who can precisely time your process (e.g. co-located on the same host).
- **No secret zeroization.** Python's memory model does not allow reliably wiping the scalar, ISK, or password copies from memory.

## Scope

Only the CPACE-X25519-SHA512 suite in initiator-responder mode is implemented. Symmetric (unordered) mode and the other cipher suites from the draft are out of scope for now.
