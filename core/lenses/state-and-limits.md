---
id: state-and-limits
title: State, concurrency and limits
scope: surface
bug_classes: race condition, denial of service, replay, cryptographic misuse
---
STATE, CONCURRENCY AND LIMITS. On this surface:

1. Time of check to time of use: is anything checked and then used after an await, a lock release or a second read?
2. Multi-step writes: can a crash or a concurrent request leave partial state that a later request trusts (orphaned records, half-applied configuration)?
3. Resource limits: which inputs control memory, CPU, disk or connection use (body size, list lengths, nesting depth, decompression ratio, page size, regular expressions)? Is each one bounded?
4. Authentication freshness: replay windows, token expiry, nonce reuse, revocation that does not take effect.
5. Cryptography: nonce or IV reuse, non-constant-time comparison of secrets, weak randomness, keys derived or stored insecurely.
