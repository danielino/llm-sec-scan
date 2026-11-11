---
id: parser-differential
title: Parser differential
scope: repo
bug_classes: authorization bypass, request smuggling, validation bypass
---
PARSER DIFFERENTIAL. Start from the parser pairs in the system model and add any you find: places where two components independently interpret the same input (a URI before and after rewriting or normalization, query parsing in an auth layer versus a handler, substring versus exact versus prefix matching, percent-decoding, case folding, duplicate keys, header folding, a proxy versus its backend, a client versus a server).

For each pair:

1. Read both implementations.
2. Construct concrete inputs that the two interpret DIFFERENTLY.
3. Decide whether the divergence crosses a security decision (authorization, validation, routing, rate limiting, audit) and what an attacker gains.

Report only divergences with a security consequence.
