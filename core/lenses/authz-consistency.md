---
id: authz-consistency
title: Authorization consistency
scope: surface
bug_classes: authorization bypass, privilege escalation
---
AUTHORIZATION CONSISTENCY. For each operation reachable through this surface, answer:

1. Which action and which resource does the authorization layer compute, and from WHICH representation of the request (original or rewritten URI, raw or decoded path, raw query string or parsed parameters, headers, body)?
2. Which operation does the handler actually execute, on which resource, and from which representation?
3. Can any input make (1) and (2) diverge? Try the HTTP method, the path shape (empty, trailing slash, extra segments), percent-encoding, case, the Host header or other routing headers, query parameters that are substrings or prefixes of others, duplicate or empty parameters.
4. Is any dangerous sub-operation authorized as a weaker or unrelated permission (a coarse mapping), or does the check ignore part of the request, such as the method?
5. Are explicit deny rules evaluated on the same resource string the handler uses?
