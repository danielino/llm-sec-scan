---
id: secondary-resources
title: Secondary resources and confused deputy
scope: surface
bug_classes: IDOR, confused deputy, information disclosure
---
SECONDARY RESOURCES. For each handler on this surface:

1. List EVERY resource it reads or writes: the one named by the path, and any named by headers (for example a copy source), body fields, IDs, lists of keys, tokens or references to stored objects.
2. For each resource not covered by the authorization decision taken before the handler, is there an explicit per-resource authorization check in the handler, for the right action and honouring deny rules?
3. Does the handler act with more privilege than the caller (a service credential, a server-side signing key, a stored credential referenced by name)?
4. Are bound identifiers (an upload ID, a session, a job) checked against the resource in the path, or can one be used against another resource?
5. Do error messages or timing distinguish states the caller is not entitled to know (exists versus missing, which part is missing)?
