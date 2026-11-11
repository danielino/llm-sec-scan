---
id: privilege-escalation
title: Privilege model escalation
scope: repo
bug_classes: privilege escalation, broken access control
---
PRIVILEGE MODEL. Enumerate the permissions, roles or scopes the system defines and, for each non-administrative one, answer:

1. Which operations does it allow, according to the code rather than the documentation?
2. Can a holder use those operations to obtain more privilege, directly or in a chain: grant permissions to themselves or to a group they can join, mint or reset credentials for another principal (administrators included), remove deny rules, change configuration that other checks trust?
3. Are scoping rules enforced (own resources only, own credentials only), or does the permission act globally?
4. Do internal or peer interfaces accept operations from callers that hold a weaker secret than those operations warrant?

Also list permissions that are defined but never checked, when a reachable operation needs them.
