---
id: input-to-sink
title: Untrusted input to dangerous sinks
scope: surface
bug_classes: injection, path traversal, SSRF, XSS, deserialization, secret leakage
---
INPUT TO SINK. Trace untrusted input on this surface (path, query, headers, body, file names, object keys, configuration accepted through the API) to dangerous sinks:

1. Filesystem paths: traversal, absolute paths, symlinks, reserved names.
2. Query languages and interpreters: SQL, shell or process arguments, templates, regular expressions built from input.
3. Parsers and deserializers: XML entities, YAML, archives (zip slip, decompression bombs), formats with type tags.
4. Outbound requests: URLs or hosts taken from input or from stored configuration (SSRF, exfiltration to attacker endpoints).
5. Rendering: values later shown in a web UI or another client without escaping (stored XSS), content served inline with an attacker-chosen content type.
6. Logs, errors and API responses that echo secrets (tokens, keys, credentials held in stored configuration).

For each path, name the neutralization step, or state that there is none.
