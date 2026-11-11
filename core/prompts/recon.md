Build a security-oriented model of the repository at {{repo}}.

1. What the system does, in a few sentences.
2. Actors and their privilege levels (for example anonymous, low-privilege authenticated user, administrator, internal peer or service, operator with host access).
3. Assets worth protecting (data, credentials, configuration, availability).
4. Attack surfaces, grouped coherently: a surface is a set of related entry points (routes, commands, consumers, jobs) that share a code path. List at most {{max_surfaces}}. For each surface give:
   - the ORDERED layer chain a request crosses, outermost first, with file:line (listeners, middleware or layers, routing, handler, storage or other sinks);
   - the decision points along the chain (authentication, authorization, validation, rewriting or normalization);
   - a risk score from 1 to 10 for how much security-relevant logic it holds.
5. Parser pairs: places where two components independently interpret the same input (for example a URI before and after rewriting, query parsing in an auth layer versus a handler, path normalization, header parsing, a proxy versus its backend, client-side versus server-side validation).

Enumerate entry points and middleware with deterministic search (grep, glob, router definitions); do not guess. Prefer precision over breadth.

{{rules}}
