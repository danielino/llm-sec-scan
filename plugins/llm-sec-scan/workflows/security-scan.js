export const meta = {
  name: 'security-scan',
  description: 'LLM security scan of N repositories: recon, surface x lens fan-out, root-cause dedup, multi-vote adversarial verification, variant hunt',
  whenToUse: 'Security audit of one or more local repositories. args: {repos: [absolute paths], maxSurfaces?, maxClusters?, verifyVotes?, findModel?, lenses?}',
  phases: [
    { title: 'Recon', detail: 'system and threat model per repository' },
    { title: 'Scan', detail: 'surface x lens finders and repository-wide lenses' },
    { title: 'Dedup', detail: 'cluster findings by root cause' },
    { title: 'Verify', detail: 'independent verifier votes per cluster' },
    { title: 'Variants', detail: 'sibling hunt from surviving findings' },
  ],
}

// BUNDLE is injected by scripts/build.py from core/ (lenses, prompts, stances, schemas).
// The copy under plugins/ is generated: edit src/ and core/, then rebuild.
const BUNDLE = {
 "LENSES": [
  {
   "body": "AUTHORIZATION CONSISTENCY. For each operation reachable through this surface, answer:\n\n1. Which action and which resource does the authorization layer compute, and from WHICH representation of the request (original or rewritten URI, raw or decoded path, raw query string or parsed parameters, headers, body)?\n2. Which operation does the handler actually execute, on which resource, and from which representation?\n3. Can any input make (1) and (2) diverge? Try the HTTP method, the path shape (empty, trailing slash, extra segments), percent-encoding, case, the Host header or other routing headers, query parameters that are substrings or prefixes of others, duplicate or empty parameters.\n4. Is any dangerous sub-operation authorized as a weaker or unrelated permission (a coarse mapping), or does the check ignore part of the request, such as the method?\n5. Are explicit deny rules evaluated on the same resource string the handler uses?",
   "bug_classes": [
    "authorization bypass",
    "privilege escalation"
   ],
   "id": "authz-consistency",
   "scope": "surface",
   "title": "Authorization consistency"
  },
  {
   "body": "INPUT TO SINK. Trace untrusted input on this surface (path, query, headers, body, file names, object keys, configuration accepted through the API) to dangerous sinks:\n\n1. Filesystem paths: traversal, absolute paths, symlinks, reserved names.\n2. Query languages and interpreters: SQL, shell or process arguments, templates, regular expressions built from input.\n3. Parsers and deserializers: XML entities, YAML, archives (zip slip, decompression bombs), formats with type tags.\n4. Outbound requests: URLs or hosts taken from input or from stored configuration (SSRF, exfiltration to attacker endpoints).\n5. Rendering: values later shown in a web UI or another client without escaping (stored XSS), content served inline with an attacker-chosen content type.\n6. Logs, errors and API responses that echo secrets (tokens, keys, credentials held in stored configuration).\n\nFor each path, name the neutralization step, or state that there is none.",
   "bug_classes": [
    "injection",
    "path traversal",
    "SSRF",
    "XSS",
    "deserialization",
    "secret leakage"
   ],
   "id": "input-to-sink",
   "scope": "surface",
   "title": "Untrusted input to dangerous sinks"
  },
  {
   "body": "PARSER DIFFERENTIAL. Start from the parser pairs in the system model and add any you find: places where two components independently interpret the same input (a URI before and after rewriting or normalization, query parsing in an auth layer versus a handler, substring versus exact versus prefix matching, percent-decoding, case folding, duplicate keys, header folding, a proxy versus its backend, a client versus a server).\n\nFor each pair:\n\n1. Read both implementations.\n2. Construct concrete inputs that the two interpret DIFFERENTLY.\n3. Decide whether the divergence crosses a security decision (authorization, validation, routing, rate limiting, audit) and what an attacker gains.\n\nReport only divergences with a security consequence.",
   "bug_classes": [
    "authorization bypass",
    "request smuggling",
    "validation bypass"
   ],
   "id": "parser-differential",
   "scope": "repo",
   "title": "Parser differential"
  },
  {
   "body": "PRIVILEGE MODEL. Enumerate the permissions, roles or scopes the system defines and, for each non-administrative one, answer:\n\n1. Which operations does it allow, according to the code rather than the documentation?\n2. Can a holder use those operations to obtain more privilege, directly or in a chain: grant permissions to themselves or to a group they can join, mint or reset credentials for another principal (administrators included), remove deny rules, change configuration that other checks trust?\n3. Are scoping rules enforced (own resources only, own credentials only), or does the permission act globally?\n4. Do internal or peer interfaces accept operations from callers that hold a weaker secret than those operations warrant?\n\nAlso list permissions that are defined but never checked, when a reachable operation needs them.",
   "bug_classes": [
    "privilege escalation",
    "broken access control"
   ],
   "id": "privilege-escalation",
   "scope": "repo",
   "title": "Privilege model escalation"
  },
  {
   "body": "SECONDARY RESOURCES. For each handler on this surface:\n\n1. List EVERY resource it reads or writes: the one named by the path, and any named by headers (for example a copy source), body fields, IDs, lists of keys, tokens or references to stored objects.\n2. For each resource not covered by the authorization decision taken before the handler, is there an explicit per-resource authorization check in the handler, for the right action and honouring deny rules?\n3. Does the handler act with more privilege than the caller (a service credential, a server-side signing key, a stored credential referenced by name)?\n4. Are bound identifiers (an upload ID, a session, a job) checked against the resource in the path, or can one be used against another resource?\n5. Do error messages or timing distinguish states the caller is not entitled to know (exists versus missing, which part is missing)?",
   "bug_classes": [
    "IDOR",
    "confused deputy",
    "information disclosure"
   ],
   "id": "secondary-resources",
   "scope": "surface",
   "title": "Secondary resources and confused deputy"
  },
  {
   "body": "STATE, CONCURRENCY AND LIMITS. On this surface:\n\n1. Time of check to time of use: is anything checked and then used after an await, a lock release or a second read?\n2. Multi-step writes: can a crash or a concurrent request leave partial state that a later request trusts (orphaned records, half-applied configuration)?\n3. Resource limits: which inputs control memory, CPU, disk or connection use (body size, list lengths, nesting depth, decompression ratio, page size, regular expressions)? Is each one bounded?\n4. Authentication freshness: replay windows, token expiry, nonce reuse, revocation that does not take effect.\n5. Cryptography: nonce or IV reuse, non-constant-time comparison of secrets, weak randomness, keys derived or stored insecurely.",
   "bug_classes": [
    "race condition",
    "denial of service",
    "replay",
    "cryptographic misuse"
   ],
   "id": "state-and-limits",
   "scope": "surface",
   "title": "State, concurrency and limits"
  }
 ],
 "PROMPTS": {
  "dedup": "The security findings below were produced independently by several analysts, so the same underlying bug often appears more than once with different wording or nearby line numbers.\n\nGroup them into clusters that share ONE root cause: the same defect that one code fix would remove.\n\n- Two findings belong together only if fixing one necessarily fixes the other.\n- Different exploitation paths of the same missing check belong to the same cluster.\n- The same bug class in two independent places that need separate fixes belongs to DIFFERENT clusters.\n- Every index must appear in exactly one cluster.\n\nFindings (`i` is the index to use):\n{{findings}}",
  "recon": "Build a security-oriented model of the repository at {{repo}}.\n\n1. What the system does, in a few sentences.\n2. Actors and their privilege levels (for example anonymous, low-privilege authenticated user, administrator, internal peer or service, operator with host access).\n3. Assets worth protecting (data, credentials, configuration, availability).\n4. Attack surfaces, grouped coherently: a surface is a set of related entry points (routes, commands, consumers, jobs) that share a code path. List at most {{max_surfaces}}. For each surface give:\n   - the ORDERED layer chain a request crosses, outermost first, with file:line (listeners, middleware or layers, routing, handler, storage or other sinks);\n   - the decision points along the chain (authentication, authorization, validation, rewriting or normalization);\n   - a risk score from 1 to 10 for how much security-relevant logic it holds.\n5. Parser pairs: places where two components independently interpret the same input (for example a URI before and after rewriting, query parsing in an auth layer versus a handler, path normalization, header parsing, a proxy versus its backend, client-side versus server-side validation).\n\nEnumerate entry points and middleware with deterministic search (grep, glob, router definitions); do not guess. Prefer precision over breadth.\n\n{{rules}}",
  "repo-lens": "{{context}}\n\nSYSTEM MODEL (from reconnaissance; it may be incomplete, extend it where you find more):\n{{system_model}}\n\nLENS (repository-wide):\n{{lens}}\n\nApply the lens across the whole repository. Report only findings that have concrete code evidence and a realistic attacker with the MINIMUM privileges and configuration required. For each finding give a concrete exploit (requests or steps) and its impact.\n\n{{rules}}",
  "rules": "Rules:\n- Read-only analysis. Do not modify files, build, install dependencies, start servers or make network requests.\n- Work only inside the repository root given above.\n- Base every claim on code you actually read. Cite paths relative to the repository root, with line numbers.\n- Ignore existing vulnerability reports, audits or pentest write-ups you come across; reason from the code only.\n- An empty result is a valid answer. Do not pad.",
  "surface-lens": "{{context}}\n\n{{surface}}\n\nLENS:\n{{lens}}\n\nAnswer the lens questions for this surface by reading the code along the full layer chain, not just the handler. Report only findings that have concrete code evidence and a realistic attacker with the MINIMUM privileges and configuration required. For each finding give a concrete exploit (requests or steps) and its impact.\n\n{{rules}}",
  "variants": "{{context}}\n\nThese findings survived verification:\n{{confirmed}}\n\nVARIANT HUNT. For each root cause above, search the WHOLE repository for further instances of the same defect: the same code pattern elsewhere (grep for it), sibling handlers or commands, parallel code paths that perform the same operation, other components that parse the same input, other operations that read or write secondary resources. Report only NEW instances with code evidence. These are already known and must not be reported again:\n{{known}}\n\n{{rules}}",
  "verify": "You are an independent security verifier. Your stance:\n{{stance}}\n\nRead the actual code and decide:\n- CONFIRMED: you traced the full path from the attacker's input to the impact in code and found nothing that blocks it.\n- PLAUSIBLE: the path is credible but depends on something you could not verify (configuration, runtime behaviour, code outside the repository).\n- REFUTED: something blocks it (an upstream check, an unreachable route, a configuration that prevents it), or the finding misreads the code.\nWhen torn between two verdicts, choose the more skeptical one.\n\nRe-assess the severity for the stated attacker (critical, high, medium, low). Provide a concrete proof of concept (requests or commands) and a regression test that would fail today and pass after a fix.\n\n{{context}}\n\nFINDING:\n{{finding}}\n\n{{rules}}"
 },
 "SCHEMAS": {
  "clusters": {
   "properties": {
    "clusters": {
     "items": {
      "properties": {
       "members": {
        "description": "indices of the findings in this cluster",
        "items": {
         "type": "integer"
        },
        "type": "array"
       },
       "root_cause": {
        "type": "string"
       }
      },
      "required": [
       "members",
       "root_cause"
      ],
      "type": "object"
     },
     "type": "array"
    }
   },
   "required": [
    "clusters"
   ],
   "type": "object"
  },
  "findings": {
   "properties": {
    "findings": {
     "items": {
      "properties": {
       "attacker": {
        "description": "actor and minimum privileges or configuration required",
        "type": "string"
       },
       "bug_class": {
        "type": "string"
       },
       "confidence": {
        "description": "from 0 to 1",
        "type": "number"
       },
       "exploit": {
        "description": "concrete requests or steps",
        "type": "string"
       },
       "file": {
        "description": "path relative to the repository root",
        "type": "string"
       },
       "impact": {
        "type": "string"
       },
       "line": {
        "type": "number"
       },
       "other_locations": {
        "description": "file:line",
        "items": {
         "type": "string"
        },
        "type": "array"
       },
       "root_cause": {
        "type": "string"
       },
       "severity": {
        "enum": [
         "critical",
         "high",
         "medium",
         "low"
        ],
        "type": "string"
       },
       "title": {
        "type": "string"
       }
      },
      "required": [
       "title",
       "bug_class",
       "severity",
       "file",
       "line",
       "attacker",
       "root_cause",
       "exploit",
       "impact",
       "confidence"
      ],
      "type": "object"
     },
     "type": "array"
    }
   },
   "required": [
    "findings"
   ],
   "type": "object"
  },
  "recon": {
   "properties": {
    "actors": {
     "items": {
      "properties": {
       "name": {
        "type": "string"
       },
       "privileges": {
        "type": "string"
       }
      },
      "required": [
       "name",
       "privileges"
      ],
      "type": "object"
     },
     "type": "array"
    },
    "assets": {
     "items": {
      "type": "string"
     },
     "type": "array"
    },
    "parser_pairs": {
     "description": "pairs of components that independently interpret the same input",
     "items": {
      "properties": {
       "component_a": {
        "type": "string"
       },
       "component_b": {
        "type": "string"
       },
       "input": {
        "type": "string"
       }
      },
      "required": [
       "input",
       "component_a",
       "component_b"
      ],
      "type": "object"
     },
     "type": "array"
    },
    "summary": {
     "type": "string"
    },
    "surfaces": {
     "items": {
      "properties": {
       "decision_points": {
        "items": {
         "type": "string"
        },
        "type": "array"
       },
       "description": {
        "type": "string"
       },
       "entry_files": {
        "items": {
         "type": "string"
        },
        "type": "array"
       },
       "id": {
        "description": "short kebab-case identifier",
        "type": "string"
       },
       "layer_chain": {
        "description": "ordered layers a request crosses, outermost first, with file:line",
        "items": {
         "type": "string"
        },
        "type": "array"
       },
       "name": {
        "type": "string"
       },
       "risk": {
        "description": "security relevance from 1 to 10",
        "type": "number"
       }
      },
      "required": [
       "id",
       "name",
       "description",
       "entry_files",
       "layer_chain",
       "decision_points",
       "risk"
      ],
      "type": "object"
     },
     "type": "array"
    }
   },
   "required": [
    "summary",
    "actors",
    "assets",
    "surfaces",
    "parser_pairs"
   ],
   "type": "object"
  },
  "verdict": {
   "properties": {
    "poc": {
     "type": "string"
    },
    "reasoning": {
     "type": "string"
    },
    "regression_test": {
     "type": "string"
    },
    "severity": {
     "enum": [
      "critical",
      "high",
      "medium",
      "low"
     ],
     "type": "string"
    },
    "verdict": {
     "enum": [
      "CONFIRMED",
      "PLAUSIBLE",
      "REFUTED"
     ],
     "type": "string"
    }
   },
   "required": [
    "verdict",
    "severity",
    "reasoning",
    "poc",
    "regression_test"
   ],
   "type": "object"
  }
 },
 "STANCES": [
  {
   "id": "refute",
   "text": "Skeptic. Your goal is to REFUTE the finding. Look for an upstream check or layer that blocks it, a route or code path that makes it unreachable, a default configuration that prevents it, or a misreading of the code. Confirm it only if you fail after genuine effort."
  },
  {
   "id": "reachability",
   "text": "Path tracer. Ignore the finding's own narrative and independently trace the request from the outermost entry point (listener, middleware, router) to the vulnerable code, recording every check it passes. Confirm only if an attacker with the stated privileges can actually reach the vulnerable code with the required input."
  },
  {
   "id": "impact",
   "text": "Impact assessor. Assume the code path is reachable and judge whether the claimed impact actually follows: what exactly does the attacker gain beyond the privileges they already hold? Refute findings whose impact is behaviour already permitted to that attacker, or that the documentation describes as intended behind an explicit trust boundary."
  }
 ],
 "VERSION": "0.1.0"
}
const { VERSION, LENSES, PROMPTS, STANCES, SCHEMAS } = BUNDLE

const A = typeof args === 'string' ? { repos: [args] } : (args || {})
const REPOS = A.repos || []
const MAX_SURFACES = A.maxSurfaces ?? 8
const MAX_CLUSTERS = A.maxClusters ?? 30
const VOTES = Math.min(Math.max(A.verifyVotes ?? 2, 1), STANCES.length)
const FIND_MODEL = A.findModel || 'sonnet'
const LENS_FILTER = Array.isArray(A.lenses) && A.lenses.length ? new Set(A.lenses) : null

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const VERDICT_ORDER = { CONFIRMED: 0, PLAUSIBLE: 1, REFUTED: 2 }
const sevRank = s => { const i = SEVERITIES.indexOf(s); return i < 0 ? SEVERITIES.length : i }
const bySeverity = (a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.confidence ?? 0) - (a.confidence ?? 0)

const lenses = LENSES.filter(l => !LENS_FILTER || LENS_FILTER.has(l.id))
const surfaceLenses = lenses.filter(l => l.scope === 'surface')
const repoLenses = lenses.filter(l => l.scope === 'repo')

// Replaces {{name}} placeholders; a missing variable is a bug in this script.
function fill(template, vars) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, name) => {
    if (!(name in vars)) throw new Error(`missing prompt variable: ${name}`)
    return String(vars[name])
  })
}

const describeContext = (repo, recon) => [
  `Repository root: ${repo}`,
  `System summary: ${recon.summary}`,
  `Actors: ${recon.actors.map(a => `${a.name} (${a.privileges})`).join('; ')}`,
  `Assets: ${recon.assets.join('; ')}`,
].join('\n')

const describeSurface = s => [
  `SURFACE: ${s.name}. ${s.description}`,
  `Entry files: ${s.entry_files.join(', ')}`,
  `Layer chain: ${s.layer_chain.join(' -> ')}`,
  `Decision points: ${s.decision_points.join('; ') || 'none identified'}`,
].join('\n')

// Coarse identity, used when semantic dedup is unavailable and to drop variant-hunt repeats.
const locationKey = f => `${String(f.bug_class).toLowerCase().replace(/[^a-z]/g, '')}|${f.file}|${Math.floor((f.line || 0) / 15)}`

// Middle element of the sorted severities; for an even count, the less severe of the two.
function lowerMedian(severities) {
  const sorted = [...severities].sort((a, b) => sevRank(a) - sevRank(b))
  return sorted[Math.floor(sorted.length / 2)]
}

function aggregate(votes) {
  const valid = votes.filter(Boolean)
  if (!valid.length) return null
  const refuted = valid.filter(v => v.verdict === 'REFUTED').length
  const confirmed = valid.filter(v => v.verdict === 'CONFIRMED').length
  const verdict = refuted * 2 > valid.length ? 'REFUTED' : confirmed * 2 > valid.length ? 'CONFIRMED' : 'PLAUSIBLE'
  const standing = valid.filter(v => v.verdict !== 'REFUTED')
  const severity = lowerMedian((standing.length ? standing : valid).map(v => v.severity))
  return { verdict, severity, votes: valid }
}

function mergeCluster(members) {
  const best = [...members].sort(bySeverity)[0]
  const locations = new Set(best.other_locations || [])
  for (const m of members) {
    if (m !== best) locations.add(`${m.file}:${m.line}`)
    for (const l of m.other_locations || []) locations.add(l)
  }
  locations.delete(`${best.file}:${best.line}`)
  return { ...best, other_locations: [...locations], members: members.length, lenses: [...new Set(members.map(m => m.lens))] }
}

function checkClusters(clusters, count) {
  if (!Array.isArray(clusters)) return null
  const seen = new Set()
  for (const c of clusters) for (const i of c.members) {
    if (!Number.isInteger(i) || i < 0 || i >= count || seen.has(i)) return null
    seen.add(i)
  }
  const groups = clusters.filter(c => c.members.length).map(c => c.members)
  for (let i = 0; i < count; i++) if (!seen.has(i)) groups.push([i])  // forgotten indices stay as singletons
  return groups
}

async function dedup(raw, tag) {
  if (raw.length < 2) return raw.map(f => mergeCluster([f]))
  const compact = raw.map((f, i) => ({ i, title: f.title, bug_class: f.bug_class, location: `${f.file}:${f.line}`, root_cause: String(f.root_cause).slice(0, 400) }))
  const res = await agent(fill(PROMPTS.dedup, { findings: JSON.stringify(compact, null, 1) }),
    { label: `dedup:${tag}`, phase: 'Dedup', schema: SCHEMAS.clusters, model: FIND_MODEL })
  let groups = res && checkClusters(res.clusters, raw.length)
  if (!groups) {
    log(`${tag}: semantic dedup failed or returned inconsistent indices; falling back to class/file/line keys`)
    const byKey = new Map()
    raw.forEach((f, i) => byKey.set(locationKey(f), [...(byKey.get(locationKey(f)) || []), i]))
    groups = [...byKey.values()]
  }
  return groups.map(g => mergeCluster(g.map(i => raw[i]))).sort(bySeverity)
}

async function verify(repo, recon, finding, tag, label) {
  const votes = await parallel(STANCES.slice(0, VOTES).map(stance => () =>
    agent(fill(PROMPTS.verify, {
      stance: stance.text,
      context: describeContext(repo, recon),
      finding: JSON.stringify(finding, null, 2),
      rules: PROMPTS.rules,
    }), { label: `verify:${tag}:${stance.id}:${label}`, phase: 'Verify', schema: SCHEMAS.verdict, effort: 'high' })
      .then(v => v && { stance: stance.id, ...v })))
  const verdict = aggregate(votes)
  return verdict ? { ...finding, verdict } : null
}

async function scanRepo(repo) {
  const tag = repo.split('/').filter(Boolean).pop()

  const recon = await agent(fill(PROMPTS.recon, { repo, max_surfaces: MAX_SURFACES * 2, rules: PROMPTS.rules }),
    { label: `recon:${tag}`, phase: 'Recon', schema: SCHEMAS.recon })
  if (!recon) return { repo, error: 'recon failed' }
  const context = describeContext(repo, recon)
  const surfaces = [...recon.surfaces].sort((a, b) => b.risk - a.risk)
  const scanned = surfaces.slice(0, MAX_SURFACES)
  const notScanned = surfaces.slice(MAX_SURFACES).map(s => s.name)
  if (notScanned.length) log(`${tag}: scanning ${scanned.length}/${surfaces.length} surfaces by risk; not scanned: ${notScanned.join(', ')}`)

  const tagged = (lens, surface) => r => r && r.findings.map(f => ({ ...f, lens, surface }))
  const tasks = []
  for (const s of scanned) for (const l of surfaceLenses) tasks.push(() =>
    agent(fill(PROMPTS['surface-lens'], { context, surface: describeSurface(s), lens: l.body, rules: PROMPTS.rules }),
      { label: `${tag}:${s.id}:${l.id}`, phase: 'Scan', schema: SCHEMAS.findings, model: FIND_MODEL })
      .then(tagged(l.id, s.name)))
  const systemModel = JSON.stringify({ surfaces: recon.surfaces, parser_pairs: recon.parser_pairs }, null, 1)
  for (const l of repoLenses) tasks.push(() =>
    agent(fill(PROMPTS['repo-lens'], { context, system_model: systemModel, lens: l.body, rules: PROMPTS.rules }),
      { label: `${tag}:${l.id}`, phase: 'Scan', schema: SCHEMAS.findings })
      .then(tagged(l.id, '(repository-wide)')))
  const raw = (await parallel(tasks)).filter(Boolean).flat()

  const clusters = await dedup(raw, tag)
  const eligible = clusters.filter(c => sevRank(c.severity) <= sevRank('medium'))
  const toVerify = eligible.slice(0, MAX_CLUSTERS)
  const unverified = [...eligible.slice(MAX_CLUSTERS), ...clusters.filter(c => sevRank(c.severity) > sevRank('medium'))]
  log(`${tag}: ${raw.length} raw findings -> ${clusters.length} clusters -> verifying ${toVerify.length} with ${VOTES} vote(s); ${unverified.length} left unverified (low severity or over maxClusters)`)

  const verified = (await parallel(toVerify.map((f, i) => () => verify(repo, recon, f, tag, i)))).filter(Boolean)
  const kept = verified.filter(f => f.verdict.verdict !== 'REFUTED')

  let variants = []
  if (kept.length) {
    const hunt = await agent(fill(PROMPTS.variants, {
      context,
      confirmed: kept.map((f, i) => `${i + 1}. [${f.verdict.verdict}] ${f.title} @ ${f.file}:${f.line}\n   Root cause: ${f.root_cause}`).join('\n'),
      known: clusters.map(c => `- ${c.title} @ ${c.file}:${c.line}`).join('\n'),
      rules: PROMPTS.rules,
    }), { label: `variants:${tag}`, phase: 'Variants', schema: SCHEMAS.findings })
    const known = new Set(clusters.map(locationKey))
    const fresh = (hunt?.findings || []).filter(f => !known.has(locationKey(f)))
      .map(f => ({ ...f, lens: 'variant-hunt', surface: '(variant hunt)', members: 1, other_locations: f.other_locations || [] }))
    const capped = fresh.slice(0, MAX_CLUSTERS)
    if (fresh.length > capped.length) log(`${tag}: variant hunt returned ${fresh.length} new instances; verifying the first ${capped.length}`)
    variants = (await parallel(capped.map((f, i) => () => verify(repo, recon, f, tag, `v${i}`)))).filter(Boolean)
      .filter(f => f.verdict.verdict !== 'REFUTED').map(f => ({ ...f, from_variant_hunt: true }))
  }

  const findings = [...kept, ...variants].sort((a, b) =>
    sevRank(a.verdict.severity) - sevRank(b.verdict.severity) || VERDICT_ORDER[a.verdict.verdict] - VERDICT_ORDER[b.verdict.verdict])
  const refuted = verified.filter(f => f.verdict.verdict === 'REFUTED')
  return {
    repo,
    summary: recon.summary,
    coverage: { surfaces_total: surfaces.length, surfaces_scanned: scanned.map(s => s.name), surfaces_not_scanned: notScanned, lenses: lenses.map(l => l.id), verify_votes: VOTES },
    stats: { raw: raw.length, clusters: clusters.length, verified: verified.length, refuted: refuted.length, unverified: unverified.length, variants: variants.length, final: findings.length },
    findings,
    refuted: refuted.map(f => ({ title: f.title, file: f.file, line: f.line, votes: f.verdict.votes.map(v => ({ stance: v.stance, verdict: v.verdict, reasoning: v.reasoning })) })),
    unverified: unverified.map(f => ({ title: f.title, severity: f.severity, file: f.file, line: f.line, lens: f.lens })),
  }
}

if (!REPOS.length) throw new Error('args.repos must list absolute repository paths')
if (!lenses.length) throw new Error(`no lens matches args.lenses: ${[...LENS_FILTER].join(', ')}`)
const results = await pipeline(REPOS, repo => scanRepo(repo))
return { version: VERSION, results }
