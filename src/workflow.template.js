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
const BUNDLE = /*@@BUNDLE@@*/ null
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
