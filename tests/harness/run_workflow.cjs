// Runs the generated workflow with mocked agent(), parallel() and pipeline() for the smoke tests.
// Usage: node run_workflow.cjs <workflow.js> <scenario>; prints {result, logs, calls, errors} as JSON.
'use strict'
const fs = require('fs')

const [workflowPath, scenario] = process.argv.slice(2)
const source = fs.readFileSync(workflowPath, 'utf8').replace('export const meta', 'const meta')

const RECON = {
  summary: 'Toy service.',
  actors: [{ name: 'user', privileges: 'authenticated, low privilege' }],
  assets: ['objects'],
  surfaces: [
    { id: 'api', name: 'Public API', description: 'HTTP API', entry_files: ['src/api.rs'], layer_chain: ['src/auth.rs:1', 'src/api.rs:1'], decision_points: ['auth'], risk: 9 },
    { id: 'cli', name: 'CLI', description: 'Local CLI', entry_files: ['src/cli.rs'], layer_chain: ['src/cli.rs:1'], decision_points: [], risk: 2 },
  ],
  parser_pairs: [],
}

function finding(title, severity, line, extra = {}) {
  return {
    title, bug_class: 'authorization bypass', severity, file: 'src/auth.rs', line,
    attacker: 'user', root_cause: `root cause of ${title}`, exploit: 'GET /x', impact: 'read data', confidence: 0.8,
    ...extra,
  }
}

// Scan output per lens id; every other lens returns no findings.
const SCAN = {
  'authz-consistency': [finding('Auth uses original URI', 'high', 10)],
  'state-and-limits': [finding('Unbounded list', 'low', 200, { bug_class: 'denial of service', file: 'src/list.rs' })],
  'parser-differential': [finding('Auth and handler parse URI differently', 'medium', 12)],
}

const verdict = (v, severity) => ({ verdict: v, severity, reasoning: `${v} because`, poc: 'curl x', regression_test: 'test x' })

function respond(label) {
  if (label.startsWith('recon:')) return RECON
  if (label.startsWith('dedup:')) {
    if (scenario === 'dedup-invalid') return { clusters: [{ members: [0, 7], root_cause: 'bad index' }] }
    return { clusters: [{ members: [0, 2], root_cause: 'uri split' }, { members: [1], root_cause: 'no limit' }] }
  }
  if (label.startsWith('variants:')) return { findings: [finding('Variant elsewhere', 'high', 90, { file: 'src/other.rs' })] }
  if (label.startsWith('verify:')) {
    if (label.endsWith(':v0')) return verdict('REFUTED', 'high')
    if (scenario === 'split') return label.includes(':refute:') ? verdict('REFUTED', 'high') : verdict('CONFIRMED', 'critical')
    return verdict('CONFIRMED', 'high')
  }
  const lens = Object.keys(SCAN).find(id => label.endsWith(`:${id}`))
  return { findings: lens ? SCAN[lens] : [] }
}

const logs = []
const calls = []
const errors = []
const capture = error => { errors.push(String((error && error.stack) || error)); return null }

const agent = async (prompt, opts) => {
  calls.push(opts.label)
  if (/\{\{\w+\}\}/.test(prompt)) throw new Error(`unfilled placeholder in ${opts.label}`)
  return respond(opts.label)
}
const parallel = thunks => Promise.all(thunks.map(t => Promise.resolve().then(t).catch(capture)))
const pipeline = (items, ...stages) => Promise.all(items.map(async (item, index) => {
  let value = item
  try {
    for (const stage of stages) value = await stage(value, item, index)
  } catch (error) {
    return capture(error)
  }
  return value
}))

const args = { repos: ['/work/toy-repo'], maxSurfaces: 1, verifyVotes: 2 }
const run = new Function('args', 'agent', 'parallel', 'pipeline', 'log', 'phase', 'budget',
  `return (async () => {\n${source}\n})()`)
run(args, agent, parallel, pipeline, message => logs.push(message), () => {}, { total: null })
  .then(result => console.log(JSON.stringify({ result, logs, calls, errors })))
  .catch(error => {
    console.log(JSON.stringify({ fatal: String((error && error.stack) || error), logs, calls, errors }))
    process.exitCode = 1
  })
