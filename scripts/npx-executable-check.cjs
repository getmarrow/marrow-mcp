#!/usr/bin/env node
// Release check: `npx @getmarrow/mcp <args>` must resolve an executable.
//
// npx picks the executable named after the package (`mcp` for @getmarrow/mcp)
// or, failing that, the only entry in `bin`. A package with several `bin`
// entries and none named `mcp` fails with "could not determine executable to
// run" (broken for every published `npx @getmarrow/mcp setup` command from
// 3.9.57 until this check existed).
//
// Usage: node scripts/npx-executable-check.cjs [path-to-tarball]
//   Static check of package.json, then (real proof) runs both npx forms against
//   a packed tarball using a throwaway HOME and an empty npm cache. Read-only:
//   only `--help` is ever executed. Set MARROW_NPX_CHECK_STATIC_ONLY=1 to skip
//   the npx run (for offline use).

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const root = path.resolve(__dirname, '..')
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
const failures = []

function check(label, condition) {
  if (!condition) failures.push(label)
}

function staticCheck(manifest) {
  const bin = typeof manifest.bin === 'string' ? { [manifest.name]: manifest.bin } : manifest.bin || {}
  const names = Object.keys(bin)
  const unscoped = manifest.name.replace(/^@[^/]+\//, '')
  check('package must declare at least one bin entry', names.length > 0)
  check(
    `npx cannot choose between bin entries [${names.join(', ')}]: keep one entry or add one named "${unscoped}"`,
    names.length === 1 || names.includes(unscoped),
  )
  check('bin "marrow-mcp" must exist and point at dist/cli.js', bin['marrow-mcp'] === 'dist/cli.js')
  if (names.includes(unscoped)) check(`bin "${unscoped}" must point at the same file as "marrow-mcp"`, bin[unscoped] === bin['marrow-mcp'])
}

function run(command, args, options) {
  return spawnSync(command, args, { encoding: 'utf8', timeout: 180000, ...options })
}

staticCheck(pkg)

if (process.env.MARROW_NPX_CHECK_STATIC_ONLY !== '1') {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-npx-check-'))
  try {
    let tarball = process.argv[2] ? path.resolve(process.argv[2]) : ''
    if (!tarball) {
      const packDir = path.join(work, 'pack')
      fs.mkdirSync(packDir)
      const packed = run('npm', ['pack', '--silent', '--ignore-scripts', '--pack-destination', packDir], {
        cwd: root,
        env: { ...process.env, HOME: path.join(work, 'home'), npm_config_cache: path.join(work, 'pack-cache') },
      })
      if (packed.status !== 0) {
        failures.push(`npm pack failed (exit ${packed.status})`)
      } else {
        tarball = path.join(packDir, packed.stdout.trim().split('\n').pop())
      }
    }
    if (tarball) {
      // Both probes are read-only and run with no Marrow credentials in the
      // environment. `--help` (the form from the bug report) is not a special
      // flag in this CLI: it starts the stdio server, which with no key prints
      // its usage text and exits 1, so success means that usage text appeared.
      // `loop-guard-self-test` is an offline self-test that exits 0 with pass:true.
      const forms = [
        // npx executes a bare path to an existing file instead of installing it, so
        // the spec needs a file: prefix to behave like a registry spec.
        ['npx -y file:<tarball>', (extra) => ['-y', `file:${tarball}`, ...extra]],
        ['npx -y --package=<tarball> marrow-mcp', (extra) => ['-y', `--package=${tarball}`, 'marrow-mcp', ...extra]],
      ]
      forms.forEach(([label, buildArgs], index) => {
        const home = path.join(work, `home-${index}`)
        const cwd = path.join(work, `cwd-${index}`)
        fs.mkdirSync(home, { recursive: true })
        fs.mkdirSync(cwd, { recursive: true })
        const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, npm_config_cache: path.join(work, `cache-${index}`), npm_config_update_notifier: 'false' }
        for (const extra of [['--help'], ['loop-guard-self-test']]) {
          const result = run('npx', buildArgs(extra), { cwd, env, input: '' })
          const output = `${result.stdout || ''}${result.stderr || ''}`
          const what = `${label} ${extra.join(' ')}`
          const npxFailure = /could not determine executable|Permission denied|not found|ERR!|npm error/i.test(output)
          if (extra[0] === '--help') {
            check(`${what} must run the CLI and print its usage text (exit ${result.status}${npxFailure ? '; npx failed to run an executable' : ''})`, /Usage: MARROW_API_KEY=/.test(output))
          } else {
            check(`${what} must exit 0 and report pass:true from the real CLI (exit ${result.status}${npxFailure ? '; npx failed to run an executable' : ''})`, result.status === 0 && /"pass": true/.test(result.stdout || ''))
          }
        }
      })
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true })
  }
}

if (failures.length > 0) {
  console.error(`NPX_EXECUTABLE_CHECK=FAIL reason=${failures.join('; ')}`)
  process.exitCode = 1
} else {
  console.log(`NPX_EXECUTABLE_CHECK=PASS name=${pkg.name} version=${pkg.version}`)
}
