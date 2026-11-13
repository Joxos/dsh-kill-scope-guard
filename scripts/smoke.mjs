import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { apply } from '../index.js'

/**
 * Test double for the DSH shell executor: runs the resolved spec with real
 * pwsh and exposes the ShellExecution shape the plugin consumes.
 */
function realShell() {
  return {
    resolve(request) {
      return {
        command: request.command,
        workdir: process.cwd(),
        timeoutMs: request.timeoutMs ?? 8000,
        onExpiry: request.onExpiry ?? 'kill',
        stdoutMaxBytes: request.stdoutMaxBytes ?? 65536,
        stdin: request.stdin,
        signal: request.signal,
      }
    },
    async execute(spec) {
      const child = spawn('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', spec.command], {
        windowsHide: true,
      })
      let stdout = ''
      let stderr = ''
      child.stdout.setEncoding('utf8')
      child.stderr.setEncoding('utf8')
      child.stdout.on('data', (chunk) => {
        stdout += chunk
      })
      child.stderr.on('data', (chunk) => {
        stderr += chunk
      })
      child.stdin.end(spec.stdin ?? '')
      const done = new Promise((resolve) => {
        child.on('error', () => resolve({ exitCode: 1, signal: null }))
        child.on('close', (code) => resolve({ exitCode: code, signal: null }))
      })
      return {
        async result() {
          const outcome = await done
          return {
            exitCode: outcome.exitCode,
            signal: null,
            timedOut: false,
            aborted: false,
            timeoutMs: spec.timeoutMs,
            stdout: { text: stdout, truncated: false },
            stderr: { text: stderr, truncated: false },
          }
        },
      }
    },
  }
}

function mount(shell) {
  const disposers = []
  const warnings = []
  let listener
  const ctx = {
    effect(callback) {
      const disposer = callback()
      disposers.push(disposer)
      return disposer
    },
    on(event, callback) {
      if (event === 'tools/pre-execute') {
        listener = callback
        return () => {
          listener = undefined
        }
      }
      return () => {}
    },
    get(name) {
      return name === 'shell' ? shell : undefined
    },
    logger: {
      warn(message) {
        warnings.push(message)
      },
    },
    inject(dependencies, callback) {
      callback(ctx)
    },
  }
  apply(ctx)
  assert.equal(typeof listener, 'function', 'plugin must register a pre-execute listener')

  return {
    warnings,
    async run(name, args, agentId = 'agent-a') {
      let allowed = false
      const decision = await listener(
        { name, arguments: args, agent: { id: agentId }, signal: new AbortController().signal },
        async () => {
          allowed = true
          return { kind: 'allow' }
        },
      )
      return { decision, allowed }
    },
    async pwsh(command, agentId) {
      return await this.run('pwsh', { command }, agentId)
    },
    dispose() {
      for (const disposer of disposers.reverse()) if (typeof disposer === 'function') disposer()
    },
  }
}

const base = mount(realShell())

// --- precise kills pass untouched -------------------------------------------
for (const command of [
  'Stop-Process -Id 1234 -Force',
  'Stop-Process -Id 1234',
  'Stop-Process -Id 1234, 5678',
  'Stop-Process -Id $pid',
  'Stop-Process 1234',
  'Stop-Process -Force',
  'kill 1234',
]) {
  const { decision, allowed } = await base.pwsh(command)
  assert.equal(decision.kind, 'allow', `expected allow for: ${command}`)
  assert.equal(allowed, true)
}

// --- range kills are denied with the parser's reason ------------------------
async function denial(command, expectedReason, agentId) {
  const { decision } = await base.pwsh(command, agentId)
  assert.equal(decision.kind, 'deny', `expected deny for: ${command}`)
  if (expectedReason !== undefined) {
    assert.ok(decision.reason.includes(expectedReason), `reason should mention "${expectedReason}": ${decision.reason}`)
  }
  return decision.reason
}

await denial('Stop-Process -Name notepad', '按进程名（-Name）')
await denial('stop-process -name "notepad" -Force', '按进程名（-Name）')
await denial('Stop-Process -Na notepad', '按进程名（-Name）')
await denial('spps -Name notepad', '按进程名（-Name）')
await denial('Get-Process notepad | Stop-Process', 'Get-Process 管道或子表达式')
await denial('ps | Stop-Process', 'Get-Process 管道或子表达式')
await denial('Get-Process | Where-Object { $_.CPU -gt 1 } | Stop-Process -Force', 'Get-Process 管道或子表达式')
await denial('Stop-Process -Id (Get-Process notepad).Id', '表达式 Id（不是字面 PID）')
await denial('Stop-Process -Id $procs.Id', '表达式 Id（不是字面 PID）')
await denial('Stop-Process -InputObject $procs', '按对象（-InputObject）')
await denial('Stop-Process @params', '位置参数（目标不是字面 PID）')

// --- one denial per agent per command ---------------------------------------
assert.equal((await base.pwsh('Stop-Process -Name notepad')).decision.kind, 'allow', 'identical retry should pass')
assert.equal((await base.pwsh('Stop-Process -Name notepad', 'agent-b')).decision.kind, 'deny', 'another agent gets its own denial')

// --- inert text and non-kill tools ------------------------------------------
assert.equal((await base.pwsh('Write-Output "Stop-Process -Name notepad"')).decision.kind, 'allow')
assert.equal((await base.pwsh('# Stop-Process -Name notepad')).decision.kind, 'allow')
assert.equal((await base.pwsh('Get-Command Stop-Process')).decision.kind, 'allow')
assert.equal((await base.run('write', { file_path: 'a.ps1', content: 'Stop-Process -Name x' })).allowed, true)

// --- shell failure: no fallback, the call proceeds ---------------------------
const broken = mount({
  resolve() {
    throw new Error('no shell executor')
  },
  async execute() {
    throw new Error('must not execute')
  },
})
assert.equal((await broken.pwsh('Stop-Process -Name notepad')).decision.kind, 'allow')
assert.ok(
  broken.warnings.some((message) => message.includes('command not checked')),
  `failure must be reported, got: ${JSON.stringify(broken.warnings)}`,
)

for (const session of [base, broken]) session.dispose()

console.log('kill-scope-guard smoke: ok')
