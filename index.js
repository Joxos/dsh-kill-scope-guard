/**
 * Kill scope guard — denies the first *range* process kill in a shell tool call
 * once, with a reminder to confirm the kill scope. A precise kill such as
 * `Stop-Process -Id 1234 -Force` passes untouched.
 *
 * The plugin is deliberately thin: DSH's shell executor (`ctx.shell`) runs one
 * pwsh helper, and PowerShell's own parser plus `Get-Command` metadata decide
 * whether the command is a range kill (see parser.js). This file only registers
 * the gate, applies the one-denial-per-agent policy, and renders the reminder.
 *
 * There is no text fallback and no second opinion: when the helper cannot
 * answer, the call proceeds and a warning is logged.
 */

import { analyze } from './parser.js'

/** Tool name → argument field that carries executable text. */
const TARGET_FIELDS = Object.freeze({
  pwsh: 'command',
  terminal_send: 'text',
})

/** Cheap spawn filter: a command without one of these is never parsed. */
const CANDIDATE_TOKENS = Object.freeze(['stop-process', 'spps', 'kill'])

const VERDICT_LIMIT = 128
const DENIAL_LIMIT = 512
const EXCERPT_LENGTH = 240

const REMINDER = `范围 Stop-Process 拦截：这条命令没有执行。

命中方式：{{reason}}
命令片段：{{command}}

这是按进程集合结束进程的写法，不是按单个 PID 精确操作。先确认这一批目标具体是哪些进程、范围是否就是你要处理的；确认后把同一条命令原样重发即可放行；本插件对同一 agent 的同一命令只拦一次。只带字面 PID 的写法（如 \`Stop-Process -Id <PID>\`）不会触发拦截。`

/**
 * Register the gate for as long as the profile provides a subprocess service.
 * @param ctx - plugin context.
 */
export function apply(ctx) {
  const verdicts = new Map()
  const denied = new Map()

  ctx.inject(['shell'], (injected) => {
    const scoped = injected ?? ctx
    const shell = scoped.get('shell')
    if (shell === undefined) return

    scoped.effect(() =>
      scoped.on('tools/pre-execute', async (exec, next) => {
        const text = commandText(exec)
        if (text === undefined || !looksLikeKill(text)) return next()
        try {
          const verdict = await verdictFor(shell, verdicts, text, exec.signal)
          if (!verdict.range) return next()
          const agent = exec.agent === undefined ? 'host' : String(exec.agent.id)
          const key = `${agent}\u0000${normalize(text)}`
          if (denied.has(key)) return next()
          remember(denied, key, true, DENIAL_LIMIT)
          return {
            kind: 'deny',
            reason: render(verdict, text),
            info: { name: 'KillScopeGuardError', code: 'RANGE_KILL' },
          }
        } catch (error) {
          warn(scoped, error)
          return next()
        }
      }),
    )
  })
}

/** Reuse a cached verdict; a failed parse is never cached. */
async function verdictFor(shell, cache, text, signal) {
  const key = normalize(text)
  const cached = cache.get(key)
  if (cached !== undefined) return cached
  const verdict = await analyze(shell, text, signal)
  remember(cache, key, verdict, VERDICT_LIMIT)
  return verdict
}

/** Read the command field the tool actually runs, if this tool is in scope. */
function commandText(exec) {
  const field = TARGET_FIELDS[exec.name]
  if (field === undefined) return undefined
  const args = exec.arguments
  if (typeof args !== 'object' || args === null) return undefined
  const value = args[field]
  if (typeof value === 'string') return value.length === 0 ? undefined : value
  if (!Array.isArray(value)) return undefined
  const parts = value.filter((item) => typeof item === 'string')
  return parts.length === 0 ? undefined : parts.join('\n')
}

/** Whether the text is worth a parser call at all; it never decides a denial. */
function looksLikeKill(text) {
  const lowered = text.toLowerCase()
  return CANDIDATE_TOKENS.some((token) => lowered.includes(token))
}

/** Keep one bounded insertion-ordered map. */
function remember(map, key, value, limit) {
  map.set(key, value)
  while (map.size > limit) {
    const oldest = map.keys().next().value
    if (oldest === undefined) return
    map.delete(oldest)
  }
}

/** Collapse whitespace so cosmetic edits count as the same command. */
function normalize(text) {
  return text.replace(/\s+/gu, ' ').trim().toLowerCase()
}

/** Fill the reminder template. */
function render(verdict, text) {
  return REMINDER.replaceAll('{{reason}}', verdict.reason === '' ? '范围 kill' : verdict.reason).replaceAll(
    '{{command}}',
    excerpt(text, verdict.command),
  )
}

/** Quote the matched command with a little context, bounded for prompt size. */
function excerpt(text, needle) {
  const index = needle === '' ? -1 : text.toLowerCase().indexOf(needle.toLowerCase())
  const at = index === -1 ? 0 : index
  const length = needle === '' ? 0 : needle.length
  const start = Math.max(0, at - 60)
  const end = Math.min(text.length, at + length + 120)
  let body = text.slice(start, end).replace(/\s+/gu, ' ').trim()
  if (body.length > EXCERPT_LENGTH) body = `${body.slice(0, EXCERPT_LENGTH - 1)}…`
  return `${start > 0 ? '…' : ''}${body}${end < text.length ? '…' : ''}`
}

/** Best-effort diagnostic sink; a failing logger must not break the gate. */
function warn(ctx, error) {
  try {
    const message = error instanceof Error ? error.message : String(error)
    ctx.logger.warn(`kill-scope-guard: command not checked: ${message}`)
  } catch {
    // Logging is best effort.
  }
}
