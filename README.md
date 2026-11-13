# Kill scope guard

A DSH Host bundle that denies the first **range** process kill in a shell tool
call once, with a short reminder to confirm the kill scope. A precise kill such
as `Stop-Process -Id 1234 -Force` passes untouched.

## Install

The bundle is published as [`@joxos/dsh-kill-scope-guard`](https://www.npmjs.com/package/@joxos/dsh-kill-scope-guard).
Install it into a DSH profile through the plugin manager, or add the row in a
profile patch:

```yaml
- insert:
    - id: kill-scope-guard
      name: '@joxos/dsh-kill-scope-guard'
      config: {}
```

It needs the profile's PowerShell tool (`pwsh`) and shell executor; both are
already present in the Windows desktop composition.

## How it works

- One async `tools/pre-execute` gate. A token check decides only whether to parse
  a command; it never decides a denial.
- DSH's shell executor (`ctx.shell`) runs one `pwsh` for that command — the same
  executor the `pwsh` tool uses, so executable resolution, environment, output
  collection, and deadlines are the tool's own semantics. The inline script
  parses the command with PowerShell's own `Parser` and resolves aliases and
  parameter abbreviations with `Get-Command`, then answers
  `{ range, reason, command }`. The analyzed command is never executed.
- The plugin applies one denial per agent per command, renders the reminder, and
  caches the verdict per command text.
- There is no text-based fallback. If the helper cannot answer, the call
  proceeds and a warning is logged.

Range means: `-Name`, a `Get-Process` pipeline or subexpression, `-InputObject`,
a non-literal `-Id`, or a non-literal positional target. Precise means literal
PIDs, a list of literal PIDs, `$pid`, or a positional PID. Because names are
matched after alias resolution, `spps` and `kill` count as `Stop-Process`, and
`ps` counts as `Get-Process`.

A parse spawns one fresh `pwsh` (roughly 0.6–0.8 s) per distinct command text;
repeat commands are served from the verdict cache.

## Behaviour

- The first range kill for an agent is denied once; resending the identical
  command passes. Whitespace and case are normalized.
- Denials become `Error:` tool results, so the model reads the reminder on its
  next step.
- Only `pwsh` (`command`) and `terminal_send` (`text`) are scanned.
- If another pre-execute listener short-circuits the waterfall before this gate
  (for example an approval request), this gate does not run for that call.
- The helper runs through `ctx.shell`, so it inherits the deployment sandbox
  policy: under a confining mode the .NET parser call can be blocked by
  ConstrainedLanguage, and the gate then fails open with a warning.
- Out of scope: `taskkill`, object `.Kill()`, and kills hidden behind dynamic
  invocation such as `& $name`.

## Development

```powershell
node --check index.js
node --check parser.js
node scripts/smoke.mjs
```

The smoke script spawns real `pwsh`; no build step and no npm dependencies.
