/**
 * One-shot PowerShell analysis for the kill-scope guard.
 *
 * Reuse instead of integration:
 * - `ctx.shell` is the same executor the `pwsh` tool runs commands through, so
 *   executable resolution, environment, output collection, deadline, and
 *   cancellation are the tool's own semantics. This module only builds one
 *   `ShellExecRequest`.
 * - `Parser::ParseInput` and `Get-Command` are PowerShell's own parser and
 *   command metadata; the analyzed command is never executed.
 *
 * The helper answers one question for one command text:
 * `{ range, reason, command }`.
 */

const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
try { [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
$text = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
$verdict = @{ range = $false; reason = ''; command = '' }

function Resolve-Command([string]$name) {
  if ([string]::IsNullOrEmpty($name)) { return @{ name = ''; command = $null } }
  $info = @()
  try { $info = @(Get-Command -Name $name -ErrorAction SilentlyContinue) } catch { $info = @() }
  if ($info.Count -eq 0) { return @{ name = $name; command = $null } }
  $first = $info[0]
  if ($first -is [System.Management.Automation.AliasInfo]) {
    $target = $first.Definition
    if ([string]::IsNullOrEmpty($target)) { return @{ name = $name; command = $null } }
    $targetInfo = @()
    try { $targetInfo = @(Get-Command -Name $target -ErrorAction SilentlyContinue) } catch { $targetInfo = @() }
    if ($targetInfo.Count -eq 0) { return @{ name = $target; command = $null } }
    return @{ name = $target; command = $targetInfo[0] }
  }
  return @{ name = $first.Name; command = $first }
}

foreach ($commandAst in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
  $name = $null
  try { $name = $commandAst.GetCommandName() } catch { $name = $null }
  if ([string]::IsNullOrEmpty($name)) { continue }
  $resolvedInfo = Resolve-Command $name
  $info = $resolvedInfo.command
  if ($resolvedInfo.name -ne 'Stop-Process') { continue }

  $parameterNames = @()
  if ($null -ne $info -and $null -ne $info.PSObject.Properties['Parameters']) { $parameterNames = @($info.Parameters.Keys) }
  $elements = @($commandAst.CommandElements)
  $parameters = @{}
  $positional = New-Object System.Collections.ArrayList
  for ($index = 1; $index -lt $elements.Count; $index++) {
    $element = $elements[$index]
    if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
      $canonical = $null
      $hits = @($parameterNames | Where-Object { $_.StartsWith($element.ParameterName, [System.StringComparison]::OrdinalIgnoreCase) })
      if ($hits.Count -eq 1) { $canonical = $hits[0] }
      $isSwitch = $false
      if ($null -ne $canonical -and $null -ne $info) {
        $metadata = $info.Parameters[$canonical]
        if ($null -ne $metadata -and $metadata.ParameterType -eq [System.Management.Automation.SwitchParameter]) { $isSwitch = $true }
      }
      $argument = $element.Argument
      if ($null -eq $argument -and -not $isSwitch -and ($index + 1) -lt $elements.Count) {
        $next = $elements[$index + 1]
        if ($next -isnot [System.Management.Automation.Language.CommandParameterAst]) {
          $argument = $next
          $index++
        }
      }
      if ($null -ne $canonical) { $parameters[$canonical] = $argument }
    } else {
      [void]$positional.Add($element)
    }
  }

  $reason = $null
  $pipeline = $commandAst.Parent
  if ($pipeline -is [System.Management.Automation.Language.PipelineAst]) {
    $pipelineElements = @($pipeline.PipelineElements)
    $position = [array]::IndexOf($pipelineElements, $commandAst)
    for ($index = 0; $index -lt $position; $index++) {
      $previous = $pipelineElements[$index]
      if ($previous -isnot [System.Management.Automation.Language.CommandAst]) { continue }
      $previousName = $null
      try { $previousName = $previous.GetCommandName() } catch { $previousName = $null }
      if ([string]::IsNullOrEmpty($previousName)) { continue }
      if ((Resolve-Command $previousName).name -eq 'Get-Process') { $reason = 'Get-Process 管道或子表达式'; break }
    }
  }

  if ($null -eq $reason -and $parameters.ContainsKey('Name')) { $reason = '按进程名（-Name）' }
  if ($null -eq $reason -and $parameters.ContainsKey('InputObject')) { $reason = '按对象（-InputObject）' }
  if ($null -eq $reason -and $parameters.ContainsKey('Id')) {
    $argument = $parameters['Id']
    $literal = $false
    if ($argument -is [System.Management.Automation.Language.ConstantExpressionAst]) {
      $literal = ($argument.Value -is [int]) -or ($argument.Value -is [long])
    } elseif ($argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
      $literal = ($argument.Value -match '^\d+$')
    } elseif ($argument -is [System.Management.Automation.Language.VariableExpressionAst]) {
      $literal = ($argument.VariablePath.UserPath -eq 'pid')
    } elseif ($argument -is [System.Management.Automation.Language.ArrayLiteralAst]) {
      $literal = $true
      foreach ($item in $argument.Elements) {
        if ($item -is [System.Management.Automation.Language.ConstantExpressionAst] -and (($item.Value -is [int]) -or ($item.Value -is [long]))) { continue }
        if ($item -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $item.Value -match '^\d+$') { continue }
        $literal = $false
      }
    }
    if (-not $literal) { $reason = '表达式 Id（不是字面 PID）' }
  }

  if ($null -eq $reason) {
    $target = $null
    foreach ($item in $positional) {
      if ($item -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $item.Value -match '^[-/]') { continue }
      $target = $item
      break
    }
    if ($null -ne $target) {
      $literal = $false
      if ($target -is [System.Management.Automation.Language.ConstantExpressionAst] -and (($target.Value -is [int]) -or ($target.Value -is [long]))) { $literal = $true }
      if ($target -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $target.Value -match '^\d+$') { $literal = $true }
      if (-not $literal) { $reason = '位置参数（目标不是字面 PID）' }
    }
  }

  if ($null -ne $reason) {
    $verdict = @{ range = $true; reason = $reason; command = $name }
    break
  }
}

[Console]::Out.Write(($verdict | ConvertTo-Json -Compress))
`

const TIMEOUT_MS = 8000

/**
 * Ask the shell executor whether one command text is a range kill.
 * @param shell - the profile's `ctx.shell` executor.
 * @param text - exact command text about to run.
 * @param signal - caller cancellation.
 * @returns `{ range, reason, command }`.
 * @throws when the executor cannot run the helper or answers with invalid output.
 */
export async function analyze(shell, text, signal) {
  const spec = shell.resolve({
    command: SCRIPT,
    stdin: text,
    timeoutMs: TIMEOUT_MS,
    onExpiry: 'kill',
    stdoutMaxBytes: 64 * 1024,
    signal,
  })
  const execution = await shell.execute(spec)
  const result = await execution.result()
  if (result.timedOut) throw new Error('parse timed out')
  if (result.aborted) throw new Error('parse aborted')
  if (result.exitCode !== 0) {
    const stderr = result.stderr?.text ?? ''
    throw new Error(`pwsh exited ${String(result.exitCode)}${stderr.trim() === '' ? '' : `: ${stderr.trim().slice(0, 400)}`}`)
  }
  const parsed = JSON.parse(result.stdout.text)
  return {
    range: parsed.range === true,
    reason: typeof parsed.reason === 'string' ? parsed.reason : '',
    command: typeof parsed.command === 'string' ? parsed.command : '',
  }
}
