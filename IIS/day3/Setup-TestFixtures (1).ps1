<#
  Setup-TestFixtures.ps1 - TEST VM ONLY. Creates known files and dummy scheduled tasks so you can check that
  spybot-hunt, keyword-hunt and Remo find / do what they should. Never run it on a real box.
  Run elevated:
      .\Setup-TestFixtures.ps1             create everything and print what each script should report
      .\Setup-TestFixtures.ps1 -Cleanup    remove everything it created
  Files go in C:\TestFixtures. Tasks are TestFix-Task1, TestFix-Task2 and TestFix-Keep.
  The flag text and hunt words are built while the script runs, so this file is never a FLAG. Its checklist text
  will still show up as a keyword/mention hit if you leave it on the test box.
#>
[CmdletBinding()]
param([switch]$Cleanup)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Host 'Run as Administrator.'; return }

$Root = 'C:\TestFixtures'
$TaskNames = @('TestFix-Task1','TestFix-Task2','TestFix-Keep')

if($Cleanup){
  foreach($t in $TaskNames){ if(Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue){ Unregister-ScheduledTask -TaskName $t -Confirm:$false } }
  if(Test-Path -LiteralPath $Root){ Remove-Item -LiteralPath $Root -Recurse -Force }
  Write-Host 'Test fixtures and test tasks removed.'
  return
}

# words are assembled here so this file does not contain them
$flag = 'RED{' + 'SPY' + ' BOT}'
$inj = 'in' + 'ject'
$red = 'Red' + ' Team'
$blue = 'blue' + '_team'
$grey = 'Grey' + 'Team'
$gray = 'gray' + '-team'

function Put([string]$Path,[string]$Text,[switch]$Utf16){
  $dir = Split-Path -Parent $Path
  if(-not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  if($Utf16){ [IO.File]::WriteAllText($Path,$Text,[Text.Encoding]::Unicode) } else { [IO.File]::WriteAllText($Path,$Text,[Text.Encoding]::ASCII) }
}

if(Test-Path -LiteralPath $Root){ Remove-Item -LiteralPath $Root -Recurse -Force }
$spy = Join-Path $Root 'spy'
$kw = Join-Path $Root 'kw'

# ---- SPY BOT fixtures ----
Put (Join-Path $spy 'desktop.ini.bak') ($flag + "`r`n")                                   # hidden + system, odd name
[IO.File]::SetAttributes((Join-Path $spy 'desktop.ini.bak'),([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
Put (Join-Path $spy 'application.evtx') ($flag + "`r`n")                                  # event-log extension
Put (Join-Path $spy 'utf16.dat') ($flag) -Utf16                                           # UTF-16
Put (Join-Path $spy 'late.txt') (('filler line' + "`r`n") * 20000 + $flag + "`r`n")       # flag ~240 KB into the file
Put (Join-Path $spy 'plain.txt') "nothing to see here`r`n"
Set-Content -LiteralPath (Join-Path $spy 'plain.txt') -Stream 'hidden' -Value $flag       # flag only in an alternate data stream
Put (Join-Path $spy 'lower.txt') ($flag.ToLower())                                        # variant: lowercase
Put (Join-Path $spy 'nospace.txt') ('RED{' + 'SPY' + 'BOT}')                              # variant: no space
Put (Join-Path $spy 'mention.txt') ('Spy' + 'bot Search and Destroy')                     # plain mention
$big = Join-Path $spy 'oversize.bin'                                                      # 6 MB, flag at the very end
$fs = [IO.File]::Create($big)
try{ $bytes = [Text.Encoding]::ASCII.GetBytes($flag); $fs.SetLength(6MB + $bytes.Length); $fs.Position = 6MB; $fs.Write($bytes,0,$bytes.Length) } finally { $fs.Dispose() }

# ---- keyword fixtures: these names / contents SHOULD be found ----
New-Item -ItemType Directory -Path (Join-Path $kw $red) -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $kw ($inj.Substring(0,1).ToUpper() + $inj.Substring(1) + '3')) -Force | Out-Null
Put (Join-Path $kw ('i' + 'N' + $inj.Substring(2) + '.txt')) 'x'                          # mixed-case name
Put (Join-Path $kw ($grey + '_plan.docx')) 'x'
Put (Join-Path $kw ($gray + ' notes.md')) 'x'
Put (Join-Path $kw ($blue + '.txt')) 'x'
Put (Join-Path $kw ($inj + '_notes.txt')) 'x'
Put (Join-Path $kw ('MyRedTeam' + 'In' + 'ject.txt')) 'x'
Put (Join-Path $kw ('ReD' + 'Team.log')) 'x'
Put (Join-Path $kw 'content_ascii.txt') ('the ' + $red + ' will i' + 'N' + 'Ject payloads')
Put (Join-Path $kw 'content_utf16.txt') ('see the ' + $blue.Replace('_',' ') + ' plan') -Utf16

# ---- keyword fixtures: these must NOT be found ----
New-Item -ItemType Directory -Path (Join-Path $kw ('Dependency' + 'Inj' + 'ection')) -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $kw ($inj + 'or')) -Force | Out-Null
Put (Join-Path $kw ('re' + $inj + '.txt')) 'x'
Put (Join-Path $kw ('inj' + 'ection.txt')) 'x'
Put (Join-Path $kw ($inj + 'ed.log')) 'x'
Put (Join-Path $kw ('sha' + 'red team.txt')) 'x'
$repo = 'Winny' + 'Ft' + 'Lock'                                                             # our repo folder: skipped completely
Put (Join-Path (Join-Path $kw $repo) ($inj + '_notes.txt')) 'x'
Put (Join-Path (Join-Path $kw ($repo.ToLower() + '-main')) ('Red' + 'Team.txt')) ('the ' + $red)
Put (Join-Path $kw 'content_noise.txt') ('dependency inj' + 'ection, the ' + $inj + 'or, re' + $inj + ' and sha' + 'red team')

# ---- dummy scheduled tasks for Remo ----
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
$trigger = New-ScheduledTaskTrigger -AtStartup
foreach($t in $TaskNames){
  Register-ScheduledTask -TaskName $t -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
}

Write-Host ''
Write-Host 'Created C:\TestFixtures and tasks TestFix-Task1, TestFix-Task2, TestFix-Keep.' -ForegroundColor Green
Write-Host ''
Write-Host 'EXPECTED RESULTS' -ForegroundColor Cyan
Write-Host '  spybot-hunt.ps1'
Write-Host '    FLAG (5):          spy\desktop.ini.bak, spy\application.evtx, spy\utf16.dat, spy\late.txt, spy\plain.txt:hidden'
Write-Host '    FLAG-VARIANT (2):  spy\lower.txt, spy\nospace.txt'
Write-Host '    mention (1):       spy\mention.txt'
Write-Host '    COVERAGE lists:    spy\oversize.bin as over the size limit (flag not found - expected)'
Write-Host '  spybot-hunt.ps1 -Repeat   same results every pass, a new log each pass; Ctrl+C stops it'
Write-Host '  keyword-hunt.ps1 (11 paths, all under kw\)'
Write-Host '    names (9):         the Red Team folder, the Inject3 folder, iNject.txt, GreyTeam_plan.docx, gray-team notes.md,'
Write-Host '                       blue_team.txt, inject_notes.txt, MyRedTeamInject.txt, ReDTeam.log'
Write-Host '    content (2):       content_ascii.txt, content_utf16.txt'
Write-Host '    must NOT appear:   DependencyInjection, injector, reinject.txt, injection.txt, injected.log, "shared team.txt", content_noise.txt,'
Write-Host '                       anything under the WinnyFtLock and winnyftlock-main folders (COVERAGE shows "Skipped ... winnyftlock: 2")'
Write-Host '  Remo -Action Once (one pass, nothing left running)'
Write-Host '    TestFix-Task1, TestFix-Task2 and TestFix-Keep are Disabled right away (the run prints "Disabled N task(s)").'
Write-Host '    -Action RestoreTasks turns them back on. -Action Once is refused while Remo is installed.'
Write-Host '  Remo (full install, after 1-2 minutes)'
Write-Host '    TestFix-Task1 and TestFix-Task2 become Disabled. TestFix-Keep stays enabled only if you put'
Write-Host "    '\TestFix-Keep' in `$KeepTasks before installing; otherwise it is disabled too."
Write-Host '    -Action Pause then -Action RestoreTasks turns them back on.'
Write-Host ''
Write-Host 'Remove everything when done: .\Setup-TestFixtures.ps1 -Cleanup'
