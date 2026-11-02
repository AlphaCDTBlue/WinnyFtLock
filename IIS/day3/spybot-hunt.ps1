<#
  spybot-hunt.ps1 - finds the hidden SPY BOT flag files (content RED{SPY BOT}) on this Windows host.
  Run elevated, no arguments:
      powershell -ExecutionPolicy Bypass -File .\spybot-hunt.ps1
  Content-based: file name, extension (including .evtx/.etl) and hidden/system attributes do not matter.
  Searches every readable file <= 5 MB on all fixed drives (ASCII/UTF-8 and UTF-16, any case), then NTFS
  alternate data streams (including Zone.Identifier; -NoStreams to skip). Links/junctions are not followed.
  Only exclusion: C:\Windows\WinSxS (component store, hard links to system files) - add -IncludeWinSxS to search it.
  Match labels:
    FLAG          the exact text RED{SPY BOT}
    FLAG-VARIANT  looks like the flag but differs (case, RED{SPYBOT}, RED{SPY_BOT}, extra spaces)
    mention       "spy bot" text without the flag format
  Where labels: unclassified = not recognised as a copy (treat as a candidate real location), or a copy made by
  something else: backup-copy, repo-clone, remo-quarantine, remo-files, gitat-baseline, gitat-emergency-copy,
  BlueLogs-file, this-script. Copies are listed, never ignored.
  The log is written as hits are found (an interrupted scan leaves a partial log); a finished scan ends with
  SCAN COMPLETE, a path list and a COVERAGE section (unreadable files, files over the size limit, folders not entered).
  Default is ONE pass, then it exits.
      .\spybot-hunt.ps1 -Repeat     scans again every 60 s until you press Ctrl+C (each pass has its own log)
  Read-only: nothing is moved or deleted.
  Results: C:\BlueLogs\spybot_<host>_<time>.txt
#>
[CmdletBinding()]
param([switch]$NoStreams,[switch]$IncludeWinSxS,[ValidateRange(1,1024)][int]$MaxFileMB=5,[switch]$Repeat)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

if($Repeat){
  # each pass is a fresh process, so counters and lists start clean every time
  $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $passArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-MaxFileMB',[string]$MaxFileMB)
  if($NoStreams){ $passArgs += '-NoStreams' }
  if($IncludeWinSxS){ $passArgs += '-IncludeWinSxS' }
  $n = 0
  while($true){
    $n++
    Write-Host ('===== spybot-hunt pass ' + $n + ' at ' + (Get-Date).ToString('s') + ' (Ctrl+C to stop) =====') -ForegroundColor Cyan
    & $psExe @passArgs
    Write-Host 'Next pass in 60 seconds.'
    Start-Sleep -Seconds 60
  }
}

$OutDir = 'C:\BlueLogs'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutTxt = Join-Path $OutDir ('spybot_' + $env:COMPUTERNAME + '_' + (Get-Date).ToString('yyyyMMdd_HHmmss') + '.txt')
$script:Hits = New-Object System.Collections.ArrayList
$script:Seen = @{}
$script:StreamErrors = New-Object System.Collections.ArrayList
$script:StreamBig = New-Object System.Collections.ArrayList
$script:StreamsChecked = 0

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin){ Write-Host 'Run as Administrator.'; return }

$CSharp = @'
using System;
using System.IO;
using System.Collections.Generic;
public static class SpyScan {
  public static long Scanned = 0, Oversized = 0, Unreadable = 0, Links = 0, Excluded = 0;
  public static List<string> OversizedList = new List<string>();
  public static List<string> UnreadableList = new List<string>();
  public static List<string> LinkList = new List<string>();
  static void Note(List<string> l, string s) { if (l.Count < 300) l.Add(s); }
  static int C(byte[] b, int p, int len, int w) {
    if (p < 0 || p + w > len) return -1;
    if (w == 2 && b[p + 1] != 0) return -1;
    int c = b[p];
    if (c >= 'A' && c <= 'Z') c += 32;
    return c;
  }
  static bool Match(byte[] b, int i, int len, int w) {
    if (C(b, i, len, w) != 's' || C(b, i + w, len, w) != 'p' || C(b, i + 2 * w, len, w) != 'y') return false;
    int p = i + 3 * w;
    int c = C(b, p, len, w);
    if (c == ' ' || c == '_' || c == '-' || c == '.') { p += w; c = C(b, p, len, w); }
    return c == 'b' && C(b, p + w, len, w) == 'o' && C(b, p + 2 * w, len, w) == 't';
  }
  static bool Find(byte[] b, int len, int w) {
    for (int i = 0; i < len; i++) {
      int c = b[i];
      if (c != 's' && c != 'S') continue;
      if (Match(b, i, len, w)) return true;
    }
    return false;
  }
  public static bool CheckBytes(byte[] b, int len) { return Find(b, len, 1) || Find(b, len, 2); }
  public static bool Check(string path, long maxBytes) {
    try {
      long total = new FileInfo(path).Length;
      if (total > maxBytes) { Oversized++; Note(OversizedList, path + " (" + (total / 1048576) + " MB)"); return false; }
      if (total < 6) return false;
      bool found = false;
      using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536)) {
        int chunk = 1 << 20; int keep = 40;
        byte[] buf = new byte[chunk + keep];
        int carry = 0;
        while (true) {
          int n = fs.Read(buf, carry, chunk);
          if (n <= 0) break;
          int len = carry + n;
          if (CheckBytes(buf, len)) { found = true; break; }
          carry = Math.Min(keep, len);
          Buffer.BlockCopy(buf, len - carry, buf, 0, carry);
        }
      }
      Scanned++;
      return found;
    } catch (Exception ex) { Unreadable++; Note(UnreadableList, path + " :: " + ex.GetType().Name); }
    return false;
  }
  public static List<string> ScanTree(string root, bool recurse, long maxBytes, string[] skipDirs, string[] skipExt) {
    var res = new List<string>();
    var stack = new Stack<string>();
    stack.Push(root);
    bool first = true;
    while (stack.Count > 0) {
      string d = stack.Pop();
      if (recurse || !first) {
        try {
          foreach (var sd in Directory.GetDirectories(d)) {
            try { if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) != 0) { Links++; Note(LinkList, sd); continue; } } catch { Unreadable++; Note(UnreadableList, sd + " :: attributes"); continue; }
            bool skip = false;
            foreach (var s in skipDirs) { if (sd.Equals(s, StringComparison.OrdinalIgnoreCase)) { skip = true; break; } }
            if (skip) { Excluded++; Note(LinkList, sd + " (excluded)"); continue; }
            stack.Push(sd);
          }
        } catch (Exception ex) { Unreadable++; Note(UnreadableList, d + " :: folder " + ex.GetType().Name); }
      }
      first = false;
      try {
        foreach (var f in Directory.GetFiles(d)) {
          string ext = Path.GetExtension(f);
          bool sk = false;
          foreach (var e in skipExt) { if (ext.Equals(e, StringComparison.OrdinalIgnoreCase)) { sk = true; break; } }
          if (sk) continue;
          if (Check(f, maxBytes)) res.Add(f);
        }
      } catch (Exception ex) { Unreadable++; Note(UnreadableList, d + " :: files " + ex.GetType().Name); }
    }
    return res;
  }
}
'@
if(-not ('SpyScan' -as [type])){ Add-Type -TypeDefinition $CSharp -Language CSharp }

$FlagExact = 'RED{SPY BOT}'
$FlagLoose = '(?i)RED\{\s*SPY[ _.\-]?BOT\s*\}'
$SpyRx = '(?i)spy[ _.\-]?bot'
$maxBytes = [long]$MaxFileMB * 1MB
$self = ''
if($PSCommandPath){ $self = $PSCommandPath }

# folders that hold copies of files made by our own tools
$script:BackupPaths = @()
try{
  $bf = 'C:\BlueLogs\backups-locations.json'
  if(Test-Path -LiteralPath $bf){
    $raw = Get-Content -LiteralPath $bf -Raw
    foreach($m in [regex]::Matches($raw,'[A-Za-z]:[\\/][^"]+')){
      $p = ($m.Value -replace '\\\\','\').TrimEnd('\')
      if($p.Length -gt 5){ $script:BackupPaths += $p }
    }
  }
} catch {}

function Test-Under([string]$Path,[string]$Prefix){
  if(-not $Prefix){ return $false }
  return ($Path.Equals($Prefix,[StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($Prefix.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase))
}

function Append-Log([string[]]$Text){
  try{ [IO.File]::AppendAllLines($OutTxt,$Text) } catch {}
}

function Get-Where([string]$Path){
  if($self -and $Path.Equals($self,[StringComparison]::OrdinalIgnoreCase)){ return 'this-script' }
  if(Test-Under $Path $OutDir){ return 'BlueLogs-file' }
  if($Path -match '(?i)\\Remo-[a-f0-9]{32}\\quarantine\\'){ return 'remo-quarantine' }
  if($Path.StartsWith(($env:ProgramData + '\Remo'),[StringComparison]::OrdinalIgnoreCase)){ return 'remo-files' }
  if(Test-Under $Path ($env:ProgramData + '\IISCache')){ return 'gitat-baseline' }
  if($Path -match '(?i)\\Public\\Pictures\\\.[a-f0-9]{32}\\'){ return 'gitat-emergency-copy' }
  if($Path -match '(?i)\\\.git\\' -or $Path -match '(?i)\\(winnyftlock|alphacdtblue)\\'){ return 'repo-clone' }
  foreach($b in $script:BackupPaths){ if(Test-Under $Path $b){ return 'backup-copy' } }
  return 'unclassified'
}

function Get-TextForms([string]$Path,[string]$Stream){
  if($Stream){ return @([string](Get-Content -LiteralPath $Path -Stream $Stream -Raw -ErrorAction Stop)) }
  $b = [IO.File]::ReadAllBytes($Path)
  return @([Text.Encoding]::ASCII.GetString($b), [Text.Encoding]::Unicode.GetString($b), [Text.Encoding]::Unicode.GetString($b,1,($b.Length - 1) -band -2))
}

function Get-Snippet([string]$Path,[string]$Stream){
  try{
    $forms = Get-TextForms $Path $Stream
    $raw = $forms[0]
    foreach($f in $forms){
      $m = [regex]::Match($f,$FlagLoose)
      if(-not $m.Success){ $m = [regex]::Match($f,$SpyRx) }
      if($m.Success){
        $s = [math]::Max(0,$m.Index - 40); $e = [math]::Min($f.Length,$m.Index + $m.Length + 60)
        $raw = $f.Substring($s,$e - $s); break
      }
    }
    $t = ($raw -replace '[^\x20-\x7E]',' ' -replace '\s+',' ').Trim()
    if($t.Length -gt 200){ $t = $t.Substring(0,200) }
    return $t
  } catch { return '' }
}

function Get-FlagKind([string]$Path,[string]$Stream){
  $kind = 'mention'
  try{
    foreach($f in (Get-TextForms $Path $Stream)){
      if($f.Contains($FlagExact)){ return 'FLAG' }
      if($f -match $FlagLoose){ $kind = 'FLAG-VARIANT' }
    }
  } catch {}
  return $kind
}

function Add-Hit([string]$Path,[string]$Stream){
  $full = $Path
  if($Stream){ $full = $Path + ':' + $Stream }
  if($script:Seen.ContainsKey($full)){ return }
  $script:Seen[$full] = $true
  $fi = Get-Item -LiteralPath $Path -Force
  $kind = Get-FlagKind $Path $Stream
  $snip = Get-Snippet $Path $Stream
  $where = Get-Where $Path
  $owner = ''
  try{ $owner = (Get-Acl -LiteralPath $Path).Owner } catch {}
  $hash = ''
  if(-not $Stream){ $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
  $o = [pscustomobject]@{
    Kind=$kind; Where=$where; Host=$env:COMPUTERNAME; Path=$full; Attributes=[string]$fi.Attributes
    Size=$fi.Length; Created=$fi.CreationTime.ToString('s'); Modified=$fi.LastWriteTime.ToString('s')
    Owner=$owner; SHA256=$hash; Content=$snip
  }
  [void]$script:Hits.Add($o)
  $block = @(('[' + $kind + ' / ' + $where + '] ' + $full), ('   attrs=' + $o.Attributes + ' size=' + $o.Size + ' created=' + $o.Created + ' modified=' + $o.Modified + ' owner=' + $o.Owner))
  if($hash){ $block += ('   sha256=' + $hash) }
  $block += ('   content: ' + $snip)
  $block += ''
  Append-Log $block
  $color = 'Yellow'
  if($kind -like 'FLAG*'){ if($where -eq 'unclassified'){ $color = 'Green' } else { $color = 'DarkYellow' } }
  Write-Host ''
  Write-Host ('[' + $kind + ' / ' + $where + '] ' + $full) -ForegroundColor $color
  Write-Host ('   attrs=' + $o.Attributes + ' size=' + $o.Size + ' modified=' + $o.Modified + ' owner=' + $o.Owner)
  Write-Host ('   content: ' + $o.Content)
}

[IO.File]::WriteAllLines($OutTxt,[string[]]@(('spybot-hunt ' + (Get-Date).ToString('s') + ' on ' + $env:COMPUTERNAME),'SCAN STARTED. If there is no SCAN COMPLETE line at the end of this file, the scan was interrupted and the list below is partial.',''))
$roots = @()
foreach($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')){ $roots += ($d.DeviceID + '\') }
if($roots.Count -eq 0){ $roots = @('C:\') }

$skipDirs = [string[]]@()
if(-not $IncludeWinSxS){ $skipDirs = [string[]]@((Join-Path $env:SystemRoot 'WinSxS')) }
$skipExt = [string[]]@()

Write-Host ('spybot-hunt on ' + $env:COMPUTERNAME + ' - drives: ' + ($roots -join ' ') + '  (folders not entered: ' + ($skipDirs -join ', ') + '; files over ' + $MaxFileMB + ' MB are listed in COVERAGE)')
foreach($r in $roots){
  Write-Host ('[' + (Get-Date).ToString('HH:mm:ss') + '] scanning ' + $r)
  foreach($f in [SpyScan]::ScanTree($r,$false,$maxBytes,$skipDirs,$skipExt)){ Add-Hit $f '' }
  foreach($d in (Get-ChildItem -LiteralPath $r -Directory -Force)){
    if($d.Attributes -band [IO.FileAttributes]::ReparsePoint){ [SpyScan]::Links += 1; [void][SpyScan]::LinkList.Add($d.FullName); continue }
    if($skipDirs -contains $d.FullName){ continue }
    foreach($f in [SpyScan]::ScanTree($d.FullName,$true,$maxBytes,$skipDirs,$skipExt)){ Add-Hit $f '' }
  }
  Write-Host ('   files searched so far: ' + [SpyScan]::Scanned)
  Append-Log @('[' + (Get-Date).ToString('HH:mm:ss') + '] finished ' + $r + ' - files searched so far: ' + [SpyScan]::Scanned)
}

if(-not $NoStreams){
  $maxBytesStream = $maxBytes
  foreach($r in $roots){
    Write-Host ('[' + (Get-Date).ToString('HH:mm:ss') + '] alternate data streams on ' + $r)
    Append-Log @('[' + (Get-Date).ToString('HH:mm:ss') + '] checking alternate data streams on ' + $r)
    $cur = ''
    foreach($line in (& cmd.exe /c ('dir "' + $r + '" /s /r /a 2>nul'))){
      # stream lines end in :$DATA; directory header lines are the other lines that end in a drive path (any language)
      if($line -notmatch ':\$DATA' -and $line -match '^\s*[^\d\s].*?\s([A-Za-z]:\\.*)$'){ $cur = $Matches[1].Trim(); continue }
      if($line -match '^\s+(\S+)\s+(.+?):([^:]+):\$DATA\s*$'){
        $sizeText = ($Matches[1] -replace '\D','')
        $name = $Matches[2]; $stream = $Matches[3]
        $p = Join-Path $cur $name
        $script:StreamsChecked++
        if($sizeText -and ([long]$sizeText -gt $maxBytesStream)){ if($script:StreamBig.Count -lt 300){ [void]$script:StreamBig.Add($p + ':' + $stream + ' (' + [math]::Round([long]$sizeText / 1MB) + ' MB)') }; continue }
        try{
          $txt = [string](Get-Content -LiteralPath $p -Stream $stream -Raw -ErrorAction Stop)
          if($txt -match $SpyRx){
            Add-Hit $p $stream
          }
        } catch { if($script:StreamErrors.Count -lt 300){ [void]$script:StreamErrors.Add($p + ':' + $stream) } }
      }
    }
  }
}

Write-Host ''
$orig = @($script:Hits | Where-Object { $_.Kind -eq 'FLAG' -and $_.Where -eq 'unclassified' })
$vari = @($script:Hits | Where-Object { $_.Kind -eq 'FLAG-VARIANT' -and $_.Where -eq 'unclassified' })
$copies = @($script:Hits | Where-Object { $_.Kind -like 'FLAG*' -and $_.Where -ne 'unclassified' })
$ment = @($script:Hits | Where-Object { $_.Kind -eq 'mention' })
Write-Host ('=== DONE on ' + $env:COMPUTERNAME + ': ' + $orig.Count + ' FLAG file(s), ' + $vari.Count + ' FLAG-VARIANT file(s), ' + $copies.Count + ' flag copy/copies in known copy locations, ' + $ment.Count + ' other mention(s) ===') -ForegroundColor Cyan
Write-Host 'Grey Team said 5 flag files exist across the whole infrastructure - run this on every box.' -ForegroundColor Cyan

$lines = @('',('=== SCAN COMPLETE ' + (Get-Date).ToString('s') + ' ==='),'=== PATH LIST ===')
if($orig.Count){
  Write-Host ''; Write-Host 'FLAG FILE PATHS (exact RED{SPY BOT}, not in a known copy location):' -ForegroundColor Green
  $lines += ''; $lines += 'FLAG FILE PATHS (exact RED{SPY BOT}, not in a known copy location):'
  foreach($h in $orig){ Write-Host ('  ' + $h.Path) -ForegroundColor Green; $lines += ('  ' + $h.Path) }
}
if($vari.Count){
  Write-Host ''; Write-Host 'FLAG-VARIANT PATHS (look like the flag but are not exactly RED{SPY BOT}):' -ForegroundColor Yellow
  $lines += ''; $lines += 'FLAG-VARIANT PATHS (look like the flag but are not exactly RED{SPY BOT}):'
  foreach($h in $vari){ Write-Host ('  ' + $h.Path) -ForegroundColor Yellow; $lines += ('  ' + $h.Path) }
}
if($copies.Count){
  Write-Host ''; Write-Host 'FLAG COPIES in known copy locations (backups, repos, logs, quarantine, this script):' -ForegroundColor DarkYellow
  $lines += ''; $lines += 'FLAG COPIES in known copy locations (backups, repos, logs, quarantine, this script):'
  foreach($h in $copies){ Write-Host ('  ' + $h.Path + '   [' + $h.Where + ']') -ForegroundColor DarkYellow; $lines += ('  ' + $h.Path + '   [' + $h.Where + ']') }
}
if($ment.Count){
  Write-Host ''; Write-Host 'OTHER MENTIONS OF SPY BOT (not the flag format):' -ForegroundColor Yellow
  $lines += ''; $lines += 'OTHER MENTIONS OF SPY BOT (not the flag format):'
  foreach($h in $ment){ Write-Host ('  ' + $h.Path + '   [' + $h.Where + ']') -ForegroundColor Yellow; $lines += ('  ' + $h.Path + '   [' + $h.Where + ']') }
}

$cov = @('','=== COVERAGE ===')
$cov += ('Files searched: ' + [SpyScan]::Scanned)
$cov += ('Files over ' + $MaxFileMB + ' MB, not searched: ' + [SpyScan]::Oversized)
$cov += ('Files/folders that could not be read (access denied, locked, path too long): ' + [SpyScan]::Unreadable)
$cov += ('Links/junctions and excluded folders not entered: ' + ([SpyScan]::Links + [SpyScan]::Excluded))
$cov += ('Folders excluded on purpose: ' + $(if($skipDirs.Count){ $skipDirs -join ', ' }else{ 'none' }))
if(-not $NoStreams){ $cov += ('Alternate data streams checked: ' + $script:StreamsChecked + ', over the size limit: ' + $script:StreamBig.Count + ', unreadable: ' + $script:StreamErrors.Count) }
$cov += 'Not covered: archives/compressed files, UTF-16 big-endian, deleted files, network drives, other machines.'
Write-Host ''
foreach($c in $cov){ Write-Host $c -ForegroundColor Cyan }
$lines += $cov
foreach($pair in @(@('FILES OVER SIZE LIMIT',[SpyScan]::OversizedList),@('COULD NOT BE READ',[SpyScan]::UnreadableList),@('LINKS / EXCLUDED FOLDERS NOT ENTERED',[SpyScan]::LinkList),@('STREAMS OVER SIZE LIMIT',$script:StreamBig),@('UNREADABLE STREAMS',$script:StreamErrors))){
  if($pair[1].Count -eq 0){ continue }
  $lines += ''
  $lines += ($pair[0] + ' (first ' + $pair[1].Count + ')')
  foreach($x in $pair[1]){ $lines += ('  ' + $x) }
}
Append-Log $lines
Write-Host ''
Write-Host ('Saved: ' + $OutTxt + '  (full coverage lists are in the log)')
