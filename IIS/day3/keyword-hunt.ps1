<#
  keyword-hunt.ps1 - lists every file or folder on this Windows host whose NAME or CONTENT has
  greyteam / redteam / blueteam / inject.
  Run elevated, no arguments:
      powershell -ExecutionPolicy Bypass -File .\keyword-hunt.ps1
  Not case sensitive (iNject, INJECT, ReDTeam). Team words also match with a separator or grey/gray
  spelling ("Red Team", "red_team", "gray-team"). "inject" matches the word (inject, injects, Inject3,
  inject_notes, RedTeamInject) but not injection/injector/injected/reinject.
  Names: every file and folder on all fixed drives. Content: files <= 5 MB (ASCII/UTF-8 and UTF-16).
  Default exclusions (printed when it starts, and listed again in COVERAGE):
    - content in Windows, Program Files, Program Files (x86), ProgramData\Microsoft, ProgramData\Package Cache
    - the C:\Windows\WinSxS component store is not entered at all
  -IncludeSystem removes ALL of those exclusions (it is slow). Links/junctions are never followed.
  The log file is written as hits are found (an interrupted scan leaves a partial log); a finished scan
  ends with SCAN COMPLETE, a plain path list and a COVERAGE section (unreadable files, files over the size limit).
  Anything named winnyftlock (our GitHub repo folder, in any case) is skipped entirely: not listed, not entered.
  Prints a progress line every 15 s. Ctrl+C stops it at once; the log keeps the hits found so far.
  Read-only: nothing is moved or deleted.
  Results: C:\BlueLogs\keyword_<host>_<time>.txt
#>
[CmdletBinding()]
param([switch]$IncludeSystem)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$MaxFileMB = 5
$OutDir = 'C:\BlueLogs'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutTxt = Join-Path $OutDir ('keyword_' + $env:COMPUTERNAME + '_' + (Get-Date).ToString('yyyyMMdd_HHmmss') + '.txt')
$script:Hits = New-Object System.Collections.ArrayList
$script:Seen = @{}
$script:TagCount = @{}
$script:InjQuiet = 0
$script:LastProg = Get-Date
$script:ScanDone = $false

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin){ Write-Host 'Run as Administrator.'; return }

$CSharp = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;
public class KwHit {
  public string Path;
  public bool IsDir;
  public int NameMask;
  public int ContentMask;
}
public static class KwHunt {
  public static long Scanned = 0, Oversized = 0, Unreadable = 0, Links = 0, Excluded = 0, NotSearched = 0, RepoSkipped = 0;
  public static List<string> OversizedList = new List<string>();
  public static List<string> UnreadableList = new List<string>();
  public static List<string> LinkList = new List<string>();
  static void Note(List<string> l, string s) { if (l.Count < 300) l.Add(s); }
  static Regex teamRx = new Regex(@"(?<![A-Za-z])(?:grey|gray|red|blue)[ _.\-]?team|(?-i:(?<=[a-z])(?:Grey|Gray|Red|Blue))[ _.\-]?team", RegexOptions.IgnoreCase);
  static Regex injRx = new Regex(@"(?<![A-Za-z])inject(?!ion|or|ing|ed|able|ive|ant)|(?-i:(?<=[a-z])Inject)(?!ion|or|ing|ed|able|ive|ant)", RegexOptions.IgnoreCase);
  // masks: 2 = team word, 4 = inject
  public static int NameMask(string name) {
    int m = 0;
    if (teamRx.IsMatch(name)) m |= 2;
    if (injRx.IsMatch(name)) m |= 4;
    return m;
  }
  static int Lc(byte[] b, int p, int len, int w) {
    if (p < 0 || p + w > len) return -1;
    if (w == 2 && b[p + 1] != 0) return -1;
    int c = b[p];
    if (c >= 'A' && c <= 'Z') c += 32;
    return c;
  }
  static int Raw(byte[] b, int p, int len, int w) {
    if (p < 0 || p + w > len) return -1;
    if (w == 2 && b[p + 1] != 0) return -1;
    return b[p];
  }
  static bool Word(byte[] b, int p, int len, int w, string s) {
    for (int k = 0; k < s.Length; k++) { if (Lc(b, p + k * w, len, w) != s[k]) return false; }
    return true;
  }
  static bool IsSep(int c) { return c == ' ' || c == '_' || c == '-' || c == '.'; }
  static bool IsLetter(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
  // word start: not preceded by a letter, or CamelCase (capital letter after a lowercase letter)
  static bool LeadOk(byte[] b, int i, int len, int w) {
    int prev = Raw(b, i - w, len, w);
    if (!IsLetter(prev)) return true;
    int first = Raw(b, i, len, w);
    return first >= 'A' && first <= 'Z' && prev >= 'a' && prev <= 'z';
  }
  static bool Team(byte[] b, int p, int len, int w) {
    if (IsSep(Lc(b, p, len, w))) p += w;
    return Word(b, p, len, w, "team");
  }
  static int MatchAt(byte[] b, int i, int len, int w, bool eof, int want) {
    int c = Lc(b, i, len, w);
    if ((c == 'g' || c == 'r' || c == 'b') && (want & 2) != 0) {
      int e = 0;
      if (c == 'g' && (Word(b, i, len, w, "grey") || Word(b, i, len, w, "gray"))) e = i + 4 * w;
      else if (c == 'r' && Word(b, i, len, w, "red")) e = i + 3 * w;
      else if (c == 'b' && Word(b, i, len, w, "blue")) e = i + 4 * w;
      if (e == 0 || !LeadOk(b, i, len, w)) return 0;
      return Team(b, e, len, w) ? 2 : 0;
    }
    if (c == 'i' && (want & 4) != 0) {
      if (!Word(b, i, len, w, "inject") || !LeadOk(b, i, len, w)) return 0;
      int p = i + 6 * w;
      if (p + 4 * w > len && !eof) return 0;
      if (Word(b, p, len, w, "ion") || Word(b, p, len, w, "or") || Word(b, p, len, w, "ing") || Word(b, p, len, w, "ed") || Word(b, p, len, w, "able") || Word(b, p, len, w, "ive") || Word(b, p, len, w, "ant")) return 0;
      return 4;
    }
    return 0;
  }
  static int Find(byte[] b, int start, int len, int w, bool eof, int want) {
    int mask = 0;
    for (int i = start; i < len; i++) {
      int c = b[i];
      if (c >= 'A' && c <= 'Z') c += 32;
      if (c != 'g' && c != 'r' && c != 'b' && c != 'i') continue;
      mask |= MatchAt(b, i, len, w, eof, want);
      if (mask == want) break;
    }
    return mask;
  }
  public static int CheckBytes(byte[] b, int len, int want) {
    return Find(b, 0, len, 1, true, want) | Find(b, 0, len, 2, true, want);
  }
  public static int CheckFile(string path, long maxBytes, int want) {
    int mask = 0;
    try {
      long total = new FileInfo(path).Length;
      if (total > maxBytes) { Oversized++; Note(OversizedList, path + " (" + (total / 1048576) + " MB)"); return 0; }
      if (total < 6) return 0;
      using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536)) {
        int chunk = 1 << 20; int keep = 40;
        byte[] buf = new byte[chunk + keep];
        int carry = 0;
        while (true) {
          int n = fs.Read(buf, carry, chunk);
          if (n <= 0) break;
          int len = carry + n;
          bool eof = fs.Position >= total;
          int start = carry > 0 ? 2 : 0;
          mask |= Find(buf, start, len, 1, eof, want);
          mask |= Find(buf, start, len, 2, eof, want);
          if (eof) break;
          carry = Math.Min(keep, len);
          Buffer.BlockCopy(buf, len - carry, buf, 0, carry);
        }
      }
      Scanned++;
    } catch (Exception ex) { Unreadable++; Note(UnreadableList, path + " :: " + ex.GetType().Name); }
    return mask;
  }
  public static string CurrentDir = "";
  static string[] SafeDirs(string d) {
    try { return Directory.GetDirectories(d); } catch (Exception ex) { Unreadable++; Note(UnreadableList, d + " :: folder " + ex.GetType().Name); }
    return new string[0];
  }
  static string[] SafeFiles(string d) {
    try { return Directory.GetFiles(d); } catch (Exception ex) { Unreadable++; Note(UnreadableList, d + " :: files " + ex.GetType().Name); }
    return new string[0];
  }
  // Yields each hit, and a null about once a second so the caller regains control (Ctrl+C works, progress can be shown).
  public static IEnumerable<KwHit> ScanTree(string root, bool recurse, long maxBytes, string[] skipDirs, string[] skipExt, string[] noisy, string outDir, string selfPath) {
    var stack = new Stack<string>();
    stack.Push(root);
    DateTime beat = DateTime.UtcNow;
    while (stack.Count > 0) {
      string d = stack.Pop();
      CurrentDir = d;
      foreach (var sd in SafeDirs(d)) {
        if (Path.GetFileName(sd).IndexOf("winnyftlock", StringComparison.OrdinalIgnoreCase) >= 0) { RepoSkipped++; continue; }
        int nm = NameMask(Path.GetFileName(sd));
        if (nm != 0) { var dh = new KwHit(); dh.Path = sd; dh.IsDir = true; dh.NameMask = nm; yield return dh; }
        if (!recurse) continue;
        try { if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) != 0) { Links++; Note(LinkList, sd); continue; } } catch { Unreadable++; Note(UnreadableList, sd + " :: attributes"); continue; }
        bool skip = false;
        foreach (var s in skipDirs) { if (sd.Equals(s, StringComparison.OrdinalIgnoreCase)) { skip = true; break; } }
        if (skip) { Excluded++; Note(LinkList, sd + " (excluded)"); continue; }
        stack.Push(sd);
      }
      foreach (var f in SafeFiles(d)) {
        string name = Path.GetFileName(f);
        if (name.IndexOf("winnyftlock", StringComparison.OrdinalIgnoreCase) >= 0) { RepoSkipped++; continue; }
        int nm = NameMask(name);
        int cm = 0;
        string ext = Path.GetExtension(f);
        bool sk = false;
        foreach (var e in skipExt) { if (ext.Equals(e, StringComparison.OrdinalIgnoreCase)) { sk = true; break; } }
        if (f.Equals(selfPath, StringComparison.OrdinalIgnoreCase)) sk = true;
        if (name.StartsWith("keyword_", StringComparison.OrdinalIgnoreCase) && d.Equals(outDir, StringComparison.OrdinalIgnoreCase)) sk = true;
        if (!sk) {
          int want = 6;
          foreach (var np in noisy) { if (f.StartsWith(np + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { want = 0; break; } }
          if (want == 0) NotSearched++;
          else cm = CheckFile(f, maxBytes, want);
        }
        if (nm != 0 || cm != 0) { var fh = new KwHit(); fh.Path = f; fh.IsDir = false; fh.NameMask = nm; fh.ContentMask = cm; yield return fh; }
        if ((DateTime.UtcNow - beat).TotalSeconds >= 1) { beat = DateTime.UtcNow; yield return null; }
      }
      if ((DateTime.UtcNow - beat).TotalSeconds >= 1) { beat = DateTime.UtcNow; yield return null; }
    }
  }
}
'@
if(-not ('KwHunt' -as [type])){ Add-Type -TypeDefinition $CSharp -Language CSharp }

$TeamRx = '(?i)(?<![A-Za-z])(?:grey|gray|red|blue)[ _.\-]?team|(?-i:(?<=[a-z])(?:Grey|Gray|Red|Blue))[ _.\-]?team'
$InjRx = '(?i)(?<![A-Za-z])inject(?!ion|or|ing|ed|able|ive|ant)|(?-i:(?<=[a-z])Inject)(?!ion|or|ing|ed|able|ive|ant)'

function Append-Log([string[]]$Text){
  try{ [IO.File]::AppendAllLines($OutTxt,$Text) } catch {}
}

function Get-Context([string]$Path,[string]$Rx){
  try{
    $b = [IO.File]::ReadAllBytes($Path)
    $n = [math]::Min($b.Length,4096); $z = 0
    for($i = 0; $i -lt $n; $i++){ if($b[$i] -eq 0){ $z++ } }
    if($z -gt ($n / 4)){ $t = [Text.Encoding]::Unicode.GetString($b) } else { $t = [Text.Encoding]::ASCII.GetString($b) }
    $m = [regex]::Match($t,$Rx)
    if(-not $m.Success){ return '' }
    $s = [math]::Max(0,$m.Index - 40)
    $e = [math]::Min($t.Length,$m.Index + $m.Length + 60)
    return (($t.Substring($s,$e - $s)) -replace '[^\x20-\x7E]',' ' -replace '\s+',' ').Trim()
  } catch { return '' }
}

function Add-Hit($h){
  $path = $h.Path
  if($script:Seen.ContainsKey($path)){ return }
  $script:Seen[$path] = $true
  $tags = @()
  $snip = ''
  if($h.NameMask -band 2){ $tags += 'TEAM-NAME' }
  if($h.ContentMask -band 2){
    $tags += 'TEAM-CONTENT'
    if($script:TagCount['TEAM-CONTENT'] -lt 100){ $snip = Get-Context $path $TeamRx }
  }
  if($h.NameMask -band 4){ $tags += 'INJECT-NAME' }
  if($h.ContentMask -band 4){
    $tags += 'INJECT-CONTENT'
    if(-not $snip -and $script:TagCount['INJECT-CONTENT'] -lt 100){ $snip = Get-Context $path $InjRx }
  }
  foreach($t in $tags){ $script:TagCount[$t] = 1 + [int]$script:TagCount[$t] }
  $fi = Get-Item -LiteralPath $path -Force
  $owner = ''
  try{ $owner = (Get-Acl -LiteralPath $path).Owner } catch {}
  $size = ''
  $created = ''
  $modified = ''
  $attrs = ''
  if($fi){
    $attrs = [string]$fi.Attributes
    $created = $fi.CreationTime.ToString('s')
    $modified = $fi.LastWriteTime.ToString('s')
    if(-not $h.IsDir){ $size = $fi.Length }
  }
  $o = [pscustomobject]@{
    Tags=($tags -join ','); Path=$path; IsDir=[bool]$h.IsDir; Attributes=$attrs
    Size=$size; Created=$created; Modified=$modified; Owner=$owner; Content=$snip
  }
  [void]$script:Hits.Add($o)
  $block = @(('[' + $o.Tags + '] ' + $path + $(if($h.IsDir){'  (folder)'}else{''})), ('   attrs=' + $o.Attributes + ' size=' + $o.Size + ' created=' + $o.Created + ' modified=' + $o.Modified + ' owner=' + $o.Owner))
  if($o.Content){ $block += ('   content: ' + $o.Content) }
  $block += ''
  Append-Log $block
  $onlyInj = ($tags.Count -eq 1 -and $tags[0] -eq 'INJECT-CONTENT')
  if($onlyInj){
    $script:InjQuiet++
    if($script:InjQuiet -eq 26){ Write-Host '   (more files containing "inject" are only listed in the log)' -ForegroundColor DarkGray }
    if($script:InjQuiet -gt 25){ return }
  }
  $label = ''; if($h.IsDir){ $label = '  (folder)' }
  Write-Host ''
  Write-Host ('[' + $o.Tags + '] ' + $path + $label) -ForegroundColor Yellow
  Write-Host ('   attrs=' + $o.Attributes + ' size=' + $o.Size + ' modified=' + $o.Modified + ' owner=' + $o.Owner)
  if($o.Content){ Write-Host ('   content: ' + $o.Content) }
}

function Show-Progress{
  if(((Get-Date) - $script:LastProg).TotalSeconds -lt 15){ return }
  $script:LastProg = Get-Date
  Write-Host ('[' + (Get-Date).ToString('HH:mm:ss') + '] still scanning - ' + [KwHunt]::Scanned + ' files content-searched, now in ' + [KwHunt]::CurrentDir) -ForegroundColor DarkGray
}

[IO.File]::WriteAllLines($OutTxt,[string[]]@(('keyword-hunt ' + (Get-Date).ToString('s') + ' on ' + $env:COMPUTERNAME),'SCAN STARTED. If there is no SCAN COMPLETE line at the end of this file, the scan was interrupted and the list below is partial.',''))
$roots = @()
foreach($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')){ $roots += ($d.DeviceID + '\') }
if($roots.Count -eq 0){ $roots = @('C:\') }

$skipDirs = [string[]]@()
if(-not $IncludeSystem){ $skipDirs = [string[]]@((Join-Path $env:SystemRoot 'WinSxS')) }
$skipExt = [string[]]@()
$noisy = [string[]]@()
if(-not $IncludeSystem){
  $noisy = [string[]]@(@($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, ($env:ProgramData + '\Microsoft'), ($env:ProgramData + '\Package Cache')) | Where-Object { $_ })
}
$self = ''
if($PSCommandPath){ $self = $PSCommandPath }
$maxBytes = [long]$MaxFileMB * 1MB

Write-Host ('keyword-hunt on ' + $env:COMPUTERNAME + ' - drives: ' + ($roots -join ' '))
if($IncludeSystem){ Write-Host 'Names and content are searched everywhere, including Windows and WinSxS (-IncludeSystem).' }
else { Write-Host ('Names are checked everywhere except the WinSxS store. Content is NOT searched in: ' + ($noisy -join ', ') + '  (add -IncludeSystem to search all of it)') }
Append-Log @(('Content not searched in: ' + ($noisy -join ', ')), ('Folders not entered: ' + ($skipDirs -join ', ')), '')
try{
foreach($r in $roots){
  Write-Host ('[' + (Get-Date).ToString('HH:mm:ss') + '] scanning ' + $r)
  foreach($h in [KwHunt]::ScanTree($r,$false,$maxBytes,$skipDirs,$skipExt,$noisy,$OutDir,$self)){ if($null -eq $h){ Show-Progress; continue }; Add-Hit $h }
  foreach($d in (Get-ChildItem -LiteralPath $r -Directory -Force)){
    if($d.Attributes -band [IO.FileAttributes]::ReparsePoint){ [KwHunt]::Links += 1; [void][KwHunt]::LinkList.Add($d.FullName); continue }
    if($skipDirs -contains $d.FullName){ continue }
    if($d.Name -like '*winnyftlock*'){ continue }
    foreach($h in [KwHunt]::ScanTree($d.FullName,$true,$maxBytes,$skipDirs,$skipExt,$noisy,$OutDir,$self)){ if($null -eq $h){ Show-Progress; continue }; Add-Hit $h }
  }
  Write-Host ('   files content-searched so far: ' + [KwHunt]::Scanned)
  Append-Log @('[' + (Get-Date).ToString('HH:mm:ss') + '] finished ' + $r + ' - files content-searched so far: ' + [KwHunt]::Scanned)
}
$script:ScanDone = $true
} finally {
  if(-not $script:ScanDone){ Append-Log @('', '=== SCAN INTERRUPTED (stopped before it finished) - the hits above are partial ==='); Write-Host 'Stopped before finishing. Hits found so far are in the log.' -ForegroundColor Yellow }
}

Write-Host ''
$groups = @(
  @{ Title='GREYTEAM / REDTEAM / BLUETEAM (name or content)'; Match='TEAM-' },
  @{ Title='INJECT (name or content)';  Match='INJECT-' }
)
Write-Host ('=== DONE on ' + $env:COMPUTERNAME + ': ' + @($script:Hits | Where-Object { $_.Tags -match 'TEAM-' }).Count + ' team path(s), ' + @($script:Hits | Where-Object { $_.Tags -match 'INJECT-' }).Count + ' inject path(s) ===') -ForegroundColor Cyan

$lines = @('',('=== SCAN COMPLETE ' + (Get-Date).ToString('s') + ' ==='))
$lines += '=== PATH LIST ==='
foreach($g in $groups){
  $sel = @($script:Hits | Where-Object { $_.Tags -match $g.Match })
  if($sel.Count -eq 0){ continue }
  $lines += ''
  $lines += ($g.Title + ' (' + $sel.Count + ')')
  Write-Host ''
  Write-Host ($g.Title + ' (' + $sel.Count + ')') -ForegroundColor Cyan
  $shown = 0
  foreach($h in $sel){
    $kind = ''; if($h.IsDir){ $kind = '  (folder)' }
    $lines += ('  ' + $h.Path + $kind)
    if($shown -lt 50){ Write-Host ('  ' + $h.Path + $kind); $shown++ }
  }
  if($sel.Count -gt 50){ Write-Host ('  ...' + ($sel.Count - 50) + ' more in the log') -ForegroundColor DarkGray }
}

$cov = @('','=== COVERAGE ===')
$cov += ('Files content-searched: ' + [KwHunt]::Scanned)
$cov += ('Files not content-searched (system folders; use -IncludeSystem): ' + [KwHunt]::NotSearched)
$cov += ('Files over ' + $MaxFileMB + ' MB (name checked, content not searched): ' + [KwHunt]::Oversized)
$cov += ('Files/folders that could not be read (access denied, locked, path too long): ' + [KwHunt]::Unreadable)
$cov += ('Skipped, name contains winnyftlock (our repo): ' + [KwHunt]::RepoSkipped)
$cov += ('Links/junctions and excluded folders not entered: ' + ([KwHunt]::Links + [KwHunt]::Excluded + 0))
$cov += 'Not covered: archives/compressed files, UTF-16 big-endian, deleted files, network drives, other machines.'
if(-not $IncludeSystem){ $cov += 'Excluded by default (use -IncludeSystem): content in Windows/Program Files/ProgramData\Microsoft; the WinSxS folder.' }
Write-Host ''
foreach($c in $cov){ Write-Host $c -ForegroundColor Cyan }
$lines += $cov
foreach($pair in @(@('FILES OVER SIZE LIMIT',[KwHunt]::OversizedList),@('COULD NOT BE READ',[KwHunt]::UnreadableList),@('LINKS / EXCLUDED FOLDERS NOT ENTERED',[KwHunt]::LinkList))){
  if($pair[1].Count -eq 0){ continue }
  $lines += ''
  $lines += ($pair[0] + ' (first ' + $pair[1].Count + ')')
  foreach($x in $pair[1]){ $lines += ('  ' + $x) }
}
$cov2 = @('Excluded on purpose: content in ' + ($noisy -join ', '))
$cov2 += ('Folders not entered: ' + ($skipDirs -join ', '))
Append-Log $lines
Append-Log $cov2
Write-Host ''
Write-Host ('Saved: ' + $OutTxt + '  (full coverage lists are in the log)')
