#Requires -Version 5.1
<#
Remo-Why.ps1 - read-only. Answers: "the scoring check says the site is DOWN (wrong content) - why didn't Remo fix it?"
Run elevated, no arguments:   .\Remo-Why.ps1
Changes nothing. It checks, in order: is Remo actually running and unpaused, what the site really returns and whether the
expected text is in it, which folder IIS really serves (against the folder Remo protects), which protected files are
changed / missing / new, whether IIS config is covered, and whether another site shares the binding.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Write-Host 'Open Windows PowerShell as Administrator.' -ForegroundColor Red;return}
$PD=[string]$env:ProgramData;if(-not $PD){$PD='C:\ProgramData'}
$Dep=Join-Path $PD 'Remo\deployment.json'
$Cause=New-Object System.Collections.ArrayList;$Fix=New-Object System.Collections.ArrayList
function Title([string]$t){Write-Host '';Write-Host ('=== '+$t+' ').PadRight(78,'=') -ForegroundColor Cyan}
function Line([string]$t,[string]$c='Gray'){Write-Host ('  '+$t) -ForegroundColor $c}
function Cause([string]$t,[string]$f=''){[void]$Cause.Add($t);if($f -and -not $Fix.Contains($f)){[void]$Fix.Add($f)}}
function Read-J([string]$p){try{if(Test-Path -LiteralPath $p){return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop|ConvertFrom-Json)}}catch{};return $null}
function Get-Page([string]$Url){
 $o=[pscustomobject]@{Code=0;Text='';Body='';Final=$Url;Error=''}
 try{
  $q=[Net.HttpWebRequest]::Create($Url);$q.Timeout=10000;$q.AllowAutoRedirect=$true;$q.KeepAlive=$false;$q.UserAgent='Remo-Why'
  $r=$null
  try{$r=$q.GetResponse()}catch [Net.WebException]{$r=$_.Exception.Response;if(-not $r){$o.Error=$_.Exception.Message}}
  if($r){$o.Code=[int]$r.StatusCode;$o.Text=[string]$r.StatusDescription;$o.Final=$r.ResponseUri.AbsoluteUri
   $sr=New-Object IO.StreamReader($r.GetResponseStream());$o.Body=$sr.ReadToEnd();$sr.Close();$r.Close()}
 }catch{$o.Error=$_.Exception.Message}
 return $o
}

$d=Read-J $Dep
if(-not $d -or $d.State -ne 'Active'){
 Write-Host 'Remo is not installed/Active here, so nothing is restoring the site. Run .\Remo.ps1 (or .\Remo-Check.ps1 for details).' -ForegroundColor Red;return
}
$settings=Read-J (Join-Path $d.Store 'settings.json');$status=Read-J (Join-Path $d.Store 'status.json')
if(-not $settings){Write-Host ('Cannot read '+(Join-Path $d.Store 'settings.json')) -ForegroundColor Red;return}

Title '1. IS REMO RUNNING?'
$w=Get-ScheduledTask -TaskName ([string]$d.WorkerTask) -TaskPath '\' -ErrorAction SilentlyContinue
$wState=if($w){if($w.Settings.Enabled){[string]$w.State}else{'Disabled'}}else{'Missing'}
$age=-1;if($status){try{$age=[int]((Get-Date).ToUniversalTime()-([datetimeoffset]$status.Time).UtcDateTime).TotalSeconds}catch{}}
$marker=Test-Path -LiteralPath (Join-Path $d.Store 'paused')
Line ('Deployment paused : '+$d.Paused+'     pause marker present: '+$marker) $(if($d.Paused -or $marker){'Red'}else{'Green'})
Line ('Worker task       : '+$wState) $(if($wState -eq 'Running'){'Green'}else{'Red'})
Line ('Last health pass  : '+$(if($age -ge 0){[string]$age+' s ago'}else{'none'})) $(if($age -ge 0 -and $age -le 60){'Green'}else{'Red'})
if($status){Line ('Remo says healthy : '+$status.Healthy+'   HTTP: '+[string]$status.HTTP.Result+'   pass paused: '+$status.Paused) $(if($status.Healthy){'Green'}else{'Yellow'})
 Line ('Last restore      : '+$(if($status.LastRestore){[string]$status.LastRestore}else{'never'}))
 foreach($e in @($status.Events)){Line ('event  '+$e) 'Yellow'};foreach($e in @($status.Errors)){Line ('ERROR  '+$e) 'Red'}}
if($d.Paused -or $marker -or ($status -and $status.Paused)){Cause 'Remo is PAUSED (Fix-HttpError.ps1 pauses it and leaves it paused), so nothing is being restored.' '.\Remo.ps1 -Action Resume'}
elseif($wState -ne 'Running'){Cause ('Remo worker task is '+$wState+'.') ('Start-ScheduledTask -TaskName '+$d.WorkerTask)}
elseif($age -lt 0 -or $age -gt 60){Cause 'Remo has not written a health pass in over a minute (worker stuck?).' ('Start-ScheduledTask -TaskName '+$d.WorkerTask)}

Title '2. WHAT THE SITE REALLY RETURNS'
$expected=[string]$settings.ExpectedText
Line ('Remo health URL    : '+$settings.HealthUrl);Line ('Expected text      : "'+$expected+'"') 'White'
$urls=New-Object System.Collections.ArrayList;[void]$urls.Add([string]$settings.HealthUrl)
foreach($u in @('http://127.0.0.1/',('http://'+$env:COMPUTERNAME+'/'))){if(-not $urls.Contains($u)){[void]$urls.Add($u)}}
foreach($u in $urls){
 $p=Get-Page $u
 if($p.Code -eq 0){Line ($u+'  ->  NO ANSWER '+$p.Error) 'Red';continue}
 $has=if($expected){$p.Body.Contains($expected)}else{$null}
 Line ($u+'  ->  '+$p.Code+' '+$p.Text+'   '+$p.Body.Length+' bytes   expected text: '+$(if($has -eq $null){'(none set)'}elseif($has){'FOUND'}else{'MISSING'})) $(if($has -eq $false){'Red'}elseif($p.Code -ge 400){'Red'}else{'Green'})
 if($u -eq [string]$settings.HealthUrl){
  $script:Main=$p;$script:MainHas=$has
  $snip=($p.Body -replace '\s+',' ');if($snip.Length -gt 240){$snip=$snip.Substring(0,240)+' ...'}
  Line ('   starts with: '+$snip) 'DarkGray'
  if($p.Final -ne $u){Line ('   redirected to: '+$p.Final) 'Yellow'}
 }
}

Title '3. WHICH FOLDER DOES IIS SERVE?'
$appcmd=Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
$siteRoots=@{}
if(Test-Path -LiteralPath $appcmd){
 $sites=@(& $appcmd list site 2>&1|ForEach-Object{[string]$_})
 foreach($l in $sites){Line $l $(if($l -match 'state:Stopped'){'Yellow'}else{'Gray'})}
 foreach($l in @(& $appcmd list vdir 2>&1|ForEach-Object{[string]$_})){
  if($l -match '^VDIR "(?<n>[^"]+)" \(physicalPath:(?<p>.+)\)\s*$'){$siteRoots[$Matches.n]=[Environment]::ExpandEnvironmentVariables($Matches.p)}}
 $mine=[string]$settings.SiteName;$key=$mine+'/'
 $served=$siteRoots[$key]
 if($served){
  $protected=@($settings.Targets|Where-Object{-not $_.IsConfig}|ForEach-Object{[string]$_.Root})
  Line ('Site "'+$mine+'" serves : '+$served) 'White'
  Line ('Remo protects      : '+($protected -join '; ')) 'White'
  $same=$false;foreach($r in $protected){if($r.TrimEnd('\') -ieq $served.TrimEnd('\')){$same=$true}}
  if(-not $same){Cause ('IIS serves a DIFFERENT folder ('+$served+') than the one Remo restores ('+($protected -join '; ')+'). The site was repointed.') ('& "'+$appcmd+'" set vdir "'+$key+'" /physicalPath:"'+$protected[0]+'"   (then recheck)')}
 }else{Line ('Could not find the root virtual directory of site "'+$mine+'".') 'Yellow'}
 # other sites sharing the binding
 $bind=@{};foreach($l in $sites){if($l -match '^SITE "(?<n>[^"]+)" \(id:\d+,bindings:(?<b>[^,]*(?:,[^,)]*)*),state:(?<s>\w+)\)'){foreach($b in ($Matches.b -split ',')){if($b){if(-not $bind.ContainsKey($b)){$bind[$b]=@()};$bind[$b]+=,($Matches.n+' ['+$Matches.s+']')}}}}
 foreach($k in $bind.Keys){if(@($bind[$k]).Count -gt 1){Line ('Binding '+$k+' is used by: '+(@($bind[$k]) -join ', ')) 'Yellow'}}
 $dd=@(& $appcmd list config $mine /section:defaultDocument 2>&1|ForEach-Object{[string]$_})
 $files=@([regex]::Matches(($dd -join ' '),'<add value="([^"]+)"')|ForEach-Object{$_.Groups[1].Value})
 if($files.Count){Line ('Default documents (in order): '+($files -join ', ')) 'Gray'}
}else{Line 'appcmd.exe not found.' 'Yellow'}

Title '4. PROTECTED FILES vs THE APPROVED BASELINE'
foreach($t in @($settings.Targets)){
 $root=[string]$t.Root;$miss=@();$chg=@();$known=@{}
 foreach($f in @($t.Files)){
  $known[([string]$f.Path)]=$true
  $p=Join-Path $root ([string]$f.Path)
  if(-not(Test-Path -LiteralPath $p -PathType Leaf)){$miss+=[string]$f.Path;continue}
  try{if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ine [string]$f.Hash){$chg+=[string]$f.Path}}catch{$chg+=([string]$f.Path+' (unreadable)')}
 }
 $new=@()
 if(-not $t.IsConfig -and (Test-Path -LiteralPath $root)){
  $ex=@($settings.Exclude|ForEach-Object{([string]$_).Replace('\','/').Trim('/')})
  try{foreach($i in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue){
   $rel=$i.FullName.Substring($root.TrimEnd('\').Length+1).Replace('\','/')
   $skip=$false;foreach($e in $ex){if($rel -ieq $e -or $rel.StartsWith($e+'/',[StringComparison]::OrdinalIgnoreCase)){$skip=$true}}
   if(-not $skip -and -not $known.ContainsKey($rel)){$new+=$rel}}}catch{}
 }
 $label=if($t.IsConfig){'IIS config'}else{'Site files'}
 Line ($label+' ['+$t.Id+']  '+$root+'   baseline files: '+@($t.Files).Count) 'White'
 Line ('   changed: '+$chg.Count+'    missing: '+$miss.Count+'    new (not in baseline): '+$new.Count) $(if($chg.Count+$miss.Count+$new.Count){'Red'}else{'Green'})
 foreach($x in ($chg|Select-Object -First 12)){Line ('   CHANGED  '+$x) 'Red'};foreach($x in ($miss|Select-Object -First 12)){Line ('   MISSING  '+$x) 'Red'};foreach($x in ($new|Select-Object -First 12)){Line ('   NEW      '+$x) 'Yellow'}
 if($chg.Count+$miss.Count){Cause ([string]($chg.Count+$miss.Count)+' protected file(s) differ from the baseline in '+$root+' and are not being restored (Remo paused or erroring).') '.\Remo.ps1 -Action Resume'}
 if($new.Count){Cause ([string]$new.Count+' file(s) in '+$root+' are not in the baseline'+$(if([string]$settings.NewFiles -eq 'Report'){' and Remo is set to only REPORT new files, so it leaves them in place (a new index/default page can outrank the real one).'}else{' (Remo quarantines these every pass).'})) $(if([string]$settings.NewFiles -eq 'Report'){'Review the NEW files above; move bad ones out of '+$root})}
}
$hasCfg=@($settings.Targets|Where-Object{$_.IsConfig}).Count
Line ('IIS config covered by the baseline: '+$(if($hasCfg){'yes'}else{'NO - changes to bindings, handlers, rewrite rules and default documents are not reverted'})) $(if($hasCfg){'Green'}else{'Yellow'})
Line ('Excluded from protection (never restored): '+(@($settings.Exclude) -join ', ')) 'Gray'

Title 'CONCLUSION'
$allMatch=$true
if($Cause.Count){foreach($c in $Cause){Line ('- '+$c) 'Red'};if($Fix.Count){Write-Host '';Line 'Do this:' 'White';foreach($f in $Fix){Line ('   '+$f) 'White'}}}
else{
 if($script:Main -and $script:MainHas -eq $false){
  Line 'Remo is running, the site folder is the protected one, and every protected file matches the baseline - yet the page lacks the expected text.' 'Red'
  Line 'So the problem is outside the files Remo watches. Check, in this order:' 'White'
  Line '  1. The baseline itself: Remo was installed from a copy that already served this page (compare with what the scoring check expects).' 'Gray'
  Line '  2. IIS config (bindings, handlers, rewrite/redirect, default document) - not in the baseline if the line above says NO.' 'Gray'
  Line '  3. Another site answering on the same binding (see section 3), or a proxy/rewrite sending requests elsewhere.' 'Gray'
  Line '  4. The scoring check uses a different URL or host name than Remo''s health URL - compare the three URLs in section 2.' 'Gray'
  Line '  Then run  .\Fix-HttpError.ps1 4  (it reads the IIS log and config for the real cause).' 'White'
 }else{Line 'Nothing found. The site returns the expected text right now and Remo is running; recheck the scoreboard.' 'Green'}
}
Write-Host ''
