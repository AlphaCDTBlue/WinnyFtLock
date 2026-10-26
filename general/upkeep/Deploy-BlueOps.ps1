#requires -Version 5.1
#requires -RunAsAdministrator
# Repairable BlueOps deployment. Does not stop/restart any running service.
$ErrorActionPreference='Stop'
$baseDir='C:\BlueOps'
New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
$services=@{AD='NTDS';DNS='DNS';Openfire='openfire';Telnet='inetd';IIS='W3SVC';CA='CertSvc'}
# Keep WRITE_DAC for administrative maintenance. This cannot stop an equivalent admin attacker.
$lockedSDDL='D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRCWD;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)'
$unlockedSDDL='D:(A;;CCLCSWLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRRCWD;;;SY)(A;;CCDCLCSWRPWPDTLOCRRCWD;;;BA)'
function Invoke-BlueOpsSc([string[]]$Items) {
    $out=@(& "$env:SystemRoot\System32\sc.exe" @Items 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($Items -join ' ') failed: $($out -join ' ')" }
    return $out
}
# The older script removed WRITE_DAC even from Administrators. When necessary,
# use the administrator's Take Ownership privilege on this SERVICE object only.
# Original owner/group/DACL are captured below before any change.
if (-not ('BlueOpsServiceRepair' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
public static class BlueOpsServiceRepair {
 [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Id; public uint Attributes; }
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string sys,string name,out LUID id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool all,ref TP state,int size,out TP old,out int required);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr scm,string name,uint access);
 [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceObjectSecurity(IntPtr h,uint info,byte[] data,int size,out int needed);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetServiceObjectSecurity(IntPtr h,uint info,byte[] data);
 static void Fail(){throw new Win32Exception(Marshal.GetLastWin32Error());}
 public static string Capture(string name) {
  IntPtr m=OpenSCManager(null,null,1);if(m==IntPtr.Zero)Fail();
  try {IntPtr h=OpenService(m,name,0x20000);if(h==IntPtr.Zero)Fail();
   try {int needed;QueryServiceObjectSecurity(h,7,null,0,out needed);if(needed<=0)Fail();
    byte[] b=new byte[needed];if(!QueryServiceObjectSecurity(h,7,b,b.Length,out needed))Fail();
    return new RawSecurityDescriptor(b,0).GetSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);
   } finally {CloseServiceHandle(h);}
  } finally {CloseServiceHandle(m);}
 }
 public static void TakeOwnership(string name) {
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))Fail();
  TP old=new TP();bool changed=false;
  try {LUID id;if(!LookupPrivilegeValue(null,"SeTakeOwnershipPrivilege",out id))Fail();
   TP tp=new TP{Count=1,Id=id,Attributes=2};int n;
   if(!AdjustTokenPrivileges(token,false,ref tp,Marshal.SizeOf(typeof(TP)),out old,out n))Fail();
   int error=Marshal.GetLastWin32Error();if(error!=0)throw new Win32Exception(error);changed=true;
   IntPtr m=OpenSCManager(null,null,1);if(m==IntPtr.Zero)Fail();
   try {IntPtr h=OpenService(m,name,0x80000);if(h==IntPtr.Zero)Fail();
    try {var sd=new RawSecurityDescriptor("O:"+WindowsIdentity.GetCurrent().User.Value);
     byte[] b=new byte[sd.BinaryLength];sd.GetBinaryForm(b,0);if(!SetServiceObjectSecurity(h,1,b))Fail();
    } finally {CloseServiceHandle(h);}
   } finally {CloseServiceHandle(m);}
  } finally {if(changed){TP ignored;int n;AdjustTokenPrivileges(token,false,ref old,Marshal.SizeOf(typeof(TP)),out ignored,out n);}CloseHandle(token);}
 }
}
'@
}
$backup=Join-Path $baseDir ('service-repair-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory $backup | Out-Null
Write-Host "Pre-repair descriptors: $backup (keep your original Phase 1 backup too)."
$workerScript = @'
$ErrorActionPreference='Stop'
$requestFile = "C:\BlueOps\request.json"
if (-not (Test-Path $requestFile)) { exit }

$req = Get-Content $requestFile | ConvertFrom-Json
$map = @{ "AD"="NTDS"; "DNS"="DNS"; "Openfire"="openfire"; "Telnet"="inetd"; "IIS"="W3SVC"; "CA"="CertSvc" }
$svcName = $map[$req.Service]

$lockedSDDL = "D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRCWD;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)"
$unlockedSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRRCWD;;;SY)(A;;CCDCLCSWRPWPDTLOCRRCWD;;;BA)"

sc.exe sdset $svcName $unlockedSDDL | Out-Null
if ($LASTEXITCODE) { throw 'Could not unlock service; no control action performed.' }
try {

switch ($req.Action) {
    "Stop"    { Stop-Service -Name $svcName -Force }
    "Start"   { Start-Service -Name $svcName }
    "Restart" { Restart-Service -Name $svcName -Force }
}

} finally {
    sc.exe sdset $svcName $lockedSDDL | Out-Null
    if ($LASTEXITCODE) { throw 'CRITICAL: could not reapply service lock.' }
}
"$(Get-Date -Format u) - $($req.Service) -> $($req.Action) by $(whoami)" | Out-File "C:\BlueOps\audit.log" -Append
Remove-Item $requestFile -Force
'@
$workerScript | Out-File "$baseDir\Svc-Control-Worker.ps1" -Force -Encoding UTF8


foreach ($entry in $services.GetEnumerator()) {
    $svcName=$entry.Value
    $svc=Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Host "[SKIP] $svcName not installed."; continue }
    $original=[BlueOpsServiceRepair]::Capture($svcName)
    Set-Content -LiteralPath (Join-Path $backup "$svcName.security.txt") -Value $original -Encoding ASCII
    $unlockOutput=@(& sc.exe sdset $svcName $unlockedSDDL 2>&1)
    $unlockCode=$LASTEXITCODE
    if ($unlockCode -eq 5) {
        Write-Warning "Old ACL blocks repair of $svcName. Taking ownership of this service object; original descriptor saved."
        [BlueOpsServiceRepair]::TakeOwnership($svcName)
        Invoke-BlueOpsSc -Items @('sdset',$svcName,$unlockedSDDL) | Out-Host
    } elseif ($unlockCode -ne 0) { throw "Could not unlock ${svcName}: $($unlockOutput -join ' ')" }
    try {
        Invoke-BlueOpsSc -Items @('failure',$svcName,'reset=','0','actions=','restart/5000/restart/5000/restart/5000') | Out-Host
        Invoke-BlueOpsSc -Items @('failureflag',$svcName,'1') | Out-Host
        if ($svc.Status -ne 'Running') { Start-Service -Name $svcName -ErrorAction Stop }
        Invoke-BlueOpsSc -Items @('qfailure',$svcName) | Out-Host
        Invoke-BlueOpsSc -Items @('qfailureflag',$svcName) | Out-Host
    } finally {
        # Reapply the restriction even if configuration/start fails.
        Invoke-BlueOpsSc -Items @('sdset',$svcName,$lockedSDDL) | Out-Host
    }
    Write-Host "[OK] $svcName recovery configured; service lock reapplied." -ForegroundColor Green
}
Write-Host 'Deployment complete. Use general\upkeep\Svcwithme.ps1 for deliberate service control.' -ForegroundColor Cyan
