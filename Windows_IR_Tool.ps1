<#  Windows 10/11 Incident Response Triage - KISA-mapped
    Usage  : .\windows_IR.ps1 [-RecentHours 72] [-TopProcesses 12]
#>

[CmdletBinding()]
param(
    [int]$RecentHours = 72,
    [int]$TopProcesses = 12
)

try {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::InputEncoding  = $utf8
    [Console]::OutputEncoding = $utf8
    $OutputEncoding           = $utf8
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
} catch {}

$ProgressPreference = 'SilentlyContinue'
$Width = 3000

function Write-Title($Text) {
    Write-Host ("`n" + ('=' * 80)) -ForegroundColor DarkCyan
    Write-Host ("[ " + $Text + " ]") -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor DarkCyan
}
function Write-Section($Text) {
    Write-Host ("`n" + $Text) -ForegroundColor Yellow
    Write-Host ('-' * 80) -ForegroundColor DarkYellow
}
function Try-Run([scriptblock]$Block){
    try { & $Block } catch { Write-Host "  ! $_" -ForegroundColor Red }
}
function Extract-Executable([string]$cmd){
    if (-not $cmd) { return $null }
    if ($cmd.StartsWith('"')) { return ($cmd -split '"')[1] }
    return $cmd.Split(' ')[0]
}

# ---------- Admin Check ----------
$IsAdmin = (
    [Security.Principal.WindowsPrincipal](
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "관리자 권한으로 다시 실행하세요 (많은 점검이 제한됩니다)." -ForegroundColor Red
}

# ---------- System Snapshot ----------
Write-Title "Windows IR Snapshot (Win10/11)"

$os  = Get-CimInstance Win32_OperatingSystem
$bt  = $os.LastBootUpTime
$upt = (Get-Date) - $bt
$tz  = (Get-TimeZone).Id

Write-Section "시스템 정보"
[pscustomobject]@{
    Computer    = $env:COMPUTERNAME
    OS          = "$($os.Caption) $($os.Version)"
    Build       = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    InstallDate = $os.InstallDate
    LastBoot    = $bt
    Uptime      = ('{0:dd}d {0:hh}h {0:mm}m' -f $upt)
    TimeZone    = $tz
} | Format-List | Out-String -Width $Width | Write-Host

# ---------- Patch / Defender ----------
Write-Section "패치/엔드포인트 보호"
Try-Run {
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 8 |
      Format-Table -Auto | Out-String -Width $Width | Write-Host
}

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    Try-Run {
        $mp = Get-MpComputerStatus
        [pscustomobject]@{
            RealTimeProtection = $mp.RealTimeProtectionEnabled
            AMServiceEnabled   = $mp.AMServiceEnabled
            EngineVersion      = $mp.AMEngineVersion
            SignaturesUpdated  = $mp.AntispywareSignatureLastUpdated
            TamperProtection   = $mp.IsTamperProtected
        } | Format-Table -Auto | Out-String -Width $Width | Write-Host

        Get-MpThreat | Select-Object -First 10 |
          Format-Table -Auto | Out-String -Width $Width | Write-Host
    }
} else {
    Write-Host "Microsoft Defender 모듈이 없습니다(서버/정책 환경일 수 있음)." -ForegroundColor DarkGray
}

# ---------- Accounts / Groups ----------
Write-Section "계정/그룹(Administrators)"
Try-Run {
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts) {
        $g = Get-LocalGroup -Name 'Administrators' -ErrorAction SilentlyContinue
        if ($g) {
            [pscustomobject]@{ Name = $g.Name; Description = $g.Description } |
              Format-List | Out-String -Width $Width | Write-Host

            Get-LocalGroupMember -Group 'Administrators' |
              Select-Object Name, ObjectClass, PrincipalSource |
              Format-Table -Auto | Out-String -Width $Width | Write-Host
        }
    } else {
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
        $desc = try { $adsi.Description } catch { '' }
        [pscustomobject]@{ Name = 'Administrators'; Description = $desc } |
          Format-List | Out-String -Width $Width | Write-Host

        $members = @()
        foreach ($m in $adsi.psbase.Invoke('Members')) {
            $name = $m.GetType().InvokeMember('Name','GetProperty',$null,$m,$null)
            $cls  = $m.GetType().InvokeMember('Class','GetProperty',$null,$m,$null)
            $path = $m.GetType().InvokeMember('AdsPath','GetProperty',$null,$m,$null)
            $members += [pscustomobject]@{
                Name = $name; ObjectClass = $cls; PrincipalSource = ($path -replace '^WinNT://','')
            }
        }
        $members | Sort-Object Name | Format-Table -Auto |
          Out-String -Width $Width | Write-Host
    }
}

# ---------- Network ----------
Write-Section "네트워크(리스닝/세션-프로세스 매핑)"
Try-Run {
    $procs = Get-Process | Select-Object Id, ProcessName, Path
    Get-NetTCPConnection -State Listen |
        ForEach-Object {
            $p = $procs | Where-Object Id -eq $_.OwningProcess
            [pscustomobject]@{
                LAddr = "$($_.LocalAddress):$($_.LocalPort)"
                State = $_.State
                Proc  = if($p){$p.ProcessName}else{$_.OwningProcess}
                Path  = if($p){$p.Path}else{''}
            }
        } | Sort-Object LAddr | Format-Table -Auto |
        Out-String -Width $Width | Write-Host
}
Try-Run {
    Get-NetTCPConnection -State Established |
      Where-Object { $_.RemoteAddress -and ($_.RemoteAddress -notmatch '^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') } |
      Select-Object -First 25 |
      ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Remote = "$($_.RemoteAddress):$($_.RemotePort)"
            Local  = "$($_.LocalAddress):$($_.LocalPort)"
            Proc   = if($p){$p.ProcessName}else{$_.OwningProcess}
        }
      } | Format-Table -Auto | Out-String -Width $Width | Write-Host
}

# ---------- Services Audit ----------
Write-Section "서비스(자동 시작+실행 중·서명 상태)"
Try-Run {
    $svcs = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' }
    $rows = foreach($s in $svcs){
        $exe = Extract-Executable $s.PathName
        $sigState = 'N/A'; $pub = ''
        if ($exe -and (Test-Path $exe)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop
                $sigState = $sig.Status
                $pub = $sig.SignerCertificate.Subject
            } catch { $sigState = 'Error' }
        }
        [pscustomobject]@{
            Name=$s.Name; Display=$s.DisplayName; State=$s.State; Start=$s.StartMode
            Binary=$exe; SigStatus=$sigState; Publisher=$pub
        }
    }
    $rows | Sort-Object {$_.SigStatus -ne 'Valid'}, Name |
        Select-Object -First 60 |
        Format-Table Name,State,Start, SigStatus, @{n='Binary';e={$_.Binary}} -Auto |
        Out-String -Width $Width | Write-Host
}

# ---------- Drivers (Kernel) ----------
Write-Section "드라이버(자동 시작·실행 중·서명)"
Try-Run {
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' } |
      Select-Object -First 50 |
      ForEach-Object {
          $exe = Extract-Executable $_.PathName
          $sigState='N/A'
          if ($exe -and (Test-Path $exe)) {
            try { $sigState = (Get-AuthenticodeSignature $exe).Status } catch {}
          }
          [pscustomobject]@{ Name=$_.Name; Display=$_.DisplayName; State=$_.State; SigStatus=$sigState; Binary=$exe }
      } | Format-Table -Auto | Out-String -Width $Width | Write-Host
}

# ---------- Autoruns Equivalents ----------
Write-Section "Autoruns(레지스트리 Run/RunOnce/시작폴더)"
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach($rk in $runKeys){
    Try-Run {
        if (Test-Path $rk) {
            Write-Host "[$rk]" -ForegroundColor Cyan
            Get-ItemProperty $rk | Select-Object -ExcludeProperty PS* |
              ForEach-Object {
                $_.PSObject.Properties |
                  Where-Object { $_.Name -notmatch '^PS' } |
                  ForEach-Object { "{0,-30} {1}" -f $_.Name, $_.Value }
              } | Out-String -Width $Width | Write-Host
        }
    }
}
Try-Run {
    Write-Host "[Startup Folders]" -ForegroundColor Cyan
    $startups = @(
      "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
      "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach($sp in $startups){
        if (Test-Path $sp) {
            Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue |
              Select-Object FullName, LastWriteTime | Format-Table -Auto |
              Out-String -Width $Width | Write-Host
        }
    }
}

# Winlogon / IFEO / AppInit / LSA Packages
Write-Section "Winlogon/IFEO/AppInit/LSA 패키지"
Try-Run {
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $wl) {
        $wlp = Get-ItemProperty $wl
        [pscustomobject]@{
            Shell    = $wlp.Shell
            Userinit = $wlp.Userinit
            GPExtensions = $wlp.GPExtensions
        } | Format-List | Out-String -Width $Width | Write-Host
        if ($wlp.Shell -and $wlp.Shell -notlike 'explorer.exe*') {
            Write-Host "  * 비정상 Shell 값 감지" -ForegroundColor Red
        }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue |
          ForEach-Object {
             $dbg = (Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue).Debugger
             if ($dbg) { "{0,-30} Debugger = {1}" -f $_.PSChildName, $dbg }
          } | Out-String -Width $Width | Write-Host
    }
    $win = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    if (Test-Path $win) {
        $appinit = (Get-ItemProperty $win -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($appinit) { "AppInit_DLLs = $appinit" | Write-Host }
    }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path $lsa) {
        $p = Get-ItemProperty $lsa
        "Authentication Packages: $($p.'Authentication Packages')" | Write-Host
        "Security Packages      : $($p.'Security Packages')" | Write-Host
        "Notification Packages  : $($p.'Notification Packages')" | Write-Host
    }
}

# Scheduled Tasks (refined suspicious logic)
Write-Section "스케줄러(숨김·사용자/Temp 경로·서명 비정상)"
Try-Run {
    Get-ScheduledTask | ForEach-Object {
        $ti = $_ | Get-ScheduledTaskInfo
        $acts = (Get-ScheduledTask $_.TaskName -TaskPath $_.TaskPath).Actions
        foreach($a in $acts){
            $exec = ($a.Execute + ' ' + $a.Arguments).Trim()
            $bin  = Extract-Executable $exec
            $sig  = 'N/A'
            if ($bin -and (Test-Path $bin)) {
                try { $sig = (Get-AuthenticodeSignature $bin).Status } catch {}
            } elseif ($bin) { $sig = 'Missing' }

            $sus = $false
            if ($_.Settings.Hidden) { $sus = $true }
            if ($bin -match '\\Users\\|\\AppData\\|\\Temp\\') { $sus = $true }
            if ($sig -ne 'Valid' -and $bin) { $sus = $true }

            [pscustomobject]@{
                Task       = ($_.TaskPath + $_.TaskName)
                LastRun    = $ti.LastRunTime
                NextRun    = $ti.NextRunTime
                Exec       = $exec
                Hidden     = $_.Settings.Hidden
                SigStatus  = $sig
                Suspicious = $sus
            }
        }
    } |
    Where-Object { $_.Hidden -or $_.Suspicious } |
    Sort-Object -Property Suspicious, LastRun -Descending |
    Select-Object -First 60 |
    Format-Table -Auto | Out-String -Width $Width | Write-Host
}

# ---------- WMI Eventing Persistence ----------
Write-Section "WMI 영속성(ROOT\subscription)"
Try-Run {
    $ns='root\subscription'
    $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue
    $cons    = Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $binds   = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    $filters | Select-Object Name,Query,EventNamespace | Format-Table -Auto | Out-String -Width $Width | Write-Host
    $cons    | Select-Object Name,CommandLineTemplate,WorkingDirectory | Format-Table -Auto | Out-String -Width $Width | Write-Host
    $binds   | Select-Object Filter, Consumer | Format-Table -Auto | Out-String -Width $Width | Write-Host
}

# ---------- Recent Files (Temp/Downloads) ----------
Write-Section "최근 파일(Temp/Downloads - *.exe/*.dll 등, 최근 $RecentHours 시간)"
Try-Run {
    $since = (Get-Date).AddHours(-$RecentHours)
    $paths = @("$env:TEMP","$env:USERPROFILE\Downloads")
    foreach($p in $paths){
        if (Test-Path $p){
            Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
              Where-Object { $_.LastWriteTime -ge $since -and $_.Extension -match '\.(exe|dll|ps1|js|vbs|hta|bat|cmd)$' } |
              Select-Object FullName, Length, LastWriteTime |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 50 |
              Format-Table -Auto | Out-String -Width $Width | Write-Host
        }
    }
}

# ---------- Event Logs ----------
Write-Section "이벤트 로그(최근 $RecentHours 시간: 로그인/권한상승/서비스 설치/프로세스 생성)"
Try-Run {
    $start = (Get-Date).AddHours(-$RecentHours)
    $ids = 4624,4625,4672,4688,7045
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=$ids} -ErrorAction SilentlyContinue |
      Select-Object TimeCreated, Id, ProviderName, @{n='Msg';e={$_.Message.Substring(0,[Math]::Min(160,$_.Message.Length))}} |
      Sort-Object TimeCreated -Descending | Select-Object -First 50 |
      Format-Table -Auto | Out-String -Width $Width | Write-Host
}

# ---------- RDP/Firewall (fixed if-statement) ----------
Write-Section "원격접속/방화벽 상태"
Try-Run {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    $rdpEnabled = if ($deny -eq 0) { 'Yes' } else { 'No' }
    Write-Host ("RDP Enabled?: " + $rdpEnabled)
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction, DefaultInboundAction |
      Format-Table -Auto | Out-String -Width $Width | Write-Host
}

Write-Host "`n완료." -ForegroundColor Green
