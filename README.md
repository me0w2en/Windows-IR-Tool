# Windows 10/11 Incident Response Triage Script
PowerShell 기반의 Windows 10/11용 Incident Response Triage 자동 수집 스크립트입니다.
KISA(한국인터넷진흥원)의 분석 절차를 기준으로 Windows 10/11 환경에서 주요 IR 관련련 정보를 확인할 수 있도록 구성되었습니다.

---

## Features
### 1. System Snapshot
* OS version, build, install date, uptime, timezone

### 2. Patch & Endpoint Protection
* Installed Hotfixes (latest 8)
* Microsoft Defender status (Real-time protection, signature version, tamper protection, threats)

### 3. User Accounts
* Local `Administrators` group members
* Principal source and object type

### 4. Network
* Listening TCP ports with owning process info
* External established connections (excluding private IP ranges)

### 5. Services & Drivers
* Auto-start and running Windows services
* Signed/Unsigned service binaries
* Auto-start drivers and signature verification

### 6. Auto-Start Artifacts
* Registry: `Run`, `RunOnce` (HKLM/HKCU, WOW6432Node)
* Startup folder programs
* Winlogon: `Shell`, `Userinit`, `GPExtensions`
* IFEO: `Debugger`
* AppInit DLLs
* LSA packages

### 7. Scheduled Tasks
* Hidden tasks
* Suspicious paths (user, temp, appdata)
* Missing or invalid signature detection

### 8. WMI Persistence
* `root\subscription` namespace: EventFilter, CommandLineEventConsumer, FilterToConsumerBinding

### 9. Recent Executables
* Modified within `$RecentHours` in `%TEMP%` and `Downloads` (exe, dll, js, ps1, bat, etc.)

### 10. Event Logs
* Security log events (ID: 4624, 4625, 4672, 4688, 7045)
* Only entries within `$RecentHours`

### 11. RDP & Firewall
* Remote Desktop enabled status
* Windows Firewall profile settings (inbound/outbound)

---

## Usage
### Requirements
* PowerShell 5.1 이상
* **Administrator 권한으로 실행해야 모든 정보가 수집됩니다.**

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
.\windows_IR.ps1
```

### Optional Parameters
| Parameter       | Description                                                   | Default |
| --------------- | ------------------------------------------------------------- | ------- |
| `-RecentHours`  | Defines time range (hours) for event log and recent file scan | 72      |
| `-TopProcesses` | Reserved for future use                                       | 12      |

Example:

```powershell
.\windows_IR.ps1 -RecentHours 48
```

---

## Output Style
* Section headers are clearly marked (e.g., `[ 시스템 정보 ]`)
* Tabular output for list-based artifacts (services, accounts, connections)
* Alerts (e.g., abnormal shell, unsigned binaries) are highlighted in red
* Character encoding is set to UTF-8 to support Korean output

---

## Use Cases
* 침해사고 초기 대응(IR) 시점에서 포렌식 스냅샷 확보
* 악성 행위 의심 시스템의 자동 스크리닝
* 교육용 Windows IR 실습 환경 구성

---

## Reference
* KISA 침해사고 대응 절차 가이드라인
* Microsoft Windows PowerShell / CIM / Defender / WMI 공식 문서
