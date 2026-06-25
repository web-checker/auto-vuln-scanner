<#
=====================================================================
 Windows 서버 자동 진단 스크립트 (PowerShell)
   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 - Windows(W-01~W-64)
   대상: Windows Server 2019 (2016/2022 호환)

   - 읽기 전용: secedit /export(임시 INF, 변경 안 함)·레지스트리 조회·net·Get-* 만 사용.
   - 판정값: 양호 / 취약 / N/A 3가지만.
   - 출력: 항목별 구조화(콘솔) + 보고서(TXT) + 로우데이터(CSV).
   - 일부 판단은 자동화 한계로 'N/A(수동 확인)' 표기(근거 제공).

   사용법(관리자 PowerShell):
     powershell -ExecutionPolicy Bypass -File .\win_diag.ps1
     (옵션) -ConfigFile .\win_diag.conf.ps1  -OutputDir .\win_diag_result
=====================================================================
#>
param(
    [string]$ConfigFile = (Join-Path $PSScriptRoot 'win_diag.conf.ps1'),
    [string]$OutputDir
)
$ErrorActionPreference = 'SilentlyContinue'

# ── 콘솔/출력 한글 인코딩 강제(UTF-8) ─────────────────────
# RDP/서버 환경에서 콘솔 코드페이지가 한글과 맞지 않아 '???'로 깨지는 문제 방지.
try { chcp 65001 > $null } catch {}
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding           = [System.Text.Encoding]::UTF8
} catch {}

$PASS='양호'; $VULN='취약'; $NA='N/A'

if (-not (Test-Path $ConfigFile)) { Write-Error "설정 파일 없음: $ConfigFile"; exit 1 }
. $ConfigFile
if ($OutputDir) { $Conf.OutputDir = $OutputDir }

# ── 메타/환경 ────────────────────────────────────────────
# 점검 시각 KST 고정 (서버 TZ가 무엇이든 한국시간으로 기록)
$kstNow = try { [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTime]::UtcNow, 'Korea Standard Time') } catch { Get-Date }
$TS     = $kstNow.ToString('yyyy-MM-dd HH:mm:ss')
$TSFile = $kstNow.ToString('yyyyMMdd_HHmmss')
$HostN  = $env:COMPUTERNAME
$Label  = if ($Conf.TargetLabel) { $Conf.TargetLabel } else { $HostN }
$osReg  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
# OS명: 레지스트리=로컬에서 가장 확실(WMI/CIM 불능 컨텍스트에서도 동작) → CIM/WMI는 보강용
$OS     = $osReg.ProductName
if (-not $OS) { $OS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption }
if (-not $OS) { $OS = (Get-WmiObject  Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption }
if (-not $OS) { $OS = 'Windows (확인불가)' }
$OSVer  = [string][System.Environment]::OSVersion.Version
if ($osReg.CurrentBuildNumber) { $OSVer = "$OSVer (Build $($osReg.CurrentBuildNumber).$($osReg.UBR))" }
$IP     = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
           Select-Object -First 1).IPAddress
if (-not $IP) { $IP = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
           Where-Object { $_.IPEnabled -and $_.IPAddress } |
           ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '127.*' -and $_ -notlike '169.254.*' })[0] }
# WMI 불능 + 로케일 무관 폴백(.NET DNS)
if (-not $IP) { $IP = (try { [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) } catch { @() } |
           Where-Object { $_.AddressFamily -eq 'InterNetwork' -and "$_" -notlike '127.*' -and "$_" -notlike '169.254.*' } |
           Select-Object -First 1).IPAddressToString }
# 최종 폴백: ipconfig (한글 "IPv4 주소" 줄에서 IP만 추출, "(기본 설정)" 등 꼬리 제거)
if (-not $IP) { $IP = ((ipconfig) -match 'IPv4' | ForEach-Object { if ($_ -match '(\d+\.\d+\.\d+\.\d+)') { $matches[1] } } | Where-Object { $_ -notlike '127.*' -and $_ -notlike '169.254.*' } | Select-Object -First 1) }
if (-not (Test-Path $Conf.OutputDir)) { New-Item -ItemType Directory -Path $Conf.OutputDir -Force | Out-Null }
$RawCsv = Join-Path $Conf.OutputDir "win_diag_raw_${Label}_${TSFile}.csv"
$History = Join-Path $Conf.OutputDir "win_diag_history_${Label}_${TSFile}.txt"

# ── 항목 메타 (코드→중요도/분류/이름) ────────────────────
$Codes = 1..64 | ForEach-Object { 'W-{0:D2}' -f $_ }
$Meta = @{}
function M($c,$sev,$cat,$name){ $Meta[$c]=@{Sev=$sev;Cat=$cat;Name=$name} }
M 'W-01' 상 계정관리 'Administrator 계정 이름 변경 등 보안성 강화'
M 'W-02' 상 계정관리 'Guest 계정 비활성화'
M 'W-03' 상 계정관리 '불필요한 계정 제거'
M 'W-04' 상 계정관리 '계정 잠금 임계값 설정'
M 'W-05' 상 계정관리 '해독 가능한 암호화를 사용하여 암호 저장 해제'
M 'W-06' 상 계정관리 '관리자(Administrators) 그룹에 최소한의 사용자 포함'
M 'W-07' 상 계정관리 'Everyone 사용 권한을 익명 사용자에게 적용 해제'
M 'W-08' 중 계정관리 '계정 잠금 기간 설정'
M 'W-09' 상 계정관리 '비밀번호 관리정책 설정'
M 'W-10' 중 계정관리 '마지막 사용자 이름 표시 안 함'
M 'W-11' 중 계정관리 '로컬 로그온 허용 제한'
M 'W-12' 중 계정관리 '익명 SID/이름 변환 허용 해제'
M 'W-13' 상 계정관리 '콘솔 로그온 시 로컬 계정 빈 암호 사용 제한'
M 'W-14' 중 계정관리 '원격터미널 접속 가능 사용자 그룹 제한'
M 'W-15' 상 서비스관리 '사용자 개인키 사용 시 암호 입력'
M 'W-16' 상 서비스관리 '공유 권한 및 사용자 그룹 설정'
M 'W-17' 상 서비스관리 '하드디스크 기본 공유 제거'
M 'W-18' 상 서비스관리 '불필요한 서비스 제거'
M 'W-19' 상 서비스관리 '불필요한 IIS 서비스 구동 점검'
M 'W-20' 상 서비스관리 'NetBIOS 바인딩 서비스 구동 점검'
M 'W-21' 상 서비스관리 '암호화되지 않는 FTP 서비스 비활성화'
M 'W-22' 상 서비스관리 'FTP 디렉터리 접근권한 설정'
M 'W-23' 상 서비스관리 '공유 서비스에 대한 익명 접근 제한 설정'
M 'W-24' 상 서비스관리 'FTP 접근 제어 설정'
M 'W-25' 상 서비스관리 'DNS Zone Transfer 설정'
M 'W-26' 상 서비스관리 'RDS(Remote Data Services) 제거'
M 'W-27' 상 서비스관리 '최신 Windows OS Build 버전 적용'
M 'W-28' 중 서비스관리 '터미널 서비스 암호화 수준 설정'
M 'W-29' 중 서비스관리 '불필요한 SNMP 서비스 구동 점검'
M 'W-30' 중 서비스관리 'SNMP Community String 복잡성 설정'
M 'W-31' 중 서비스관리 'SNMP Access control 설정'
M 'W-32' 중 서비스관리 'DNS 서비스 구동 점검'
M 'W-33' 하 서비스관리 'HTTP/FTP/SMTP 배너 차단'
M 'W-34' 중 서비스관리 'Telnet 서비스 비활성화'
M 'W-35' 중 서비스관리 '불필요한 ODBC/OLE-DB 데이터 소스와 드라이버 제거'
M 'W-36' 중 서비스관리 '원격터미널 접속 타임아웃 설정'
M 'W-37' 상 서비스관리 '예약된 작업에 의심스러운 명령 등록 점검'
M 'W-38' 상 패치관리 '주기적 보안 패치 및 벤더 권고사항 적용'
M 'W-39' 상 패치관리 '백신 프로그램 업데이트'
M 'W-40' 중 로그관리 '정책에 따른 시스템 로깅 설정'
M 'W-41' 중 로그관리 'NTP 및 시각 동기화 설정'
M 'W-42' 하 로그관리 '로그 관리 설정'
M 'W-43' 중 로그관리 '이벤트 로그 파일 접근 통제 설정'
M 'W-44' 상 보안관리 '원격으로 액세스할 수 있는 레지스트리 경로 제한'
M 'W-45' 상 보안관리 '백신 프로그램 설치'
M 'W-46' 상 보안관리 'SAM 파일 접근 통제 설정'
M 'W-47' 상 보안관리 '화면보호기 설정'
M 'W-48' 상 보안관리 '로그온하지 않고 시스템 종료 허용 해제'
M 'W-49' 상 보안관리 '원격 시스템에서 강제로 시스템 종료 제한'
M 'W-50' 상 보안관리 '보안 감사를 로그할 수 없는 경우 즉시 시스템 종료'
M 'W-51' 상 보안관리 'SAM 계정과 공유의 익명 열거 허용 안 함'
M 'W-52' 상 보안관리 'Autologon 기능 제어'
M 'W-53' 상 보안관리 '이동식 미디어 포맷 및 꺼내기 허용 제한'
M 'W-54' 상 보안관리 'DoS 공격 방어 레지스트리 설정'
M 'W-55' 중 보안관리 '사용자가 프린터 드라이버를 설치할 수 없게 함'
M 'W-56' 중 보안관리 'SMB 세션 중단 관리 설정'
M 'W-57' 하 보안관리 '로그온 시 경고 메시지 설정'
M 'W-58' 중 보안관리 '사용자별 홈 디렉터리 권한 설정'
M 'W-59' 중 보안관리 'LAN Manager 인증 수준'
M 'W-60' 중 보안관리 '보안 채널 데이터 디지털 암호화 또는 서명'
M 'W-61' 중 보안관리 '파일 및 디렉터리 보호'
M 'W-62' 중 보안관리 '시작프로그램 목록 분석'
M 'W-63' 중 보안관리 '도메인 컨트롤러 사용자 시간 동기화'
M 'W-64' 중 보안관리 '윈도우 방화벽 설정'

# ── KISA 판단기준(원문) W-01~64 ── (02_Windows_서버.pdf 양호/취약 원문, 판단기준 필드용)
$Std=@{}
$Std['W-01']=@{P='Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우';V='Administrator 기본 계정 이름을 변경하지 않거나 단순 비밀번호를 적용한 경우'}
$Std['W-02']=@{P='Guest 계정이 비활성화되어 있는 경우';V='Guest 계정이 활성화되어 있는 경우'}
$Std['W-03']=@{P='불필요한 계정이 존재하지 않는 경우';V='불필요한 계정이 존재하는 경우'}
$Std['W-04']=@{P='계정 잠금 임계값이 5 이하의 값으로 설정된 경우';V='계정 잠금 임계값이 5 초과의 값으로 설정된 경우'}
$Std['W-05']=@{P='“해독 가능한 암호화를 사용하여 암호 저장” 정책이 “사용 안 함”으로 설정된 경우';V='“해독 가능한 암호화를 사용하여 암호 저장” 정책이 “사용”으로 설정된 경우'}
$Std['W-06']=@{P='Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않 는 경우';V='Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우'}
$Std['W-07']=@{P='“Everyone 사용 권한을 익명 사용자에게 적용” 정책이 “사용 안 함”으로 되어 있는 경우';V='“Everyone 사용 권한을 익명 사용자에게 적용” 정책이 “사용”으로 되어 있는 경우'}
$Std['W-08']=@{P='“계정 잠금 기간” 및 “계정 잠금 기간 원래대로 설정 기간”이 60분 이상으로 설정된 경우';V='“계정 잠금 기간” 및 “잠금 기간 원래대로 설정 기간”이 설정되지 않거나 60분 미만으로 설정된 경우'}
$Std['W-09']=@{P='계정 비밀번호 관리 정책이 모두 적용된 경우';V='계정 비밀번호 관리 정책이 모두 적용되어 있지 않은 경우'}
$Std['W-10']=@{P='“마지막 사용자 이름 표시 안 함”이 “사용”으로 설정된 경우';V='“마지막 사용자 이름 표시 안 함”이 “사용 안 함”으로 설정된 경우'}
$Std['W-11']=@{P='로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하는 경우';V='로컬 로그온 허용 정책에 Administrators, IUSR_ 외 다른 계정 및 그룹이 존재하는 경우'}
$Std['W-12']=@{P='“익명 SID/이름 변환 허용” 정책이 “사용 안 함”으로 설정된 경우';V='“익명 SID/이름 변환 허용” 정책이 “사용”으로 설정된 경우'}
$Std['W-13']=@{P='“콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책이 “사용”인 경우';V='“콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책이 “사용 안 함”인 경우'}
$Std['W-14']=@{P='(관리자 계정을 제외한) 원격 접속이 가능한 계정을 생성하여 타 사용자의 원격 접속을 제한하고, 원격 접속 사용자 그룹에 불필요한 계정이 등록되어 있지 않은 경우';V='(관리자 계정을 제외한) 원격 접속이 가능한 별도의 계정이 존재하지 않는 경우'}
$Std['W-15']=@{P='사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우';V='사용자 개인 키를 사용할 때마다 암호 입력을 받지 않는 경우'}
$Std['W-16']=@{P='일반 공유 디렉터리가 없거나 공유 디렉터리 접근 권한에 Everyone 권한이 없는 경우';V='일반 공유 디렉터리의 접근 권한에 Everyone 권한이 있는 경우'}
$Std['W-17']=@{P='레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 0이며 기본 공유가 존재하지 않 는 경우';V='레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 1이거나 기본 공유가 존재하는 경우'}
$Std['W-18']=@{P='일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우';V='일반적으로 불필요한 서비스(아래 목록 참조)가 구동 중인 경우'}
$Std['W-19']=@{P='IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 IIS 서비스를 사용하는 경우';V='IIS 서비스를 불필요하게 사용하는 경우'}
$Std['W-20']=@{P='TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우';V='TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있지 않은 경우'}
$Std['W-21']=@{P='FTP 서비스를 사용하지 않는 경우 또는 Secure FTP 서비스를 사용하는 경우';V='암호화되지 않는 FTP 서비스를 사용하는 경우'}
$Std['W-22']=@{P='FTP 홈 디렉터리에 Everyone 권한이 없는 경우';V='FTP 홈 디렉터리에 Everyone 권한이 있는 경우'}
$Std['W-23']=@{P='공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우';V='공유 서비스를 사용하거나, 익명 인증 사용함으로 설정된 경우'}
$Std['W-24']=@{P='특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우';V='특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용하지 않는 경우'}
$Std['W-25']=@{P='아래 기준에 해당하는 경우 1. DNS 서비스가 비활성화인 경우 2. 영역 전송 허용을 하지 않는 경우 3. 특정 서버로만 설정이 되어있는 경우';V='위 3개 기준 중 하나라도 해당하지 않는 경우'}
$Std['W-26']=@{P='다음 중 한 가지라도 해당하는 경우 1. IIS를 사용하지 않는 경우 2. Windows 2008 이상 버전을 사용하는 경우 3. Windows 2000 서비스팩 4, Windows 2003 서비스팩 2 이상 설치된 경우 4. 기본 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우 5. 해당 레지스트리 값이 존재하지 않는 경우';V='양호 기준에 한 가지도 해당하지 않는 경우'}
$Std['W-27']=@{P='최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우';V='최신 Build가 설치되지 않거나, 적용 절차 및 방법이 수립되지 않은 경우'}
$Std['W-28']=@{P='원격 데스크톱 서비스를 사용하지 않거나 사용 시 암호화 수준을 “클라이언트와 호환 가능(중간)” 이상으로 설정한 경우';V='원격 데스크톱 서비스를 사용하고 암호화 수준이 “낮음”으로 설정한 경우'}
$Std['W-29']=@{P='SNMP 서비스를 사용하지 않는 경우 또는 Community String을 설정하여 SNMP 서비스를 사용하는 경우';V='불필요하게 SNMP 서비스를 사용하는 경우'}
$Std['W-30']=@{P='SNMP 서비스를 사용하지 않거나 Community String이 public, private 이 아닌 경우';V='SNMP 서비스를 사용하며, Community String이 public, private인 경우'}
$Std['W-31']=@{P='SNMP 서비스를 사용하지 않거나 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우';V='모든 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우'}
$Std['W-32']=@{P='DNS 서비스를 사용하지 않거나 동적 업데이트 “없음(아니오)”으로 설정된 경우';V='서비스를 사용하며 동적 업데이트가 설정된 경우'}
$Std['W-33']=@{P='HTTP, FTP, SMTP 접속 시 배너 정보가 보이지 않는 경우';V='HTTP, FTP, SMTP 접속 시 배너 정보가 보이는 경우'}
$Std['W-34']=@{P='Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우';V='Telnet 서비스가 구동되어 있으며 인증 방법이 NTLM이 아닌 경우'}
$Std['W-35']=@{P='시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우';V='시스템 DSN 부분의 데이터 소스를 현재 사용하고 있지 않은 경우'}
$Std['W-36']=@{P='원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우';V='원격 제어 시 Timeout 제어 설정을 적용하지 않거나 30분 초과로 설정한 경우'}
$Std['W-37']=@{P='불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우';V='불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하지 않거나, 불필 요한 작업을 제거하지 않은 경우'}
$Std['W-38']=@{P='패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우';V='패치 절차가 수립되어 있지 않거나 주기적으로 패치를 설치하지 않는 경우'}
$Std['W-39']=@{P='바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우';V='바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우'}
$Std['W-40']=@{P='감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우';V='감사 정책 권고 기준에 따라 감사 설정이 되어 있지 않은 경우'}
$Std['W-41']=@{P='NTP 및 시각 동기화를 설정한 경우';V='NTP 및 시각 동기화를 설정하지 않은 경우'}
$Std['W-42']=@{P='최대 로그 크기 “10,240KB 이상”으로 설정, “90일 이후 이벤트 덮어씀”을 설정한 경우';V='최대 로그 크기 “10,240KB 미만”으로 설정, 이벤트 덮어씀 기간이 “90일 이하로 설정된 경우'}
$Std['W-43']=@{P='로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우';V='로그 디렉터리의 접근 권한에 Everyone 권한이 있는 경우'}
$Std['W-44']=@{P='Remote Registry Service가 중지된 경우';V='Remote Registry Service가 사용 중인 경우'}
$Std['W-45']=@{P='바이러스 백신 프로그램이 설치된 경우';V='바이러스 백신 프로그램이 설치되어 있지 않은 경우'}
$Std['W-46']=@{P='SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정된 경우';V='SAM 파일 접근 권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정된 경우'}
$Std['W-47']=@{P='화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우';V='화면 보호기가 설정되지 않았거나 암호를 사용하지 않거나, 화면 보호기 대기 시간이 10분을 초과한 값으로 설정된 경우'}
$Std['W-48']=@{P='“로그온하지 않고 시스템 종료 허용”이 “사용 안 함”으로 설정된 경우';V='“로그온하지 않고 시스템 종료 허용”이 “사용”으로 설정된 경우'}
$Std['W-49']=@{P='“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators”만 존재하는 경우';V='“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators” 외 다른 계정 및 그룹이 존재하 는 경우'}
$Std['W-50']=@{P='“보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책이 “사용 안 함”으로 되어있는 경우';V='“보안 감사를 로그 할 수 없는 경우'}
$Std['W-51']=@{P='“SAM 계정과 공유의 익명 열거 허용 안 함”이 “사용”으로 설정된 경우';V='“SAM 계정과 공유의 익명 열거 허용 안 함”이 “사용 안 함”으로 설정된 경우'}
$Std['W-52']=@{P='AutoAdminLogon 값이 없거나 0으로 설정된 경우';V='AutoAdminLogon 값이 1로 설정된 경우'}
$Std['W-53']=@{P='“이동식 미디어 포맷 및 꺼내기 허용” 정책이 “Administrators”로 되어있는 경우';V='“이동식 미디어 포맷 및 꺼내기 허용” 정책이 “Administrators”로 되어있지 않은 경우'}
$Std['W-54']=@{P='아래 4가지 DoS 방어 레지스트리를 설정한 경우 Ÿ SynAttackProtect → 1이상 Ÿ EnableDeadGWDetect → 0 Ÿ KeepAliveTime → 300,000 Ÿ NoNameReleaseOnDemand → 1';V='DoS 방어 레지스트리 값이 설정되어 있지 않은 경우'}
$Std['W-55']=@{P='“사용자가 프린터 드라이버를 설치할 수 없게 함” 정책이 “사용”인 경우';V='“사용자가 프린터 드라이버를 설치할 수 없게 함” 정책이 “사용 안 함”인 경우'}
$Std['W-56']=@{P='“로그온 시간이 만료되면 클라이언트 연결 끊기” 정책을 “사용”으로, “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책을 “15분” 이하로 설정한 경우';V='“로그온 시간이 만료되면 클라이언트 연결 끊기” 정책이 “사용 안 함” 또는 “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책이 “15분” 초과로 설정한 경우'}
$Std['W-57']=@{P='로그인 경고 메시지 제목 및 내용이 설정된 경우';V='로그인 경고 메시지 제목 및 내용이 설정되어 있지 않은 경우'}
$Std['W-58']=@{P='홈 디렉터리에 Everyone 권한이 없는 경우 (All Users, Default User 디렉터리 제외)';V='홈 디렉터리에 Everyone 권한이 있는 경우'}
$Std['W-59']=@{P='"LAN Manager 인증 수준" 정책에 "NTLMv2 응답만 보냄"이 설정되어 있는 경우';V='"LAN Manager 인증 수준" 정책에 "LM" 및 "NTLM"인증이 설정되어 있는 경우'}
$Std['W-60']=@{P='아래 3가지 정책 모두 “사용"으로 되어있는 경우 Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우) Ÿ 도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)';V='아래 3가지 정책 중 일부가 "사용 안 함"으로 되어있는 경우'}
$Std['W-61']=@{P='NTFS 파일 시스템을 사용하는 경우';V='FAT 파일 시스템을 사용하는 경우'}
$Std['W-62']=@{P='시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우';V='시작 프로그램 목록을 정기적으로 검사하지 않고, 부팅 시 불필요한 서비스도 실행되고 있는 경우'}
$Std['W-63']=@{P='컴퓨터 시계 동기화 최대 허용 오차값이 5분 이하인 경우';V='컴퓨터 시계 동기화 최대 허용 오차값이 5분 초과인 경우'}
$Std['W-64']=@{P='Windows 방화벽 “사용”으로 설정된 경우';V='Windows 방화벽 “사용 안 함”으로 설정된 경우'}

# ── KISA 조치 방법(원문) W-01~64 ── (02_Windows_서버.pdf '조치 방법' 절 발췌, 조치방법 필드용)
# 각 항목코드별 권고 조치를 하드코딩한다. 결과(양호/취약/N/A)와 무관하게 항목 기준값으로 채운다.
$Remed=@{}
$Remed['W-01']='Administrator 기본 계정 이름 변경 및 보안성이 있는 비밀번호 설정'
$Remed['W-02']='Guest 계정 비활성화'
$Remed['W-03']='현재 계정 현황 확인 후 불필요한 계정 삭제'
$Remed['W-04']='계정 잠금 임계값을 5 이하의 값으로 설정'
$Remed['W-05']='“해독 가능한 암호화를 사용하여 암호 저장”을 “사용 안 함”으로 설정'
$Remed['W-06']='Administrators 그룹에 포함된 불필요한 계정 제거'
$Remed['W-07']='“Everyone 사용 권한을 익명 사용자에게 적용” 정책을 “사용 안 함”으로 설정'
$Remed['W-08']='“계정 잠금 기간” 및 “잠금 기간 원래대로 설정 기간”을 60분 이상으로 설정'
$Remed['W-09']='비밀번호 복잡성, 최소 비밀번호 길이, 최대/최소 사용 기간을 기준에 맞게 설정'
$Remed['W-10']='Windows NT: “마지막으로 로그온한 사용자 이름 표시 안 함” 설정 / Windows 2000: “로그온 스크린에 마지막 사용자 이름 표시 안 함” 사용 설정 / Windows 2003·2008·2012·2016·2019·2022: “대화형 로그온: 마지막 사용자 이름 표시 안 함” 사용 설정'
$Remed['W-11']='로컬 로그온 허용 정책에서 Administrators, IUSR_ 외 다른 계정 및 그룹 제거(로컬 로그온 제한)'
$Remed['W-12']='“네트워크 액세스: 익명 SID/이름 변환 허용” 정책을 “사용 안 함”으로 설정'
$Remed['W-13']='“계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책을 “사용”으로 설정'
$Remed['W-14']='관리자 계정과 별도로 원격 접속용 계정을 생성하고 권한을 제한 사용하도록 설정'
$Remed['W-15']='“시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용” 정책을 “키를 사용할 때마다 암호를 매번 입력해야 함”으로 적용'
$Remed['W-16']='공유 디렉터리 접근 권한에서 Everyone 권한 제거 후 필요한 계정 추가'
$Remed['W-17']='기본 공유 중지 후 레지스트리 값 설정(IPC$, 일반 공유 제외)'
$Remed['W-18']='불필요한 서비스 중지 후 “사용 안 함”으로 설정'
$Remed['W-19']='IIS 서비스가 불필요한 경우 IIS 서비스 중지'
$Remed['W-20']='네트워크 제어판을 이용하여 TCP/IP와 NetBIOS 간의 바인딩(binding) 제거'
$Remed['W-21']='FTP 서비스가 필요하지 않다면 서비스 중지 또는 Secure FTP 응용 프로그램 사용'
$Remed['W-22']='FTP 홈 디렉터리에서 Everyone 권한 삭제, 각 사용자에게 적절한 권한 부여'
$Remed['W-23']='공유 서비스를 사용하지 않는 경우 서비스 중지, 사용할 경우 익명 인증 사용 안 함 설정 적용'
$Remed['W-24']='특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정'
$Remed['W-25']='불필요 시 서비스 중지/사용 안 함 설정, 사용하는 경우 영역 전송을 특정 서버로 제한하거나 “영역 전송 허용”에 체크 해제'
$Remed['W-26']='사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용할 경우 레지스트리 키 값 제거 또는 관련 패치 적용'
$Remed['W-27']='설치에 따른 영향도 확인 후 최신 Build 설치(설치 후 시스템 재시작 필요)'
$Remed['W-28']='원격 데스크톱 서비스의 가동을 “중지” 및 “사용 안 함”으로 설정하거나, 부득이하게 사용할 경우 암호화 수준 설정 적용'
$Remed['W-29']='불필요 시 서비스 중지/사용 안 함'
$Remed['W-30']='불필요 시 서비스 중지/사용 안 함, 사용 시 기본 Community String(public, private) 변경'
$Remed['W-31']='불필요 시 서비스 중지/사용 안 함, 사용 시 SNMP 패킷 수령 호스트를 특정 호스트로 지정'
$Remed['W-32']='DNS 서비스의 동적 업데이트 비활성화 설정'
$Remed['W-33']='사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용 시 배너 정보 노출 관련 속성값 수정'
$Remed['W-34']='불필요 시 서비스 중지/사용 안 함 설정, 사용 시 인증 방법으로 NTLM만 사용'
$Remed['W-35']='사용하지 않는 불필요한 ODBC 데이터 소스 제거'
$Remed['W-36']='원격 제어 시 Timeout 제어 설정 적용(30분 이하)'
$Remed['W-37']='예약 작업에 대한 주기적인 확인 및 불필요한 작업 제거'
$Remed['W-38']='주기적인 보안 패치 확인 및 설치 적용'
$Remed['W-39']='백신 프로그램 환경설정 메뉴를 통해 DB 및 엔진의 최신 업데이트를 하도록 설정'
$Remed['W-40']='감사 정책 권고 기준에 따라 이벤트에 대한 감사 설정'
$Remed['W-41']='NTP 및 시각 동기화 설정'
$Remed['W-42']='최대 로그 크기 “10,240KB 이상”, “90일 이후 이벤트 덮어씀” 설정'
$Remed['W-43']='로그 디렉터리의 접근 권한에서 Everyone 제거'
$Remed['W-44']='Remote Registry Service 등 불필요 시 서비스 중지 및 “사용 안 함”으로 설정'
$Remed['W-45']='바이러스 백신 프로그램 설치'
$Remed['W-46']='SAM 파일 권한 확인 후 Administrator, System 그룹 외 다른 그룹에 설정된 권한 제거'
$Remed['W-47']='화면 보호기 사용, 대기 시간 10분 이하, 해제를 위한 암호 사용'
$Remed['W-48']='“시스템 종료: 로그온하지 않고 시스템 종료” 정책을 “사용 안 함”으로 설정'
$Remed['W-49']='“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators” 외 다른 계정 및 그룹 제거'
$Remed['W-50']='“보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책을 “사용 안 함”으로 설정'
$Remed['W-51']='“SAM 계정과 공유의 익명 열거 허용 안 함”을 “사용”으로 레지스트리 값 또는 로컬 보안 정책 설정'
$Remed['W-52']='AutoAdminLogon 레지스트리 값이 존재하는 경우 0으로 설정'
$Remed['W-53']='“이동식 NTFS 미디어 꺼내기 허용” 정책을 “Administrators”로 설정'
$Remed['W-54']='DoS 공격 방어 레지스트리 값(SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)을 추가 또는 수정'
$Remed['W-55']='“사용자가 프린터 드라이버를 설치할 수 없게 함” 정책을 “사용”으로 설정'
$Remed['W-56']='“로그온 시간이 만료되면 클라이언트 연결 끊기” 정책 “사용” 설정 / “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책 “15분” 이하로 설정'
$Remed['W-57']='로그인 메시지 제목 및 메시지 내용에 경고 문구 삽입'
$Remed['W-58']='사용자 홈 디렉터리에서 Everyone 권한 제거'
$Remed['W-59']='Windows 2000: “LAN Manager 인증 수준” → “NTLMv2 응답만 보내기” / Windows 2003·2008·2012·2016·2019: “네트워크 보안: LAN Manager 인증 수준” → “NTLMv2 응답만 보내기”'
$Remed['W-60']='보안 채널 데이터를 디지털 암호화·서명하는 3개 정책을 모두 “사용”으로 설정'
$Remed['W-61']='FAT 파일 시스템 사용 시 가능한 한 NTFS 파일 시스템으로 변환 설정'
$Remed['W-62']='시작 프로그램 목록의 정기적인 검사 실시 및 불필요한 서비스 비활성화 설정'
$Remed['W-63']='Kerberos 사용 시 컴퓨터 시계 동기화 최대 허용 오차값을 5분 이하로 설정'
$Remed['W-64']='Windows 방화벽을 “사용”으로 설정'

# 출력 헬퍼 + 분류 표기(PDF 공백) 매핑 + 진단대상
$CatMap=@{'계정관리'='계정 관리';'서비스관리'='서비스 관리';'패치관리'='패치 관리';'로그관리'='로그 관리';'보안관리'='보안 관리'}
$TargetSys='Windows Server'
function Truncate8($t){ if(-not $t){return '(없음)'}; $l=$t -split "`r?`n"; if($l.Count -le 8){return ($l -join "`n")}; ($l[0..7] -join "`n")+"`n... (이하 $($l.Count-8)줄 생략 — 상세는 로우데이터 CSV 참조)" }
function StripParen($r){ if($r -and ($r -notmatch "`n") -and ($r -match '^\((.*)\)$')){return $Matches[1]}; $r }
function StdBlock($c){ $s=$Std[$c]; if($s){"양호 : $($s.P)`n취약 : $($s.V)"}else{'(기준 미정의)'} }

# ── secedit 내보내기 파싱 ────────────────────────────────
$SEC=@{}
$secInf = Join-Path $env:TEMP "win_diag_sec_$PID.inf"
secedit /export /cfg $secInf /quiet 2>$null | Out-Null
if (Test-Path $secInf) {
    foreach ($line in (Get-Content $secInf -Encoding Unicode)) {
        if ($line -match '^\s*([^=\[\]]+?)\s*=\s*(.+?)\s*$') {
            $k=$Matches[1].Trim(); $v=$Matches[2].Trim()
            $SEC[$k]=$v
            if ($k -match '\\([^\\]+)$') { $SEC['REG:'+$Matches[1]]=$v }
        }
    }
    Remove-Item $secInf -Force -ErrorAction SilentlyContinue
}
function Sec($k){ if ($SEC.ContainsKey($k)) { $SEC[$k] } else { $null } }
function SecReg($leaf){ $v=$SEC['REG:'+$leaf]; if ($v) { ($v -split ',',2)[-1] } else { $null } }
function Get-Reg($Path,$Name){ try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null } }
# SID(예: *S-1-5-32-544) → 계정/그룹 이름. 해석 실패 시 SID 원본 반환.
function Resolve-Sid($sid){
    $s = ("$sid").Trim().TrimStart('*')
    if (-not $s) { return '' }
    try { (New-Object System.Security.Principal.SecurityIdentifier($s)).Translate([System.Security.Principal.NTAccount]).Value } catch { $s }
}

# ── 결과 수집/출력 ───────────────────────────────────────
$Results = New-Object System.Collections.ArrayList
$Cnt=@{$PASS=0; $VULN=0; $NA=0}
function Add-Result {
    param($Code,$Result,$File,$Raw,$Summary)
    $m=$Meta[$Code]
    $Raw = StripParen $Raw            # 결과 없음(자연어) 단일라인 (…) 괄호 제거
    $std = StdBlock $Code             # 판단기준 원문(양호/취약)
    $Cnt[$Result]++
    [void]$Results.Add([pscustomobject]@{
        Code=$Code; Sev=$m.Sev; Name=$m.Name; Cat=$m.Cat
        File=$File; Raw=$Raw; Result=$Result; Summary=$Summary; Std=$std
    })
    # 화면 블록: 점검 결과 / 점검 파일 명 / 점검 요약(8줄) / 판단 기준
    Write-Host ("[{0} ({1}) {2}]" -f $Code,$m.Sev,$m.Name)
    Write-Host ("점검 결과    : {0}" -f $Result)
    Write-Host ("점검 파일 명 : {0}" -f $File)
    Write-Host  "점검 요약    :"
    (Truncate8 $Raw) -split "`n" | ForEach-Object { Write-Host ("    " + $_) }
    Write-Host  "판단 기준    :"
    $std -split "`n" | ForEach-Object { Write-Host ("    " + $_) }
    Write-Host  "----------------------------------------------------------------"
}

function Show-PreInfo {
    "진단 스크립트 시작"
    "================================================================"
    "[사전 정보]"
    "현재 OS      : $OS ($OSVer)"
    "점검 환경 IP : $IP"
    "점검 분류    : INFRA - Windows    [전체 분류: WAS / DB / WEB / INFRA]"
    "점검 대상    : $HostN"
    "점검 시각    : $TS"
    "점검 방식    : 읽기 전용(설정 변경 없음)"
    "기준         : KISA 2026 Windows W-01~W-64 (총 64항목)"
    "설정 파일    : $ConfigFile"
    "================================================================"
}
Show-PreInfo
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "[진단 중단] 관리자 권한이 아닙니다. (현재 계정: $env:USERNAME)" -ForegroundColor Red
    Write-Host "  secedit 내보내기·레지스트리·보안설정 조회에 관리자 권한이 필요합니다." -ForegroundColor Red
    Write-Host "  조치: PowerShell을 '관리자 권한으로 실행'한 뒤 재실행하세요." -ForegroundColor Red
    Write-Host "        예) Start-Process powershell -Verb RunAs" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    exit 2
}
Write-Host ""

# =====================================================================
#  점검 함수 (W-01 ~ W-64)
# =====================================================================
$admin500 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like '*-500' }
$guest501 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like '*-501' }

# W-01 Administrator 이름 변경
$an = if ($admin500) { $admin500.Name } else { (Sec 'NewAdministratorName') -replace '"','' }
if ($an -and $an -ne 'Administrator') { Add-Result 'W-01' $PASS 'SID -500 계정명 | secedit NewAdministratorName' "관리자(-500) 계정명: $an" "기본 Administrator 계정명이 변경됨" }
else { Add-Result 'W-01' $VULN 'SID -500 계정' "관리자(-500) 계정명: $an" "기본 Administrator 계정명을 사용 중" }

# W-02 Guest 비활성화
# W-02 Guest 비활성화 (한국어 출력 명확화)
$gEnabled = if ($guest501) { -not $guest501.Disabled } else { $false }
$gname = if ($guest501) { $guest501.Name } else { 'Guest' }
if ($gEnabled) {
    Add-Result 'W-02' $VULN 'Guest 계정(-501)' "Guest($gname) 활성화됨" "Guest 계정이 활성화되어 있음"
} else {
    Add-Result 'W-02' $PASS 'Guest 계정(-501)' "Guest($gname) 활성화 여부=$gEnabled" "Guest 계정 비활성화됨"
}

# W-03 불필요한 계정 제거
$users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"
$enabledUsers = ($users | Where-Object { -not $_.Disabled } | Select-Object -ExpandProperty Name) -join ', '
Add-Result 'W-03' $NA '로컬 계정 목록' "활성 로컬 계정: $enabledUsers" "불필요(퇴직/미사용) 계정 존재 여부 — 수동 확인 대상"

# W-04 계정 잠금 임계값
$lt = [int](Sec 'LockoutBadCount')
if ($lt -ge 1 -and $lt -le $Conf.LockoutThreshold) { Add-Result 'W-04' $PASS '계정 잠금 정책' "LockoutBadCount=$lt" "계정 잠금 임계값 $lt (기준 1~$($Conf.LockoutThreshold))" }
else { Add-Result 'W-04' $VULN '계정 잠금 정책' "LockoutBadCount=$lt (0=설정안함)" "계정 잠금 임계값 미설정 또는 $($Conf.LockoutThreshold) 초과" }

# W-05 해독 가능한 암호화로 암호 저장 해제
$ct = [int](Sec 'ClearTextPassword')
if ($ct -eq 0) { Add-Result 'W-05' $PASS '암호 정책(ClearTextPassword)' "ClearTextPassword=$ct" "해독 가능한 암호화로 암호 저장 안 함(사용 안 함)" }
else { Add-Result 'W-05' $VULN '암호 정책(ClearTextPassword)' "ClearTextPassword=$ct" "해독 가능한 암호화로 암호 저장이 활성화됨" }

# W-06 Administrators 그룹 최소 사용자
$adminMembers = (net localgroup Administrators 2>$null | Where-Object { $_ -and $_ -notmatch '명령|completed|----|^Alias|^Comment|^Members|^The command' })
$adminList = ($adminMembers | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ', '
$extra = @($adminMembers | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($Conf.AllowedAdmins -notcontains $_) -and ($_ -ne 'Administrator') })
if ($extra.Count -eq 0) { Add-Result 'W-06' $PASS 'Administrators 그룹' "구성원: $adminList" "관리자 그룹에 허용된 계정만 포함" }
else { Add-Result 'W-06' $VULN 'Administrators 그룹' "구성원: $adminList / 미허용: $($extra -join ', ')" "관리자 그룹에 불필요 계정 포함 — 수동 확인" }

# W-07 Everyone 권한을 익명 사용자에게 적용 해제
$ev = SecReg 'EveryoneIncludesAnonymous'
if ($ev -eq $null) { $ev = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' }
if ("$ev" -eq '0') { Add-Result 'W-07' $PASS 'Lsa\EveryoneIncludesAnonymous' "값=$ev" "Everyone 권한이 익명 사용자에 미적용(0)" }
else { Add-Result 'W-07' $VULN 'Lsa\EveryoneIncludesAnonymous' "값=$ev" "Everyone 권한이 익명 사용자에 적용됨" }

# W-08 계정 잠금 기간
$ld = [int](Sec 'LockoutDuration')
if ($ld -ge $Conf.LockoutDuration) { Add-Result 'W-08' $PASS '계정 잠금 정책' "LockoutDuration=$ld 분" "계정 잠금 기간 $ld 분 (기준 $($Conf.LockoutDuration) 이상)" }
else { Add-Result 'W-08' $VULN '계정 잠금 정책' "LockoutDuration=$ld 분" "계정 잠금 기간 미설정 또는 $($Conf.LockoutDuration)분 미만" }

# W-09 비밀번호 관리정책
$pl=[int](Sec 'MinimumPasswordLength'); $pa=[int](Sec 'MaximumPasswordAge'); $pmin=[int](Sec 'MinimumPasswordAge'); $pc=[int](Sec 'PasswordComplexity'); $ph=[int](Sec 'PasswordHistorySize')
$praw="MinLen=$pl MaxAge=$pa MinAge=$pmin Complexity=$pc History=$ph (기준: 길이>=$($Conf.PasswordMinLength)·복잡도=1·최대<=$($Conf.MaxPasswordAge)·최소>=$($Conf.MinPasswordAge)·기억>=$($Conf.PasswordHistory))"
if ($pl -ge $Conf.PasswordMinLength -and $pa -ge 1 -and $pa -le $Conf.MaxPasswordAge -and $pmin -ge $Conf.MinPasswordAge -and $pc -eq 1 -and $ph -ge $Conf.PasswordHistory) { Add-Result 'W-09' $PASS '암호 정책' $praw "비밀번호 정책(길이/복잡도/최대·최소 사용기간/기억) 모두 적정" }
else { Add-Result 'W-09' $VULN '암호 정책' $praw "비밀번호 정책 미흡(길이>=$($Conf.PasswordMinLength)·복잡도·최대<=$($Conf.MaxPasswordAge)·최소>=$($Conf.MinPasswordAge)·기억>=$($Conf.PasswordHistory) 필요)" }

# W-10 마지막 사용자 이름 표시 안 함
$dl = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName'
if ("$dl" -eq '1') { Add-Result 'W-10' $PASS 'Policies\System\DontDisplayLastUserName' "값=$dl" "마지막 사용자 이름 표시 안 함(1)" }
else { Add-Result 'W-10' $VULN 'Policies\System\DontDisplayLastUserName' "값=$dl" "마지막 로그온 사용자 이름이 표시됨" }

# W-11 로컬 로그온 허용 제한 — SID 해석 후 자동 판정 (KISA: Administrators, IUSR_ 만 존재 = 양호)
$il = Sec 'SeInteractiveLogonRight'
$ilMembers = @(); if ($il) { $ilMembers = @(($il -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$ilResolved = $ilMembers | ForEach-Object { "{0}  [{1}]" -f (Resolve-Sid $_), $_ }
$ilBad = @($ilMembers | Where-Object { (Resolve-Sid $_) -notmatch 'Administrators|IUSR' })
$raw11 = "SeInteractiveLogonRight 구성원:`n" + (($ilResolved | ForEach-Object { "  - $_" }) -join "`n")
if ($ilMembers.Count -eq 0) {
    Add-Result 'W-11' $NA '사용자 권한 할당(대화형 로그온 허용)' "(SeInteractiveLogonRight 미설정)" "로컬 로그온 허용 정책 미설정 — 수동 확인"
}
elseif ($ilBad.Count -eq 0) {
    Add-Result 'W-11' $PASS '사용자 권한 할당(대화형 로그온 허용)' $raw11 "로컬 로그온 허용에 Administrators/IUSR_ 만 존재 — 양호"
}
else {
    $ilBadNames = ($ilBad | ForEach-Object { Resolve-Sid $_ }) -join ', '
    Add-Result 'W-11' $VULN '사용자 권한 할당(대화형 로그온 허용)' $raw11 "로컬 로그온 허용에 Administrators/IUSR_ 외 계정·그룹 존재($ilBadNames) — 취약"
}

# W-12 익명 SID/이름 변환 허용 해제
$lsl = [int](Sec 'LSAAnonymousNameLookup')
if ($lsl -eq 0) { Add-Result 'W-12' $PASS 'LSAAnonymousNameLookup' "값=$lsl" "익명 SID/이름 변환 허용 안 함(0)" }
else { Add-Result 'W-12' $VULN 'LSAAnonymousNameLookup' "값=$lsl" "익명 SID/이름 변환이 허용됨" }

# W-13 콘솔 로그온 시 로컬 계정 빈 암호 제한
$lb = SecReg 'LimitBlankPasswordUse'; if ($lb -eq $null) { $lb = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' }
if ("$lb" -eq '1') { Add-Result 'W-13' $PASS 'Lsa\LimitBlankPasswordUse' "값=$lb" "빈 암호 로컬 계정의 콘솔 외 사용 제한(1)" }
else { Add-Result 'W-13' $VULN 'Lsa\LimitBlankPasswordUse' "값=$lb" "빈 암호 사용 제한 미설정" }

# W-14 원격터미널 접속 가능 사용자 그룹 제한 (Remote Desktop Users, 고정 SID S-1-5-32-555)
#   가이드: 원격 접속 가능 그룹을 최소화. 광범위 그룹(Everyone/Users 등) 포함 시 취약.
#   그룹이 비어 있으면 원격 접속 허용 대상 없음 → 양호. 개별 계정은 양호+적정성 수동 확인.
$rdMembers = @()
$rdSrc = 'Get-LocalGroupMember'
try {
    $rdMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction Stop |
        ForEach-Object { "{0}  [{1}]" -f $_.Name, $_.ObjectClass })
} catch {
    # 폴백: net localgroup (SID로 그룹명을 역해석 후 조회, locale 헤더 제거)
    $rdSrc = 'net localgroup'
    $gname = try { (Get-LocalGroup -SID 'S-1-5-32-555' -ErrorAction Stop).Name } catch { 'Remote Desktop Users' }
    $rdMembers = @(net localgroup "$gname" 2>$null |
        Where-Object { $_ -and $_ -notmatch '별칭|이름|설명|구성원|명령|completed|^-+|^Alias|^Comment|^Members|^The command' } |
        ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# 광범위 허용을 의미하는 위험 그룹(이게 들어 있으면 사실상 모두 허용 = 취약)
$rdDanger = @($rdMembers | Where-Object { $_ -match 'Everyone|Authenticated Users|Domain Users|\bUsers\b|모든 사용자|인증된 사용자' })

if ($rdMembers.Count -eq 0) {
    # 비어 있음 = 원격 접속 허용 대상 없음 → 양호
    $rdRaw = "조회방식: $rdSrc`n구성원 수: 0 (그룹이 비어 있음)"
    Add-Result 'W-14' $PASS 'Remote Desktop Users 그룹 (SID S-1-5-32-555)' $rdRaw "Remote Desktop Users 그룹이 비어 있음 — 원격 접속 허용 대상 없음(양호)"
}
elseif ($rdDanger.Count -gt 0) {
    # 광범위 그룹 포함 → 취약
    $rdRaw = "조회방식: $rdSrc`n구성원 수: $($rdMembers.Count)`n" + (($rdMembers | ForEach-Object { "  - $_" }) -join "`n") + "`n위험 그룹 포함: $($rdDanger -join ', ')"
    Add-Result 'W-14' $VULN 'Remote Desktop Users 그룹 (SID S-1-5-32-555)' $rdRaw "Remote Desktop Users에 광범위 그룹($($rdDanger -join ', ')) 포함 — 원격 접속 과다 허용(취약)"
}
else {
    # 개별 계정만 포함 → 양호, 비고: 적정성 수동 확인 권고
    $rdRaw = "조회방식: $rdSrc`n구성원 수: $($rdMembers.Count)`n" + (($rdMembers | ForEach-Object { "  - $_" }) -join "`n")
    Add-Result 'W-14' $PASS 'Remote Desktop Users 그룹 (SID S-1-5-32-555)' $rdRaw "Remote Desktop Users에 $($rdMembers.Count)개 개별 계정 포함, 광범위 그룹 없음(양호) ※비고: 구성원 적정성 수동 확인 권고"
}

# W-15 사용자 개인키 사용 시 암호 입력 강제 (ForceKeyProtection)
# 0=요구 안함(취약), 1=사용 시 확인만(암호X), 2=사용 시마다 암호 입력(양호)
$w15Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'
$w15Value = 'ForceKeyProtection'
$w15Reg   = Get-Reg $w15Path $w15Value

$w15Label = 'Cryptography\ForceKeyProtection (개인키 사용 시마다 암호 입력)'

if ($w15Reg -ne $null -and $w15Reg -ne '') {
    $w15Int = $null
    try { $w15Int = [int]$w15Reg } catch { $w15Int = $null }

    if ($w15Int -eq 2) {
        Add-Result 'W-15' $PASS $w15Label "ForceKeyProtection=$w15Int" "개인키 사용 시마다 암호 입력 요구(값 2) — 양호"
    }
    elseif ($w15Int -eq 1) {
        Add-Result 'W-15' $VULN $w15Label "ForceKeyProtection=$w15Int" "사용 시 확인만 요구(값 1) — 암호 입력 아님, 취약"
    }
    elseif ($w15Int -eq 0) {
        Add-Result 'W-15' $VULN $w15Label "ForceKeyProtection=$w15Int" "암호/확인 요구 안 함(값 0) — 취약"
    }
    else {
        Add-Result 'W-15' $NA $w15Label "ForceKeyProtection=$w15Reg" "값 해석 불가 — 수동 확인 필요"
    }
}
else {
    # 미설정 시 기본 동작은 '암호 매번 입력 강제 아님' → 기준상 취약으로 판정
    Add-Result 'W-15' $VULN $w15Label "정책 미설정(기본값)" "ForceKeyProtection 미설정 — 기본값은 암호 입력 강제 아님, 취약"
}

# W-16 공유 권한 및 사용자 그룹 설정
$shares = Get-CimInstance Win32_Share -Filter "Type=0" | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$|^IPC\$' }
$everyoneShare=@()
foreach($s in $shares){ $acl = (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue); if($acl | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -ne 'Read' }){ $everyoneShare+=$s.Name } }
if (-not $shares) { Add-Result 'W-16' $PASS '공유 폴더' "(일반 공유 없음)" "사용자 생성 공유 없음" }
elseif ($everyoneShare.Count -eq 0) { Add-Result 'W-16' $PASS '공유 폴더 권한' "공유: $(($shares.Name) -join ', ')" "Everyone 과다 권한 공유 없음" }
else { Add-Result 'W-16' $VULN '공유 폴더 권한' "Everyone 쓰기 공유: $($everyoneShare -join ', ')" "Everyone 에 과도한 공유 권한 부여" }

# W-17 하드디스크 기본 공유 제거
$autoShare = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer'
$defShares = (Get-CimInstance Win32_Share | Where-Object { $_.Name -match '^[A-Z]\$$' } | Select-Object -ExpandProperty Name) -join ', '
if (-not $defShares) { $defShares = '(없음)' }
if ("$autoShare" -eq '0') { Add-Result 'W-17' $PASS 'LanmanServer\AutoShareServer' "AutoShareServer=$autoShare / 기본공유: $defShares" "기본 공유(AutoShareServer) 비활성화됨" }
else { Add-Result 'W-17' $VULN 'LanmanServer\AutoShareServer' "AutoShareServer=$autoShare / 기본공유: $defShares" "디스크 기본 공유(C$ 등)가 활성 상태" }

# W-18 불필요한 서비스 제거 — 전체 결과 출력 및 취약 판단 강화
$runningBad = @(); $allChecked = @()
foreach($svc in $Conf.UnnecessaryServices){
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { $allChecked += "{0}: {1}" -f $svc, $s.Status } else { $allChecked += "{0}: (서비스 없음)" -f $svc }
    if ($s -and $s.Status -eq 'Running') { $runningBad += "{0} (Running)" -f $svc }
}
$raw = "서비스 점검 결과:`n" + ($allChecked -join "`n")
if ($runningBad.Count -eq 0) {
    Add-Result 'W-18' $PASS '서비스 목록' $raw "불필요한 서비스가 구동되지 않음"
} else {
    Add-Result 'W-18' $VULN '서비스 목록' ($raw + "`n실제로 구동중인 불필요 서비스: $($runningBad -join ', ')") "불필요한 서비스 구동중 — 취약"
}

# W-19 IIS 구동 점검
$iis=Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if (-not $iis) { Add-Result 'W-19' $PASS 'IIS(W3SVC)' "(IIS 미설치)" "IIS 미설치/미사용" }
elseif ($iis.Status -ne 'Running') { Add-Result 'W-19' $PASS 'IIS(W3SVC)' "상태=$($iis.Status)" "IIS 미구동" }
else { Add-Result 'W-19' $NA 'IIS(W3SVC)' "상태=Running" "IIS 구동중 — 필요성/설정 수동 확인 대상" }

# W-20 NetBIOS 바인딩
$nb = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
$nbOn = $nb | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
if (-not ($nbOn)) { Add-Result 'W-20' $PASS 'NetBIOS over TCP/IP' "TcpipNetbiosOptions=2(비활성)" "NetBIOS over TCP/IP 비활성화됨" }
else { Add-Result 'W-20' $VULN 'NetBIOS over TCP/IP' "활성 어댑터 존재(TcpipNetbiosOptions!=2)" "NetBIOS 바인딩 활성 — 비활성화 권고" }

# W-21 암호화 안된 FTP 서비스 비활성
$ftp=Get-Service -Name MSFTPSVC,FTPSVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
if (-not $ftp) { Add-Result 'W-21' $PASS 'FTP 서비스' "(FTP 미구동)" "FTP 서비스 미사용" }
else { Add-Result 'W-21' $NA 'FTP 서비스' "구동중: $($ftp.Name -join ',')" "FTP 구동중 — FTPS(암호화) 적용 여부 수동 확인" }

# W-22 FTP 디렉터리 접근권한
# FTP 미사용 → N/A(점검 해당 없음) / 구동 중 → 기존 로직(수동 확인)
if (-not (Get-Service -Name MSFTPSVC,FTPSVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })) { Add-Result 'W-22' $NA 'FTP' "(FTP 미구동)" "FTP 미사용 — 점검 해당 없음(N/A)" }
else { Add-Result 'W-22' $NA 'FTP 홈 디렉터리' "FTP 구동중" "FTP 디렉터리 접근권한 — 수동 확인 대상" }

# W-23 공유 익명 접근 제한
$ra = SecReg 'RestrictAnonymous'; if($ra -eq $null){ $ra = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' }
$rsa = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'RestrictNullSessAccess'
if ("$rsa" -eq '1' -or "$ra" -eq '1') { Add-Result 'W-23' $PASS 'RestrictNullSessAccess | RestrictAnonymous' "RestrictNullSessAccess=$rsa, RestrictAnonymous=$ra" "공유에 대한 익명(널 세션) 접근 제한됨" }
else { Add-Result 'W-23' $VULN 'RestrictNullSessAccess' "RestrictNullSessAccess=$rsa, RestrictAnonymous=$ra" "공유 익명 접근 제한 미설정" }

# W-24 FTP 접근 제어
# FTP 미사용 → N/A(점검 해당 없음) / 구동 중 → 기존 로직(수동 확인)
if (-not (Get-Service -Name MSFTPSVC,FTPSVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })) { Add-Result 'W-24' $NA 'FTP' "(FTP 미구동)" "FTP 미사용 — 점검 해당 없음(N/A)" }
else { Add-Result 'W-24' $NA 'FTP 접근 제어' "FTP 구동중" "FTP IP/사용자 접근 제어 — 수동 확인 대상" }

# W-25 DNS Zone Transfer
$dns=Get-Service -Name DNS -ErrorAction SilentlyContinue
if (-not $dns -or $dns.Status -ne 'Running') { Add-Result 'W-25' $PASS 'DNS' "(DNS 미구동)" "DNS 미사용(Zone Transfer 무관)" }
else { Add-Result 'W-25' $NA 'DNS Zone Transfer' "DNS 구동중" "Zone Transfer 제한 여부 — 수동 확인 대상" }

# W-26 RDS(Remote Data Services) 검사 강화 — 가이드 판단기준에 맞춰 검사
$iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
$adcLaunch = 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch'
$detail = @()

if (-not $iis) {
    Add-Result 'W-26' $PASS 'RDS(ADCLaunch)' "IIS(W3SVC) 미설치 — RDS 위험 비해당" "IIS 미사용으로 RDS 위험 없음"
}
else {
    $hasADC = Test-Path $adcLaunch
    $detail += if ($hasADC) { "[발견] $adcLaunch" } else { "[미발견] $adcLaunch" }
    $msadcPath = "$env:SystemDrive\Program Files\Common Files\System\msadc"
    $detail += if (Test-Path $msadcPath) { "[발견] MSADC 폴더: $msadcPath" } else { "[미발견] MSADC 폴더" }

    $raw = "IIS(W3SVC) 구동 중`n확인 항목:`n  " + ($detail -join "`n  ")
    if (-not $hasADC) { Add-Result 'W-26' $PASS 'RDS(ADCLaunch)' $raw "RDS(ADCLaunch) 레지스트리 키 없음 — 양호" }
    else { Add-Result 'W-26' $VULN 'RDS(ADCLaunch)' $raw "IIS 환경에서 RDS(ADCLaunch) 키 존재 — 제거/패치 검토 권고" }
}

# W-27 최신 OS Build (빌드 번호 기반 실제 버전명 매핑)
$cvPath     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$ubr        = Get-Reg $cvPath 'UBR'
$dispv      = Get-Reg $cvPath 'DisplayVersion'
$releaseId  = Get-Reg $cvPath 'ReleaseId'
$buildLab   = Get-Reg $cvPath 'BuildLabEx'
$productName= Get-Reg $cvPath 'ProductName'
$curBuild   = Get-Reg $cvPath 'CurrentBuildNumber'

# 빌드 번호 정수화
$buildNum = $null
try { if ($curBuild) { $buildNum = [int]$curBuild } } catch { $buildNum = $null }

# 빌드 번호로 실제 OS 이름 판별 (ProductName이 Win11도 "Windows 10"으로 표기하는 문제 보정)
function Get-FriendlyOSName($build, $product) {
    if ($build -eq $null) { return $product }
    # 클라이언트 OS
    if ($build -ge 22000) { return ($product -replace 'Windows 10','Windows 11') }
    if ($build -ge 10240) { return $product }  # Windows 10 계열
    # 서버 OS (대략적 매핑)
    switch ($build) {
        { $_ -ge 26100 } { return 'Windows Server 2025' }
        { $_ -ge 20348 } { return 'Windows Server 2022' }
        { $_ -ge 17763 } { return 'Windows Server 2019' }
        { $_ -ge 14393 } { return 'Windows Server 2016' }
        default          { return $product }
    }
}

$friendlyName = Get-FriendlyOSName $buildNum $productName

# 전체 빌드 문자열 (예: 22631.4317)
$fullBuild = $curBuild
if ($ubr) { $fullBuild = "$curBuild.$ubr" }

$verDetail = "OS(판별): $friendlyName"
if ($dispv)     { $verDetail += "`n버전(DisplayVersion): $dispv" }
elseif ($releaseId) { $verDetail += "`n버전(ReleaseId): $releaseId" }
if ($fullBuild) { $verDetail += "`n빌드: $fullBuild" }
$verDetail += "`n원본 ProductName: $productName"
if ($buildLab)  { $verDetail += "`nBuildLabEx: $buildLab" }

Add-Result 'W-27' $NA 'Windows Build 정보' $verDetail "최신 OS Build/패치 적용 여부 — 수동 확인 대상"

# W-28 터미널 서비스 암호화 수준
$me = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
if ([int]$me -ge $Conf.RDPMinEncryption -or $me -eq $null) { Add-Result 'W-28' $PASS 'RDP MinEncryptionLevel' "값=$me" "터미널 암호화 수준 중간(2) 이상 (또는 RDP 미사용)" }
else { Add-Result 'W-28' $VULN 'RDP MinEncryptionLevel' "값=$me" "터미널 서비스 암호화 수준이 '낮음(1)'으로 설정됨" }

# W-29 SNMP 구동
$snmp=Get-Service -Name SNMP -ErrorAction SilentlyContinue
if (-not $snmp -or $snmp.Status -ne 'Running') { Add-Result 'W-29' $PASS 'SNMP' "(SNMP 미구동)" "SNMP 서비스 미사용" }
else { Add-Result 'W-29' $NA 'SNMP' "구동중" "SNMP 구동중 — 필요성 수동 확인" }

# W-30 SNMP Community
$comm = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ErrorAction SilentlyContinue
if (-not (Get-Service SNMP -ErrorAction SilentlyContinue)) { Add-Result 'W-30' $PASS 'SNMP Community' "(SNMP 미설치)" "SNMP 미사용" }
elseif ($comm) { $cnames=($comm.Property) -join ', '; if($cnames -match 'public|private'){ Add-Result 'W-30' $VULN 'SNMP ValidCommunities' "Community: $cnames" "기본 Community(public/private) 사용" } else { Add-Result 'W-30' $PASS 'SNMP ValidCommunities' "Community: $cnames" "기본 Community 미사용" } }
else { Add-Result 'W-30' $NA 'SNMP Community' "(설정 확인 필요)" "SNMP Community — 수동 확인" }

# W-31 SNMP Access control
$permMgr = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' '1'
if (-not (Get-Service SNMP -ErrorAction SilentlyContinue)) { Add-Result 'W-31' $PASS 'SNMP' "(SNMP 미설치)" "SNMP 미사용" }
elseif ($permMgr) { Add-Result 'W-31' $PASS 'SNMP PermittedManagers' "허용 관리자 지정됨" "SNMP 접근 제어 설정됨" }
else { Add-Result 'W-31' $VULN 'SNMP PermittedManagers' "(PermittedManagers 미지정=모든 호스트 허용)" "SNMP 접근 제어 미설정" }

# W-32 DNS 구동
$dns2=Get-Service -Name DNS -ErrorAction SilentlyContinue
if (-not $dns2 -or $dns2.Status -ne 'Running') { Add-Result 'W-32' $PASS 'DNS' "(DNS 미구동)" "DNS 서비스 미사용" }
else { Add-Result 'W-32' $NA 'DNS' "구동중" "DNS 구동중 — 필요성 수동 확인" }

# W-33 HTTP/FTP/SMTP 배너 차단
# 관련 서비스(IIS/FTP/SMTP) 미사용 → N/A(점검 해당 없음) / 구동 중 → 기존 로직(수동 확인)
$svcList = @('W3SVC','MSFTPSVC','SMTPSVC','FTPSVC')
$present = @()
foreach($s in $svcList){ $ss = Get-Service -Name $s -ErrorAction SilentlyContinue; if ($ss -and $ss.Status -eq 'Running') { $present += "{0}({1})" -f $s,$ss.Status } }
if ($present.Count -eq 0) {
    Add-Result 'W-33' $NA 'IIS/FTP/SMTP 배너' "관련 서비스 없음" "웹/FTP/SMTP 서비스 미구동 — 점검 해당 없음(N/A)"
} else {
    $w33Raw = "구동중 서비스: " + ($present -join ', ')
    Add-Result 'W-33' $NA 'IIS/FTP/SMTP 배너' $w33Raw "서비스가 구동중 — 배너 차단 여부 수동 확인 필요"
}

# W-34 Telnet 비활성
# Telnet 서비스 자체가 없으면(예: Windows Server 2019 기본) 진단 미해당 → N/A
#   서비스 존재 + 구동 중 → 취약 / 서비스 존재하나 미구동 → 양호
$telSvc = Get-Service -Name TlntSvr,Telnet -ErrorAction SilentlyContinue
if (-not $telSvc) {
    Add-Result 'W-34' $NA 'Telnet' "(Telnet 서비스 미설치)" "Telnet 서비스 자체가 없음(2019 기본) — 진단 해당 없음(N/A)"
}
elseif ($telSvc | Where-Object { $_.Status -eq 'Running' }) {
    Add-Result 'W-34' $VULN 'Telnet' "구동중" "Telnet 서비스 활성화됨"
}
else {
    Add-Result 'W-34' $PASS 'Telnet' "서비스 존재, 미구동" "Telnet 서비스 설치되어 있으나 비활성화 — 양호"
}

# W-35 ODBC/OLE-DB 드라이버 — 0개이면 양호
$dsn = Get-ChildItem 'HKLM:\SOFTWARE\ODBC\ODBC.INI' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'ODBC Data Sources' }
$countDsn = @($dsn).Count
if ($countDsn -eq 0) {
    Add-Result 'W-35' $PASS 'ODBC/OLE-DB 데이터소스' "DSN 수: 0" "불필요한 ODBC DSN 미존재"
} else {
    $dsnNames = ($dsn | ForEach-Object { $_.PSChildName }) -join ', '
    $w35Raw = "DSN 수: $countDsn ($dsnNames)"
    Add-Result 'W-35' $NA 'ODBC/OLE-DB 데이터소스' $w35Raw "ODBC DSN 존재 — 필요 여부 수동 확인 필요"
}

# W-36 원격터미널 타임아웃 (포맷 개선)
$idle = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MaxIdleTime'
try { $idleInt = [int]$idle } catch { $idleInt = 0 }
if ($idleInt -gt 0) { $idleMin = [math]::Round($idleInt/60000)
    if ($idleInt -le $Conf.RDPIdleTimeoutMaxMs) { Add-Result 'W-36' $PASS 'Terminal Services MaxIdleTime' "값=${idleInt}ms (${idleMin}분)" "원격터미널 유휴 타임아웃이 ${idleMin}분으로 적정" }
    else { Add-Result 'W-36' $VULN 'Terminal Services MaxIdleTime' "값=${idleInt}ms (${idleMin}분)" "원격터미널 타임아웃이 기준(${[math]::Round($Conf.RDPIdleTimeoutMaxMs/60000)}분) 초과" }
} else { Add-Result 'W-36' $VULN 'Terminal Services MaxIdleTime' "값=$idle (0=미설정)" "원격터미널 타임아웃 미설정 또는 0" }

# W-37 예약 작업 의심 명령 — 활성 작업을 '전부' 나열(화면은 8줄까지, CSV에 전수). 의심 여부는 수동/AI 확인.
$actTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' })
$taskLines = $actTasks | ForEach-Object {
    $act = ($_.Actions | ForEach-Object { ($_.Execute, $_.Arguments | Where-Object { $_ }) -join ' ' }) -join ' ; '
    "{0}{1}  [{2}]{3}" -f $_.TaskPath, $_.TaskName, $_.State, $(if ($act) { " → $act" } else { "" })
}
$raw37 = "활성 예약 작업 $($actTasks.Count)개:`n" + (($taskLines) -join "`n")
Add-Result 'W-37' $NA '예약 작업(Scheduled Tasks)' $raw37 "예약 작업 $($actTasks.Count)개 — 의심 명령 등록 여부 목록 수동/AI 확인 대상"

# W-38 보안 패치
$lastHotfix = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1)
Add-Result 'W-38' $NA 'Windows Update / HotFix' "최근 패치: $($lastHotfix.HotFixID) ($($lastHotfix.InstalledOn))" "주기적 보안 패치 정책·적용 — 수동 확인 대상"

# W-39 백신 업데이트 (서버 OS는 SecurityCenter2 없음 → Defender 서비스/상태로 보완)
$av  = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
$avn = ($av | Select-Object -ExpandProperty displayName) -join ', '
$def = Get-MpComputerStatus -ErrorAction SilentlyContinue
$wd  = Get-Service WinDefend -ErrorAction SilentlyContinue
$avInstalled = ([bool]$av) -or ($def -ne $null) -or ($wd -ne $null)
$avDesc = if ($avn) { $avn } elseif ($def) { "Windows Defender(서명 $($def.AntivirusSignatureVersion), 실시간=$($def.RealTimeProtectionEnabled))" } elseif ($wd) { "Windows Defender(서비스 $($wd.Status))" } else { '(백신 미탐지)' }
if ($avInstalled) { Add-Result 'W-39' $NA '백신(SecurityCenter2/Defender)' "$avDesc" "백신 설치 확인 — 최신 엔진 업데이트 여부 수동 확인" }
else { Add-Result 'W-39' $VULN '백신' "$avDesc" "백신 프로그램 미설치/미탐지" }

# W-40 정책에 따른 시스템 로깅(감사 정책)
$auditRaw = (auditpol /get /category:* 2>$null)
$auditMatches = $auditRaw | Select-String -Pattern 'Success|Failure|성공|실패'
$auditEnabled = @()
foreach($m in $auditMatches){ if ($m -notmatch '설정 안 함|No Auditing') { $auditEnabled += $m } }
# 활성 감사 항목(하위범주: 설정값)을 전수 나열 — 화면은 8줄, CSV에 전체.
$auditLines = $auditEnabled | ForEach-Object { ($_.ToString().Trim() -replace '\s{2,}',' : ') }
$raw40 = "감사 활성 항목 $($auditEnabled.Count)개 (auditpol /get /category:*):`n" + ($auditLines -join "`n")
if ($auditEnabled.Count -gt 0) { Add-Result 'W-40' $PASS '감사 정책(auditpol)' $raw40 "시스템 감사(로깅) 정책 설정됨 — 활성 항목 $($auditEnabled.Count)개" }
else { Add-Result 'W-40' $VULN '감사 정책(auditpol)' "감사 활성 항목 없음(모두 '설정 안 함')" "감사 정책 미설정 또는 비활성" }

# W-41 NTP 및 시각 동기화 설정
# 가이드: NTP/시각 동기화를 '설정'한 경우 양호 / 미설정 시 취약
#   판정 핵심: NtpServer가 등록되어 있고 W32Time이 동작하면 동기화 설정된 것 → 양호
$w32 = w32tm /query /status 2>$null
$svc = Get-Service W32Time -ErrorAction SilentlyContinue

# 구성에서 NtpServer / Type 추출
$cfg       = w32tm /query /configuration 2>$null
$ntpServer = ($cfg | Select-String 'NtpServer' | Select-Object -First 1)
$ntpType   = ($cfg | Select-String 'Type'      | Select-Object -First 1)
# w32tm 한글 출력의 괄호 꼬리(예 '(로컬)')가 콘솔 인코딩으로 '(??)'로 깨지므로 값에서 제거
$ntpSrvVal = if ($ntpServer) { (($ntpServer.ToString() -split ':',2)[-1].Trim() -replace '\s*\(.*$','') } else { '' }
$ntpTypVal = if ($ntpType)   { (($ntpType.ToString()   -split ':',2)[-1].Trim() -replace '\s*\(.*$','') } else { '' }

# 소스(참고용, 실패해도 판정엔 영향 없음)
$srcLine = ($w32 | Select-String -Pattern '소스|원본|Source' | Select-Object -First 1)
$srcVal  = if ($srcLine) { ($srcLine.ToString() -split ':',2)[-1].Trim() } else { '(추출실패)' }

$raw41 = "W32Time=$($svc.Status) / Type=$ntpTypVal / NtpServer=$ntpSrvVal / 소스=$srcVal"

# 판정: NtpServer가 등록(빈 값/없음 아님)되어 있고 서비스가 살아 있으면 동기화 설정됨 → 양호
$hasNtp = ($ntpSrvVal -and $ntpSrvVal -notmatch '^\s*$' -and $ntpTypVal -ne 'NoSync')
$svcOk  = ($svc -and $svc.Status -eq 'Running')

if ($hasNtp -and $svcOk) {
    Add-Result 'W-41' $PASS 'W32Time' $raw41 "NTP 시각 동기화 설정됨(NtpServer=$ntpSrvVal) — 양호"
}
elseif ($hasNtp -and -not $svcOk) {
    Add-Result 'W-41' $VULN 'W32Time' $raw41 "NtpServer 등록됐으나 W32Time 미동작($($svc.Status)) — 동기화 비활성(취약)"
}
else {
    Add-Result 'W-41' $VULN 'W32Time' $raw41 "NTP 서버 미등록/NoSync — 시각 동기화 미설정(취약)"
}

# W-42 이벤트 로그 관리 — 최대 크기(10,240KB 이상) + 90일 보관(덮어쓰기) 판정
$logPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
$maxSizeReg  = Get-Reg $logPath 'MaxSize'      # 바이트 단위
$retentionReg = Get-Reg $logPath 'Retention'   # 0=필요시덮어쓰기, 0xFFFFFFFF(-1)=덮어쓰지않음, 그외=초단위 보관기간

# Get-WinEvent로 보강 (레지스트리 미설정 시 실효값 확보)
$winLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue

# --- 최대 크기 확보 (바이트) ---
$maxBytes = $null
if ($maxSizeReg -ne $null -and $maxSizeReg -ne '') {
    try { $maxBytes = [int64]$maxSizeReg } catch { $maxBytes = $null }
}
if ($maxBytes -eq $null -and $winLog) { $maxBytes = $winLog.MaximumSizeInBytes }

$maxKB = if ($maxBytes -ne $null) { [math]::Round($maxBytes / 1KB) } else { $null }

# --- 보관 정책 판별 ---
# Retention 레지스트리 우선, 없으면 LogMode 사용
$retentionDays = $null     # 명시적 보관 일수(있으면)
$overwriteOK   = $false    # 덮어쓰기/보관 정책이 로그 손실 없이 적정한지

if ($retentionReg -ne $null -and $retentionReg -ne '') {
    $retVal = $null
    try { $retVal = [int64]$retentionReg } catch { $retVal = $null }
    if ($retVal -ne $null) {
        if ($retVal -eq 0) {
            # 필요시 덮어쓰기 (크기 초과 시 오래된 것부터) — 손실 없음으로 간주
            $overwriteOK = $true
        } elseif ($retVal -lt 0 -or $retVal -eq 4294967295) {
            # 덮어쓰지 않음(수동 삭제) — 가득 차면 신규 로그 손실 위험
            $overwriteOK = $false
        } else {
            # 초 단위 보관 기간 → 일수 환산
            $retentionDays = [math]::Round($retVal / 86400)
            $overwriteOK = ($retentionDays -ge 90)
        }
    }
} elseif ($winLog) {
    switch ($winLog.LogMode) {
        'Circular'   { $overwriteOK = $true }   # 필요시 덮어쓰기
        'AutoBackup' { $overwriteOK = $true }   # 가득 차면 보관 후 새 로그
        'Retain'     { $overwriteOK = $false }  # 덮어쓰지 않음
        default      { $overwriteOK = $false }
    }
}

# --- 판정 ---
$sizeText = if ($maxKB -ne $null) { "${maxKB}KB" } else { "확인불가" }
$retText  = if ($retentionDays -ne $null) { "${retentionDays}일" }
           elseif ($overwriteOK) { "덮어쓰기/보관(손실없음)" }
           else { "덮어쓰지않음(수동삭제)" }
$logSummary = "Security MaxSize=$sizeText, 보관정책=$retText"

$sizeOK = ($maxKB -ne $null -and $maxKB -ge 10240)

if ($maxKB -eq $null) {
    Add-Result 'W-42' $NA '이벤트 로그 크기' $logSummary "최대 로그 크기 확인 불가 — 수동 검토 필요"
}
elseif ($sizeOK -and $overwriteOK) {
    Add-Result 'W-42' $PASS '이벤트 로그 크기' $logSummary "최대 크기 10,240KB 이상 및 로그 손실 없는 보관 정책 — 양호"
}
else {
    $reason = @()
    if (-not $sizeOK)     { $reason += "최대 크기 10,240KB 미만" }
    if (-not $overwriteOK){ $reason += "보관 정책 부적정(덮어쓰지 않음/90일 미만)" }
    Add-Result 'W-42' $VULN '이벤트 로그 크기' $logSummary ("취약: " + ($reason -join ', '))
}

# W-43 이벤트 로그 파일 접근 통제
$evtPath = "$env:SystemRoot\System32\winevt\Logs"
$evtAcl = (Get-Acl $evtPath -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write|FullControl|Modify' }
if (-not $evtAcl) { Add-Result 'W-43' $PASS 'winevt\Logs ACL' "Everyone/Users 쓰기 권한 없음" "이벤트 로그 파일 접근 통제 적정" }
else { Add-Result 'W-43' $VULN 'winevt\Logs ACL' "Everyone/Users 쓰기 권한 존재" "이벤트 로그 디렉터리 접근 권한 과다" }

# W-44 원격 액세스 가능 레지스트리 경로
$arp = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' 'Machine'
$rc = (Get-Service RemoteRegistry -ErrorAction SilentlyContinue)
if (-not $rc -or $rc.Status -ne 'Running') { Add-Result 'W-44' $PASS 'RemoteRegistry | AllowedPaths' "RemoteRegistry 상태=$($rc.Status)" "원격 레지스트리 서비스 미구동" }
else { Add-Result 'W-44' $NA 'winreg AllowedPaths' "AllowedPaths.Machine 설정됨" "원격 액세스 레지스트리 경로 — 수동 확인" }

# W-45 백신 설치
if ($avInstalled) { Add-Result 'W-45' $PASS '백신' "$avDesc" "백신 프로그램 설치됨" }
else { Add-Result 'W-45' $VULN '백신' "$avDesc" "백신 프로그램 미설치" }

# W-46 SAM 파일 접근 통제
$samAcl = (Get-Acl "$env:SystemRoot\System32\config\SAM" -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match 'Everyone|Users' }
if (-not $samAcl) { Add-Result 'W-46' $PASS 'config\SAM ACL' "Everyone/Users 권한 없음" "SAM 파일 접근 통제 적정(관리자/SYSTEM 외 차단)" }
else { Add-Result 'W-46' $VULN 'config\SAM ACL' "Everyone/Users 권한 존재" "SAM 파일에 일반 사용자 권한 존재" }

# W-47 화면보호기 설정 (값 포맷/널 처리 개선)
$scrActive = (Get-Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive') -as [string]
$scrSecure = (Get-Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure') -as [string]
$scrTime   = (Get-Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut') -as [string]
$scrActive = if ($scrActive) { $scrActive } else { '0' }
$scrSecure = if ($scrSecure) { $scrSecure } else { '0' }
try { $scrTimeInt = [int]$scrTime } catch { $scrTimeInt = 0 }
$raw47 = "ScreenSaveActive=$scrActive, IsSecure=$scrSecure, TimeOut=$scrTimeInt"
if ($scrActive -eq '1' -and $scrSecure -eq '1' -and $scrTimeInt -gt 0 -and $scrTimeInt -le $Conf.ScreenSaverTimeout) {
    Add-Result 'W-47' $PASS '화면보호기(HKCU Desktop)' $raw47 "화면보호기 활성+암호+타임아웃 적정"
} else {
    Add-Result 'W-47' $VULN '화면보호기(HKCU Desktop)' $raw47 "화면보호기 미설정/암호 미적용/타임아웃 과다 또는 값 불명 (※ 현재 사용자 기준)"
}

# W-48 로그온하지 않고 시스템 종료 허용 해제
$sw = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ShutdownWithoutLogon'
if ("$sw" -eq '0') { Add-Result 'W-48' $PASS 'ShutdownWithoutLogon' "값=$sw" "로그온 없이 시스템 종료 허용 안 함(0)" }
else { Add-Result 'W-48' $VULN 'ShutdownWithoutLogon' "값=$sw" "로그온 없이 시스템 종료가 허용됨" }

# W-49 원격 시스템에서 강제 종료
$rsd = Sec 'SeRemoteShutdownPrivilege'
$rsdResolved = if ($rsd) { (($rsd -split ',') | ForEach-Object { "{0} [{1}]" -f (Resolve-Sid $_), $_.Trim() }) -join ', ' } else { '(미지정)' }
if ($rsd -and ($rsd -notmatch 'S-1-5-32-545|Users') ) { Add-Result 'W-49' $PASS 'SeRemoteShutdownPrivilege' $rsdResolved "원격 종료 권한이 관리자로 제한됨" }
elseif (-not $rsd) { Add-Result 'W-49' $VULN 'SeRemoteShutdownPrivilege' "(미지정)" "원격 종료 권한 설정 확인 필요" }
else { Add-Result 'W-49' $VULN 'SeRemoteShutdownPrivilege' $rsdResolved "원격 종료 권한에 일반 사용자 포함" }

# W-50 보안 감사 로그 불가 시 즉시 종료
$caf = SecReg 'CrashOnAuditFail'; if($caf -eq $null){ $caf = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'CrashOnAuditFail' }
if ("$caf" -eq '0' -or $caf -eq $null) { Add-Result 'W-50' $PASS 'Lsa\CrashOnAuditFail' "값=$caf" "감사 로그 불가 시 즉시 종료 '사용 안 함'(0) — 양호" }
else { Add-Result 'W-50' $VULN 'Lsa\CrashOnAuditFail' "값=$caf" "감사 로그 불가 시 즉시 종료가 '사용'($caf)으로 설정됨" }

# W-51 SAM 계정과 공유의 익명 열거 허용 안 함 — 핵심 판정값은 RestrictAnonymous
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

function To-IntOrNull($v){
    if ($v -eq $null -or "$v" -eq '') { return $null }
    try { return [int]("$v".Trim()) } catch { return $null }
}

# 레지스트리 직접 읽기 우선
$raRaw = Get-Reg $lsaPath 'RestrictAnonymous'
if ($raRaw -eq $null -or "$raRaw" -eq '') { $raRaw = SecReg 'RestrictAnonymous' }
$rasamRaw = Get-Reg $lsaPath 'RestrictAnonymousSAM'
if ($rasamRaw -eq $null -or "$rasamRaw" -eq '') { $rasamRaw = SecReg 'RestrictAnonymousSAM' }

$ra    = To-IntOrNull $raRaw       # 핵심: 공유 및 SAM 계정 익명 열거 제한
$rasam = To-IntOrNull $rasamRaw    # 참고: SAM 계정 익명 열거 제한

$summary = "RestrictAnonymous=$ra / RestrictAnonymousSAM=$rasam"

if ($ra -eq 1 -and $rasam -eq 1) {
    Add-Result 'W-51' $PASS 'Lsa\RestrictAnonymous | RestrictAnonymousSAM' $summary "SAM 계정 및 공유 익명 열거 제한(정책 '사용') — 양호"
}
else {
    Add-Result 'W-51' $VULN 'Lsa\RestrictAnonymous | RestrictAnonymousSAM' $summary "RestrictAnonymous 및 RestrictAnonymousSAM 모두 1이 아님 — 익명 열거 제한 미충족, 취약"
}

# W-52 Autologon 제어
$aal = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
$aalShow = if ($aal -eq $null -or "$aal" -eq '') { '(미설정)' } else { "$aal" }
if ("$aal" -ne '1') { Add-Result 'W-52' $PASS 'Winlogon\AutoAdminLogon' "값=$aalShow" "Autologon 비활성화" }
else { Add-Result 'W-52' $VULN 'Winlogon\AutoAdminLogon' "값=$aalShow (자동 로그온 활성)" "Autologon이 활성화됨(평문 암호 노출 위험)" }

# W-53 이동식 미디어 포맷/꺼내기 허용 제한
$ad = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AllocateDASD'
if ("$ad" -eq '0') { Add-Result 'W-53' $PASS 'Winlogon\AllocateDASD' "값=$ad" "이동식 미디어 포맷/꺼내기 허용이 Administrators로 제한됨(0)" }
else { Add-Result 'W-53' $VULN 'Winlogon\AllocateDASD' "값=$ad (0=Administrators 만)" "이동식 미디어 포맷/꺼내기 허용이 Administrators로 제한되지 않음" }

# W-54 DoS 공격 방어 레지스트리 설정
# 가이드: 4개 값 모두 충족 시 양호 / 하나라도 미설정·불일치 시 취약
#   SynAttackProtect>=1, EnableDeadGWDetect=0, KeepAliveTime=300000, NoNameReleaseOnDemand=1
$tcpPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$netbtPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'

function To-IntOrNull($v){
    if ($v -eq $null -or "$v" -eq '') { return $null }
    try { return [int]("$v".Trim()) } catch { return $null }
}
function Show($v){ if ($v -eq $null) { '(미설정)' } else { "$v" } }

$syn = To-IntOrNull (Get-Reg $tcpPath 'SynAttackProtect')
$dgw = To-IntOrNull (Get-Reg $tcpPath 'EnableDeadGWDetect')
$kal = To-IntOrNull (Get-Reg $tcpPath 'KeepAliveTime')

# NoNameReleaseOnDemand: 환경에 따라 Tcpip 또는 NetBT에 존재 → 양쪽 탐색
$nnr = To-IntOrNull (Get-Reg $tcpPath 'NoNameReleaseOnDemand')
if ($nnr -eq $null) { $nnr = To-IntOrNull (Get-Reg $netbtPath 'NoNameReleaseOnDemand') }

$okSyn = ($syn -ne $null -and $syn -ge 1)
$okDgw = ($dgw -eq 0)
$okKal = ($kal -eq 300000)
$okNnr = ($nnr -eq 1)

$bad = @()
if (-not $okSyn) { $bad += "SynAttackProtect=$(Show $syn)(기준>=1)" }
if (-not $okDgw) { $bad += "EnableDeadGWDetect=$(Show $dgw)(기준 0)" }
if (-not $okKal) { $bad += "KeepAliveTime=$(Show $kal)(기준 300000)" }
if (-not $okNnr) { $bad += "NoNameReleaseOnDemand=$(Show $nnr)(기준 1)" }

$raw54 = "SynAttackProtect=$(Show $syn) / EnableDeadGWDetect=$(Show $dgw) / KeepAliveTime=$(Show $kal) / NoNameReleaseOnDemand=$(Show $nnr)"

if ($bad.Count -eq 0) {
    Add-Result 'W-54' $PASS 'Tcpip | NetBT Parameters' $raw54 "DoS 방어 레지스트리 4개 값 모두 기준 충족 — 양호"
}
else {
    Add-Result 'W-54' $VULN 'Tcpip | NetBT Parameters' ($raw54 + "`n미충족: " + ($bad -join ', ')) "DoS 방어 레지스트리 미설정/불일치 항목 존재 — 취약 (미충족: $($bad -join ', '))"
}

# W-55 프린터 드라이버 설치 제한
$apd = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers'
if ("$apd" -eq '1') { Add-Result 'W-55' $PASS 'AddPrinterDrivers' "값=$apd" "일반 사용자 프린터 드라이버 설치 제한됨" }
else { Add-Result 'W-55' $VULN 'AddPrinterDrivers' "값=$apd" "프린터 드라이버 설치 제한 미설정" }

# W-56 SMB 세션 중단 관리 — 로그온 만료 시 연결 끊기 + 유휴 시간(15분 이하)
$lmPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
$forcedRaw = Get-Reg $lmPath 'EnableForcedLogOff'   # 로그온 시간 만료 시 클라이언트 연결 끊기 (1=사용)
$autoDiscRaw = Get-Reg $lmPath 'AutoDisconnect'     # 세션 중단 전 유휴 시간(분), 15 이하 양호

function To-IntOrNull($v){
    if ($v -eq $null -or "$v" -eq '') { return $null }
    try { return [int]("$v".Trim()) } catch { return $null }
}
$forced   = To-IntOrNull $forcedRaw
$autoDisc = To-IntOrNull $autoDiscRaw

# EnableForcedLogOff 기본값은 1(사용). 미설정이면 기본 사용으로 간주
$forcedOK = ($forced -eq $null -or $forced -eq 1)

# AutoDisconnect: 0~15 양호. 미설정 시 기본값 15분이라 양호로 간주.
# 음수(-1)나 99999는 사실상 해제 → 취약
$autoOK = $false
$autoText = if ($autoDisc -ne $null) { "${autoDisc}분" } else { "미설정(기본15분)" }
if ($autoDisc -eq $null) { $autoOK = $true }                 # 기본 15분
elseif ($autoDisc -ge 0 -and $autoDisc -le 15) { $autoOK = $true }
else { $autoOK = $false }                                    # 16분 이상, -1, 99999 등

$forcedText = if ($forced -eq $null) { "미설정(기본사용)" } elseif ($forced -eq 1) { "사용" } else { "사용 안 함" }
$summary = "EnableForcedLogOff=$forcedText, AutoDisconnect=$autoText"

if ($forcedOK -and $autoOK) {
    Add-Result 'W-56' $PASS 'LanManServer SMB 세션 중단 관리' $summary "로그온 만료 시 연결 끊기 사용 및 유휴 시간 15분 이하 — 양호"
} else {
    $reason = @()
    if (-not $forcedOK) { $reason += "로그온 만료 시 연결 끊기 '사용 안 함'" }
    if (-not $autoOK)   { $reason += "유휴 시간 15분 초과/해제" }
    Add-Result 'W-56' $VULN 'LanManServer SMB 세션 중단 관리' $summary ("취약: " + ($reason -join ', '))
}

# W-57 로그온 경고 메시지 (메시지 없으면 취약)
$lnc = (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeCaption') -as [string]
$lnt = (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeText') -as [string]
$lnc = if ($lnc) { $lnc.Trim() } else { '' }
$lnt = if ($lnt) { $lnt.Trim() } else { '' }
if ($lnc.Length -gt 0 -and $lnt.Length -gt 0) { Add-Result 'W-57' $PASS 'Policies\System\LegalNotice' "Caption='$lnc' / Text 설정됨" "로그온 경고 메시지 설정됨" }
else { Add-Result 'W-57' $VULN 'Policies\System\LegalNotice' "Caption='$lnc' / Text='$lnt'" "로그온 경고 메시지 미설정 — 취약" }

# W-58 사용자별 홈 디렉터리 권한
$udir = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
# 각 사용자 홈 디렉터리를 전수 나열 + Everyone 권한 유무 표기(화면 8줄/CSV 전체)
$badHome=@(); $homeLines=@()
foreach($d in $udir){
    $hasEv = (Get-Acl $d.FullName -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match 'Everyone' }
    if ($hasEv) { $badHome += $d.Name; $homeLines += ("{0} : Everyone 권한 있음" -f $d.FullName) }
    else        { $homeLines += ("{0} : Everyone 권한 없음" -f $d.FullName) }
}
$raw58 = if ($homeLines) { "C:\Users 사용자 디렉터리 $(@($udir).Count)개:`n" + ($homeLines -join "`n") } else { "(점검 대상 사용자 디렉터리 없음)" }
if ($badHome.Count -eq 0) { Add-Result 'W-58' $PASS 'C:\Users 권한' $raw58 "사용자 홈 디렉터리에 Everyone 권한 없음 — 양호" }
else { Add-Result 'W-58' $VULN 'C:\Users 권한' $raw58 "홈 디렉터리에 Everyone 권한 존재: $($badHome -join ', ') — 취약" }

# W-59 LAN Manager 인증 수준
$lm = SecReg 'LmCompatibilityLevel'; if($lm -eq $null){ $lm = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' }
if ([int]$lm -ge $Conf.LmCompatLevelMin) { Add-Result 'W-59' $PASS 'Lsa\LmCompatibilityLevel' "값=$lm" "LAN Manager 인증 수준 $lm (기준 $($Conf.LmCompatLevelMin) 이상)" }
else { Add-Result 'W-59' $VULN 'Lsa\LmCompatibilityLevel' "값=$lm" "LAN Manager 인증 수준이 낮음(NTLMv2 미강제)" }

# W-60 보안 채널 데이터 암호화/서명
$ss = SecReg 'RequireSignOrSeal'; if($ss -eq $null){ $ss = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal' }
if ("$ss" -eq '1') { Add-Result 'W-60' $PASS 'Netlogon\RequireSignOrSeal' "값=$ss" "보안 채널 데이터 디지털 암호화/서명 요구됨" }
else { Add-Result 'W-60' $VULN 'Netlogon\RequireSignOrSeal' "값=$ss" "보안 채널 암호화/서명 미요구" }

# W-61 파일 및 디렉터리 보호 (NTFS)
$sysDrive = try { [System.IO.DriveInfo]::new($env:SystemDrive + '\').DriveFormat } catch { $null }
if (-not $sysDrive) { $sysDrive = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue).FileSystem }
if ($sysDrive -eq 'NTFS') { Add-Result 'W-61' $PASS '파일시스템' "$env:SystemDrive = $sysDrive" "시스템 드라이브 NTFS(권한 관리 가능)" }
elseif (-not $sysDrive) { Add-Result 'W-61' $NA '파일시스템' "$env:SystemDrive 파일시스템 확인 불가" "파일시스템 확인 불가 — 수동 확인" }
else { Add-Result 'W-61' $VULN '파일시스템' "$env:SystemDrive = $sysDrive" "시스템 드라이브가 NTFS 아님(권한 관리 불가)" }

# W-62 시작프로그램 목록 분석 — Run/RunOnce 항목(이름=실행명령)을 전수 나열(화면 8줄/CSV 전체). 의심 항목 수동/AI 확인.
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$runLines = @()
foreach($rk in $runKeys){
    $item = Get-Item $rk -ErrorAction SilentlyContinue
    if ($item) { foreach($p in $item.Property){ $runLines += "[{0}] {1} = {2}" -f ($rk -replace '^HKLM:\\SOFTWARE\\|^HKCU:\\SOFTWARE\\',''), $p, $item.GetValue($p) } }
}
$raw62 = if ($runLines.Count -gt 0) { "시작프로그램(Run/RunOnce) $($runLines.Count)개:`n" + ($runLines -join "`n") } else { "(Run/RunOnce 시작프로그램 항목 없음)" }
Add-Result 'W-62' $NA '시작프로그램(Run/RunOnce 키)' $raw62 "시작프로그램 $($runLines.Count)개 — 의심 항목 등록 여부 수동/AI 확인 대상"

# W-63 도메인 컨트롤러 시간 동기화
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
if ($role -lt 4) { Add-Result 'W-63' $NA '시간 동기화' "역할=$role(비 도메인 컨트롤러)" "도메인 컨트롤러 아님 — W-41(NTP)로 갈음, 수동 확인" }
else { Add-Result 'W-63' $NA 'DC 시간 동기화' "역할=$role(DC)" "DC 시간 동기화 설정 — 수동 확인 대상" }

# W-64 윈도우 방화벽
$fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$fwOff = $fw | Where-Object { -not $_.Enabled }
if ($fw -and -not $fwOff) { Add-Result 'W-64' $PASS 'Windows Firewall' "프로필 Domain/Private/Public 모두 사용" "윈도우 방화벽 모든 프로필 활성화" }
elseif ($fw) { Add-Result 'W-64' $VULN 'Windows Firewall' "비활성 프로필: $(($fwOff.Name) -join ', ')" "윈도우 방화벽 일부 프로필 비활성화" }
else {
    # netsh 폴백
    $ns = netsh advfirewall show allprofiles state 2>$null
    $states = @($ns | Select-String -Pattern '상태|State')
    $offCnt = @($states | Where-Object { $_ -match 'OFF|꺼짐' }).Count
    if ($states.Count -gt 0 -and $offCnt -eq 0) { Add-Result 'W-64' $PASS 'Windows Firewall (netsh)' (($states | ForEach-Object { $_.ToString().Trim() }) -join ' / ') "윈도우 방화벽 모든 프로필 활성화" }
    elseif ($offCnt -gt 0) { Add-Result 'W-64' $VULN 'Windows Firewall (netsh)' (($states | ForEach-Object { $_.ToString().Trim() }) -join ' / ') "윈도우 방화벽 일부 프로필 비활성화" }
    else { Add-Result 'W-64' $NA 'Windows Firewall' "(상태 확인 불가)" "방화벽 상태 — 수동 확인" }
}

# =====================================================================
#  출력 (보고서 TXT + 로우데이터 CSV)
# =====================================================================
$Total=$Results.Count
function Format-Block($r){
    "[{0} ({1}) {2}]" -f $r.Code,$r.Sev,$r.Name
    "점검 결과    : {0}" -f $r.Result
    "점검 파일 명 : {0}" -f $r.File
    "점검 요약    :"
    (Truncate8 $r.Raw) -split "`n" | ForEach-Object { "    $_" }
    "판단 기준    :"
    $r.Std -split "`n" | ForEach-Object { "    $_" }
    "----------------------------------------------------------------"
}
$rep = New-Object System.Collections.ArrayList
[void]$rep.Add( (Show-PreInfo) -join "`n" )
[void]$rep.Add("")
[void]$rep.Add(("[종합] 총 {0}개 | 양호 {1} | 취약 {2} | N/A {3}" -f $Total,$Cnt[$PASS],$Cnt[$VULN],$Cnt[$NA]))
[void]$rep.Add("================================================================")
foreach($r in $Results){ [void]$rep.Add( (Format-Block $r) -join "`n" ) }
[void]$rep.Add("※ 'N/A(수동 확인)' 표기 항목과 취약 항목은 담당자의 실제 설정 검토로 최종 확정 필요.")
# TXT: 한글 호환을 위해 BOM 포함 UTF-8로 저장
[System.IO.File]::WriteAllText($History, ($rep -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

function CsvF($s){ '"' + (($s -replace '"','""') -replace "`r?`n",' | ') + '"' }
$csv = New-Object System.Collections.ArrayList
[void]$csv.Add( (@('항목코드','분류','항목','판단기준','결과','점검내용','조치방법','진단대상','진단대상IP','중요도','점검파일') | ForEach-Object { CsvF $_ }) -join ',' )
foreach($r in $Results){
    $cat = if ($CatMap.ContainsKey($r.Cat)) { $CatMap[$r.Cat] } else { $r.Cat }
    $remed = if ($Remed.ContainsKey($r.Code)) { $Remed[$r.Code] } else { '' }
    [void]$csv.Add( (@($r.Code,$cat,$r.Name,$r.Std,$r.Result,$r.Raw,$remed,$TargetSys,$IP,$r.Sev,$r.File) | ForEach-Object { CsvF $_ }) -join ',' )
}
# CSV: Excel 한글 호환을 위해 BOM 포함 UTF-8로 저장
[System.IO.File]::WriteAllText($RawCsv, ($csv -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

Write-Host "================================================================"
Write-Host ("[종합] 총 {0}개 | 양호 {1} | 취약 {2} | N/A {3}" -f $Total,$Cnt[$PASS],$Cnt[$VULN],$Cnt[$NA])
Write-Host (" 히스토리(TXT)   : {0}" -f $History)
Write-Host (" 로우데이터(CSV) : {0}" -f $RawCsv)
Write-Host "진단 스크립트 종료"
Write-Host ""
$null = Read-Host "Enter 키를 누르면 종료합니다"
