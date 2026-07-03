<#
=====================================================================
 Oracle DBMS 자동 진단 스크립트 (PowerShell) - 통합본 v2 (수정본)
   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 - DBMS(D-01~D-26)
   대상: Windows Server 환경의 Oracle Database (12c~21c)

   [v2 주요 수정]
   - D-04/D-11/D-20 : ORACLE_MAINTAINED='Y'(기본 유지관리 객체) 일괄 제외 -> 오탐 제거
   - D-10/D-14/D-15 : 21c 읽기전용 홈(ORACLE_BASE_HOME)·ADR 기반 경로 탐색,
                      D-10 은 Windows 방화벽 통제까지 반영
   - 버전 감지     : v$instance 에서 직접 조회(이전의 -V 배열/$Matches 누수 버그 수정)
   - D-12          : 버전 정상 인식으로 12cR2+ 는 N/A
   - D-17          : 취약 판정을 (비인가 grantee 존재)로 일원화(소유자 문자열 결함 제거)
   - D-18          : KISA 기준대로 'PUBLIC 에 부여된 Role' 만 점검(기본 패키지 오탐 제거)
   - D-26          : 통합감사 활성 정책 수까지 확인, 빈 값 오판 방지
   - D-06/D-20     : 환경 사실을 설정 목록으로 등록해 자동 판정

   [원칙]
   - 읽기 전용(SELECT + 세션 한정 SET + Get-*), DB 미변경. OS 인증 접속.
   - 결과는 양호/취약/N/A 3종만. N/A 는 해당없음(MSSQL 전용·버전 미해당·조회 불가)뿐.

   사용법(관리자 PowerShell 권장):
     powershell -ExecutionPolicy Bypass -File .\dbms_diag.ps1
=====================================================================
#>
param(
    [string]$ConfigFile = (Join-Path $PSScriptRoot 'dbms_diag.conf.ps1'),
    [string]$OutputDir
)
$ErrorActionPreference = 'SilentlyContinue'
$PASS = '양호'; $VULN = '취약'; $NA = 'N/A'

if (-not (Test-Path $ConfigFile)) { Write-Error "설정 파일 없음: $ConfigFile"; exit 1 }
. $ConfigFile
if ($OutputDir) { $Conf.OutputDir = $OutputDir }

# =====================================================================
#  공용 함수 (DB 접속/버전 조회보다 먼저 정의)
# =====================================================================
function Run-Sql($Query, [switch]$NoPdb) {
    if (-not $script:hasSqlplus) { return $null }
    $pre = "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 4000 LONG 500 TRIMSPOOL ON TAB OFF VERIFY OFF ECHO OFF`n"
    # WHENEVER 를 먼저 선언해 컨테이너 전환 실패 시 즉시 중단(=ROOT 에서 조용히 읽는 오류 방지).
    # NoPdb 지정 시에는 전환하지 않고 접속된 컨테이너(CDB$ROOT 등) 그대로 조회한다.
    $pre += "WHENEVER SQLERROR EXIT SQL.SQLCODE`n"
    if ($Conf.PdbContainer -and -not $NoPdb) {
        $pre += "ALTER SESSION SET CONTAINER=$($Conf.PdbContainer);`n"
    }
    $full = $pre + $Query + "`nEXIT`n"
    try { $out = $full | & $script:sqlplusExe -S -L $Conf.SqlplusConn 2>$null } catch { return $null }
    return (($out | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' }) -join "`n")
}
function Clean-Lines($t){ if (-not $t) { return @() } return @(($t -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and $_ -notmatch 'ORA-\d|SP2-\d' }) }
function Has-Row($t){ foreach ($l in (Clean-Lines $t)) { if ($l -notmatch 'no rows selected') { return $true } } return $false }
function First-Val($t){ $c = Clean-Lines $t; if ($c.Count -gt 0) { return $c[0] } return $null }
function To-In($arr){ if (-not $arr -or @($arr).Count -eq 0) { return "''" } return ("'" + (@($arr) -join "','") + "'") }
# 마커(<<값>>)로 감싼 단일 스칼라를 출력 wrap/패딩과 무관하게 추출.
#   긴 컬럼(VARCHAR2(4000), SYS_CONTEXT 등)이 LINESIZE 로 줄바꿈/공백패딩되어
#   First-Val 이 빈 줄을 잡는 문제를 회피한다. 조회는 ...||'<<'||값||'>>'... 형태로 한다.
function Marked-Val($t){
    if (-not $t) { return $null }
    $m = [regex]::Match(($t -replace "`r?`n",' '), '<<(.*?)>>')
    if ($m.Success) { return ($m.Groups[1].Value -replace '\s','') }
    return $null
}
function Is-Num($v){ return ($v -and ($v -match '^[0-9]+(\.[0-9]+)?$')) }
$InsecureIds = @('Everyone','BUILTIN\Users','\Users','ANONYMOUS LOGON','Authenticated Users')
function Has-InsecureWrite($path){
    $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $acl) { return $null }
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne 'Allow') { continue }
        $id = "$($a.IdentityReference)"; $rt = "$($a.FileSystemRights)"
        $insecure = $false
        foreach ($ii in $InsecureIds) { if ($id -like "*$ii*") { $insecure = $true } }
        if ($insecure -and ($rt -match 'Write|Modify|FullControl|TakeOwnership')) { return $true }
    }
    return $false
}
# ORACLE_MAINTAINED='Y' 계정/롤 제외용 SQL 조각 (D-04/D-11/D-17/D-20 공용)
$ExclMaintUser = "(SELECT username FROM dba_users WHERE oracle_maintained='Y')"
$ExclMaintRole = "(SELECT role FROM dba_roles WHERE oracle_maintained='Y')"

# =====================================================================
#  Oracle 환경 자동 감지 (서비스 -> 환경변수 -> 레지스트리)
# =====================================================================
$svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
       Where-Object { $_.Name -like 'OracleService*' } | Select-Object -First 1
if ($svc) {
    if ($Conf.OracleSid -eq 'auto' -or -not $Conf.OracleSid) { $Conf.OracleSid = $svc.Name -replace 'OracleService','' }
    if (($Conf.OracleHome -eq 'auto' -or -not $Conf.OracleHome) -and $svc.PathName) {
        $p = $svc.PathName -replace '"',''
        if ($p -match '^([^\s]+\.exe)') { $Conf.OracleHome = Split-Path (Split-Path $Matches[1] -Parent) -Parent }
    }
}
if ($Conf.OracleSid -eq 'auto' -or -not $Conf.OracleSid)  { $Conf.OracleSid  = if ($env:ORACLE_SID)  { $env:ORACLE_SID }  else { 'XE' } }
if ($Conf.OracleHome -eq 'auto' -or -not $Conf.OracleHome) { $Conf.OracleHome = if ($env:ORACLE_HOME) { $env:ORACLE_HOME } else { '' } }
if (-not $Conf.OracleHome) {
    foreach ($rp in @('HKLM:\SOFTWARE\ORACLE','HKLM:\SOFTWARE\Wow6432Node\ORACLE')) {
        if (Test-Path $rp) {
            foreach ($sk in (Get-ChildItem $rp -ErrorAction SilentlyContinue)) {
                if ($sk.Name -match 'KEY_') {
                    $oh = (Get-ItemProperty $sk.PSPath -ErrorAction SilentlyContinue).ORACLE_HOME
                    if ($oh) { $Conf.OracleHome = $oh; break }
                }
            }
        }
        if ($Conf.OracleHome) { break }
    }
}

# Oracle 환경 변수 / PATH
$env:ORACLE_HOME = $Conf.OracleHome
$env:ORACLE_SID  = $Conf.OracleSid
$env:NLS_LANG    = 'AMERICAN_AMERICA.AL32UTF8'
if ($Conf.OracleHome) { $env:PATH = "$($Conf.OracleHome)\bin;$env:PATH" }

# sqlplus 위치
$script:sqlplusExe = ''; $script:hasSqlplus = $false
if ($Conf.OracleHome -and (Test-Path (Join-Path $Conf.OracleHome 'bin\sqlplus.exe'))) {
    $script:sqlplusExe = Join-Path $Conf.OracleHome 'bin\sqlplus.exe'; $script:hasSqlplus = $true
} elseif (Get-Command sqlplus.exe -ErrorAction SilentlyContinue) {
    $script:sqlplusExe = 'sqlplus.exe'; $script:hasSqlplus = $true
}

# ORACLE_BASE_HOME / ORACLE_BASE (21c 읽기전용 홈 대응) - 설정/로그 파일 실제 위치
$OraBaseHome = ''; $OraBase = ''
if ($Conf.OracleHome) {
    if (Test-Path (Join-Path $Conf.OracleHome 'bin\orabasehome.exe')) { $OraBaseHome = ((& (Join-Path $Conf.OracleHome 'bin\orabasehome.exe') 2>$null) | Select-Object -First 1) }
    if (Test-Path (Join-Path $Conf.OracleHome 'bin\orabase.exe'))     { $OraBase     = ((& (Join-Path $Conf.OracleHome 'bin\orabase.exe') 2>$null)     | Select-Object -First 1) }
}
# 설정 파일 탐색: TNS_ADMIN -> ORACLE_BASE_HOME\network\admin -> ORACLE_HOME\network\admin
function Find-OraFile($name){
    $cand = @()
    if ($env:TNS_ADMIN) { $cand += (Join-Path $env:TNS_ADMIN $name) }
    if ($Conf.TnsAdmin -and $Conf.TnsAdmin -ne 'auto') { $cand += (Join-Path $Conf.TnsAdmin $name) }
    if ($OraBaseHome)   { $cand += (Join-Path (Join-Path $OraBaseHome 'network\admin') $name) }
    if ($Conf.OracleHome) { $cand += (Join-Path (Join-Path $Conf.OracleHome 'network\admin') $name) }
    foreach ($c in $cand) { if ($c -and (Test-Path $c)) { return $c } }
    if ($cand.Count -gt 0) { return $cand[0] } else { return '' }
}
$SQLNET_ORA   = Find-OraFile 'sqlnet.ora'
$LISTENER_ORA = Find-OraFile 'listener.ora'
$TNSNAMES_ORA = Find-OraFile 'tnsnames.ora'
if ($SQLNET_ORA)   { $env:TNS_ADMIN = Split-Path $SQLNET_ORA -Parent }

# ── 메타/환경 ────────────────────────────────────────────
# 점검 시각 KST 고정 (서버 TZ가 무엇이든 한국시간으로 기록)
$kstNow = try { [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTime]::UtcNow, 'Korea Standard Time') } catch { Get-Date }
$TS     = $kstNow.ToString('yyyy-MM-dd HH:mm:ss')
$TSFile = $kstNow.ToString('yyyyMMdd_HHmmss')
$HostN  = $env:COMPUTERNAME
$Label  = if ($Conf.TargetLabel) { $Conf.TargetLabel } else { $HostN }
$osReg  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$OS     = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
if (-not $OS) { $OS = $osReg.ProductName }
$OSVer  = [string][System.Environment]::OSVersion.Version
if ($osReg.CurrentBuildNumber) { $OSVer = "$OSVer (Build $($osReg.CurrentBuildNumber).$($osReg.UBR))" }
$IP     = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
           Select-Object -First 1).IPAddress

if (-not (Test-Path $Conf.OutputDir)) { New-Item -ItemType Directory -Path $Conf.OutputDir -Force | Out-Null }
$RawCsv = Join-Path $Conf.OutputDir "dbms_diag_raw_${Label}_${TSFile}.csv"
$History = Join-Path $Conf.OutputDir "dbms_diag_history_${Label}_${TSFile}.txt"

# DB 접속 테스트 (진단 분리: ① 접속 자체 ② 컨테이너 전환)
$dbOk = $false
$connDiag = ''      # 사전 정보에 노출할 접속 진단 메시지
if ($script:hasSqlplus) {
    # ① 전환 없이 접속만 시도(ROOT 등 접속된 컨테이너). 접속 가능 여부 먼저 확정.
    $rawConn = Run-Sql "SELECT 'CONN_OK' FROM dual;" -NoPdb
    if ($rawConn -match 'CONN_OK') {
        $dbOk = $true
        # ② PdbContainer 설정 시: 전환 포함 조회가 정상 동작하는지 별도 확인
        if ($Conf.PdbContainer) {
            $rawPdb = Run-Sql "SELECT 'PDB_OK' FROM dual;"
            if ($rawPdb -notmatch 'PDB_OK') {
                # 전환 실패: 본 점검은 NoPdb(접속 컨테이너)로 수행되도록 PdbContainer 무력화
                $connDiag = "[경고] PDB 전환 실패 -> 접속 컨테이너에서 점검. SET CONTAINER 권한 또는 PDB명 확인 필요. (원문: " + (($rawPdb -split "`n")[0]) + ")"
                $Conf.PdbContainer = ''
            }
        }
    } else {
        # 접속 실패: raw 에러 첫 줄을 그대로 노출(ORA-/TNS- 진단용)
        $errLine = if ($rawConn) { (($rawConn -split "`n") | Where-Object { $_ -match 'ORA-|TNS|SP2-|ERROR' } | Select-Object -First 1) } else { '' }
        $connDiag = "[오류] DB 접속 실패. SqlplusConn/리스너/서비스명 확인. (원문: " + ($(if($errLine){$errLine}else{'응답 없음'})) + ")"
    }
}

# 실제 점검이 수행되는 컨테이너명 확인 (PdbContainer 전환이 적용되는지 검증용)
$conName = '확인불가'
if ($dbOk) {
    $cn = Marked-Val (Run-Sql "SELECT '<<'||SYS_CONTEXT('USERENV','CON_NAME')||'>>' FROM dual;")
    if ($cn) { $conName = $cn }
}

# 버전 감지 (DB 우선 -> sqlplus -V 폴백). 배열/$Matches 누수 버그 수정.
$oraVer = '확인불가'; $oraMaj = 0; $oraMin = 0
if ($dbOk) {
    $vf = First-Val (Run-Sql "SELECT version_full FROM v`$instance;")
    if (-not $vf) { $vf = First-Val (Run-Sql "SELECT version FROM v`$instance;") }
    if ($vf -and $vf -match '^([0-9]+)\.([0-9]+)\.') { $oraVer = $vf; $oraMaj = [int]$Matches[1]; $oraMin = [int]$Matches[2] }
}
if ($oraMaj -eq 0 -and $script:hasSqlplus) {
    $vstr = ((& $script:sqlplusExe -V 2>$null) -join ' ')
    $mm = [regex]::Match($vstr, '([0-9]+)\.([0-9]+)\.[0-9]+\.[0-9]+')
    if ($mm.Success) { $oraVer = $mm.Value; $oraMaj = [int]$mm.Groups[1].Value; $oraMin = [int]$mm.Groups[2].Value }
}
# 진단대상 시트 '버전정보'용 — Oracle 버전(확인불가면 그대로)
$VersionMeta = if ($oraVer -and $oraVer -ne '확인불가') { "Oracle $oraVer" } else { '확인불가' }

# ── KISA 판단기준(원문) D-01~26 ── (08_DBMS.pdf 양호/취약 원문, 판단기준 필드용)
$Std=@{}
$Std['D-01']=@{P='기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우';V='기본 계정의 초기 비밀번호 를 변경하지 않거나 잠금설정을 하지 않은 경우'}
$Std['D-02']=@{P='계정 정보를 확인하여 불필요한 계정이 없는 경우';V='인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우'}
$Std['D-03']=@{P='기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우';V='기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되지 않은 경우'}
$Std['D-04']=@{P='관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우';V='관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우'}
$Std['D-05']=@{P='비밀번호 재사용 제한 설정을 적용한 경우';V='비밀번호 재사용 제한 설정을 적용하지 않은 경우'}
$Std['D-06']=@{P='사용자별 계정을 사용하고 있는 경우';V='공용 계정을 사용하고 있는 경우'}
$Std['D-07']=@{P='DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우';V='DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우'}
$Std['D-08']=@{P='해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우';V='해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우'}
$Std['D-09']=@{P='로그인 시도 횟수를 제한하는 값을 설정한 경우';V='로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우'}
$Std['D-10']=@{P='DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우';V='DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한하지 않은 경우'}
$Std['D-11']=@{P='시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우';V='시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우'}
$Std['D-12']=@{P='Listener의 비밀번호가 설정된 경우';V='Listener의 비밀번호가 설정되어 있지 않은 경우'}
$Std['D-13']=@{P='불필요한 ODBC/OLE-DB가 설치되지 않은 경우';V='불필요한 ODBC/OLE-DB가 설치된 경우'}
$Std['D-14']=@{P='주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우';V='주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거하지 않은 경우'}
$Std['D-15']=@{P='Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우';V='Listener 관련 설정 파일에 대한 권한이 일반 사용자로 설정되어 있고, Listener로 파라미터를 변경할 수 없게 옵션이 설정되지 않은 경우'}
$Std['D-16']=@{P='Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우';V='혼합 인증 모드를 사용하고, 활성화된 sa 계정에 대한 강력한 암호 정책 설정을 하지 않은 경우'}
$Std['D-17']=@{P='Audit Table 접근 권한이 관리자 계정으로 설정한 경우';V='Audit Table 접근 권한이 일반 계정으로 설정한 경우'}
$Std['D-18']=@{P='DBA 계정의 Role이 Public으로 설정되지 않은 경우';V='DBA 계정의 Role이 Public으로 설정된 경우'}
$Std['D-19']=@{P='OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우';V='OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 TRUE로 설정되지 않은 경우'}
$Std['D-20']=@{P='Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우';V='Object Owner가 일반 사용자에게도 존재하는 경우'}
$Std['D-21']=@{P='WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우';V='WITH_GRANT_OPTION이 ROLE에 의하여 설정되지 않은 경우'}
$Std['D-22']=@{P='RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우';V='RESOURCE_LIMIT 설정이 FALSE로 되어있는 경우'}
$Std['D-23']=@{P='xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우';V='xp_cmdshell이 활성화 되어 있고, 양호의 조건을 만족하지 않는 경우'}
$Std['D-24']=@{P='제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우';V='제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여된 경우'}
$Std['D-25']=@{P='보안 패치가 적용된 버전을 사용하는 경우';V='보안 패치가 적용되지 않는 버전을 사용하는 경우'}
$Std['D-26']=@{P='DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우';V='DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우'}

# ── KISA 조치 방법(원문) D-01~26 ── (08_DBMS.pdf '조치 방법' 필드 원문 그대로)
$Fix=@{}
$Fix['D-01']='기본(관리자) 계정의 초기 비밀번호 및 권한 정책 변경'
$Fix['D-02']='계정별 용도를 파악한 후 불필요한 계정 삭제'
$Fix['D-03']='기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정'
$Fix['D-04']='관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여'
$Fix['D-05']='PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 파라미터 설정'
$Fix['D-06']='사용자별 계정 생성 및 권한 부여'
$Fix['D-07']='DBMS 구동 계정 변경'
$Fix['D-08']='SHA-256 이상의 암호화 알고리즘 적용'
$Fix['D-09']='로그인 시도 횟수 제한 값 설정'
$Fix['D-10']='DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정'
$Fix['D-11']='시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정'
$Fix['D-12']='Listener 비밀번호 설정'
$Fix['D-13']='불필요한 ODBC/OLE-DB 제거'
$Fix['D-14']='주요 설정 파일 및 디렉터리의 권한 설정 변경'
$Fix['D-15']='주요 파일 및 로그 파일에 대한 권한을 관리자로 제한'
$Fix['D-16']='Windows 인증 모드 사용'
$Fix['D-17']='Audit Table 접근 권한을 관리자 계정으로 제한'
$Fix['D-18']='DBA 계정의 Role 설정에서 Public 그룹 권한 취소'
$Fix['D-19']='OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정을 FALSE로 변경'
$Fix['D-20']='Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정'
$Fix['D-21']='WITH_GRANT_OPTION이 ROLE에 의하여 설정되도록 변경'
$Fix['D-22']='RESOURCE_LIMIT 설정을 TRUE로 설정 변경'
$Fix['D-23']='xp_cmdshell 설정 값을 0 또는 False로 설정'
$Fix['D-24']='guest/public에게 부여된 시스템 확장 저장 프로시저 권한 제거'
$Fix['D-25']='보안 패치가 적용된 버전으로 업데이트'
$Fix['D-26']='DBMS에 대한 감사 로그 저장 정책 수립, 적용'

# 출력 헬퍼 + 분류 표기(PDF 공백) 매핑 + 진단대상
$CatMap=@{'계정관리'='계정 관리';'접근관리'='접근 관리';'옵션관리'='옵션 관리';'패치관리'='패치 관리'}
$TargetSys='DBMS(Oracle)'
function Trunc8($t){ if(-not $t){return '(없음)'}; $l=($t -split "`r?`n"); if($l.Count -le 8){return ($l -join "`n")}; ($l[0..7] -join "`n")+"`n... (이하 $($l.Count-8)줄 생략 — 상세는 로우데이터 CSV 참조)" }   # 화면·TXT 요약 8줄 절단(전문은 CSV)
function StripParen($r){ if($r -and ($r -notmatch "`n") -and ($r -match '^\((.*)\)$')){return $Matches[1]}; $r }
function StdBlock($c){ $s=$Std[$c]; if($s){"양호 : $($s.P)`n취약 : $($s.V)"}else{'(기준 미정의)'} }

# ── 항목 메타 ─────────────────────────────────────────────
$Meta = @{}
function M($c,$sev,$cat,$name){ $Meta[$c]=@{Sev=$sev;Cat=$cat;Name=$name} }
M 'D-01' 상 계정관리 '기본 계정의 비밀번호, 정책 등을 변경하여 사용'
M 'D-02' 상 계정관리 '데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용'
M 'D-03' 상 계정관리 '비밀번호의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정'
M 'D-04' 상 계정관리 '데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에만 허용'
M 'D-05' 중 계정관리 '비밀번호 재사용에 대한 제약 설정'
M 'D-06' 중 계정관리 'DB 사용자 계정을 개별적으로 부여하여 사용'
M 'D-07' 중 계정관리 'root(관리자) 권한으로 서비스 구동 제한'
M 'D-08' 상 계정관리 '안전한 암호화 알고리즘 사용'
M 'D-09' 중 계정관리 '일정 횟수의 로그인 실패 시 잠금정책 설정'
M 'D-10' 상 접근관리 '원격에서 DB 서버로의 접속 제한'
M 'D-11' 상 접근관리 'DBA 이외 인가되지 않은 사용자의 시스템 테이블 접근 제한'
M 'D-12' 상 접근관리 '안전한 리스너 비밀번호 설정 및 사용'
M 'D-13' 중 접근관리 '불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거'
M 'D-14' 중 접근관리 '주요 설정파일·비밀번호 파일 등의 접근 권한 설정'
M 'D-15' 하 접근관리 '리스너 로그 및 trace 파일에 대한 변경 제한'
M 'D-16' 하 접근관리 'Windows 인증 모드 사용'
M 'D-17' 하 옵션관리 'Audit Table 접근 제한'
M 'D-18' 상 옵션관리 '응용프로그램/DBA 계정의 Role이 Public으로 설정 금지'
M 'D-19' 상 옵션관리 'OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES를 FALSE로 설정'
M 'D-20' 하 옵션관리 '인가되지 않은 Object Owner의 제한'
M 'D-21' 중 옵션관리 '인가되지 않은 GRANT OPTION 사용 제한'
M 'D-22' 하 옵션관리 '데이터베이스의 자원 제한 기능을 TRUE로 설정'
M 'D-23' 상 옵션관리 'xp_cmdshell 사용 제한'
M 'D-24' 상 옵션관리 'Registry Procedure 권한 제한'
M 'D-25' 상 패치관리 '주기적 보안 패치 및 벤더 권고사항 적용'
M 'D-26' 상 패치관리 '데이터베이스 감사 기록 설정'

# ── 결과 수집 ─────────────────────────────────────────────
$Results = New-Object System.Collections.ArrayList
$Cnt = @{ $PASS=0; $VULN=0; $NA=0 }
function Add-Result {
    param($Code,$Result,$File,$Raw,$Summary)
    $m = $Meta[$Code]; $Cnt[$Result]++
    $Raw = StripParen $Raw            # 결과 없음(자연어) 단일라인 (…) 괄호 제거
    $std = StdBlock $Code             # 판단기준 원문(양호/취약)
    $fix = if ($Fix.ContainsKey($Code)) { $Fix[$Code] } else { '' }   # 조치방법 원문(가이드 하드코딩)
    [void]$Results.Add([pscustomobject]@{ Code=$Code; Sev=$m.Sev; Name=$m.Name; Cat=$m.Cat; File=$File; Raw=$Raw; Result=$Result; Summary=$Summary; Std=$std; Fix=$fix })
    $clr = switch ($Result) { $PASS {'Green'} $VULN {'Red'} default {'Cyan'} }
    Write-Host ("[{0} ({1}) {2}]" -f $Code,$m.Sev,$m.Name)
    Write-Host ("점검 결과    : {0}" -f $Result) -ForegroundColor $clr
    Write-Host ("점검 파일 명 : {0}" -f $File)
    Write-Host  "점검 요약    :"
    (Trunc8 $Raw) -split "`n" | ForEach-Object { Write-Host ("    " + $_) }
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
    "점검 분류    : DBMS - Oracle"
    "점검 대상    : $HostN"
    "Oracle 버전  : $oraVer"
    "Oracle SID   : $($Conf.OracleSid)"
    "점검 컨테이너: $conName (PdbContainer 설정값: $(if($Conf.PdbContainer){$Conf.PdbContainer}else{'(없음)'}))"
    if ($connDiag) { "접속 진단    : $connDiag" }
    "ORACLE_HOME  : $($Conf.OracleHome)"
    "설정 디렉터리: $(if($SQLNET_ORA){Split-Path $SQLNET_ORA -Parent}else{'(미발견)'})"
    "점검 시각    : $TS"
    "점검 방식    : 읽기 전용(설정 변경 없음), 계정 인증 접속(system)"
    "기준         : KISA 2026 DBMS D-01~D-26 (총 26항목)"
    "설정 파일    : $ConfigFile"
    "================================================================"
}
Show-PreInfo | ForEach-Object { Write-Host $_ }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[경고] 관리자 권한이 아니면 파일 권한/서비스/접속 점검이 부정확할 수 있음" -ForegroundColor Yellow
}
if ($dbOk) { Write-Host "# DB 접속: 성공 (계정 인증)" -ForegroundColor Green }
else       { Write-Host "# DB 접속: 실패 - SQL 기반 항목은 N/A(조회 불가). SqlplusConn/OracleHome/SID 확인" -ForegroundColor Red }
Write-Host ""

# 프로파일 한도 맵 (DEFAULT 상속 해석 포함) - D-03/05/09 공용
$ProfMap = @{}; $OpenProfiles = @()
if ($dbOk) {
    $pr = Run-Sql @'
SELECT profile||'~'||resource_name||'~'||limit FROM dba_profiles
WHERE resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION','PASSWORD_REUSE_MAX','PASSWORD_REUSE_TIME','FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME');
'@
    foreach ($l in (Clean-Lines $pr)) {
        $f = $l -split '~'
        if ($f.Count -eq 3) { $p=$f[0].Trim(); if (-not $ProfMap.ContainsKey($p)) { $ProfMap[$p]=@{} }; $ProfMap[$p][$f[1].Trim()] = $f[2].Trim() }
    }
    $OpenProfiles = @(Clean-Lines (Run-Sql "SELECT DISTINCT profile FROM dba_users WHERE account_status='OPEN';"))
    if ($OpenProfiles.Count -eq 0 -and $ProfMap.ContainsKey('DEFAULT')) { $OpenProfiles = @('DEFAULT') }
}
function Eff($prof,$res){
    if (-not $ProfMap.ContainsKey($prof)) { return $null }
    $v = $ProfMap[$prof][$res]
    if ($v -eq 'DEFAULT' -and $ProfMap.ContainsKey('DEFAULT')) { return $ProfMap['DEFAULT'][$res] }
    return $v
}

# =====================================================================
#  점검 항목 D-01 ~ D-26
# =====================================================================

# ── D-01 기본 계정 초기 비밀번호 변경 ──────────────────────
if ($dbOk) {
    $r = Run-Sql @'
SELECT u.username||'~'||u.account_status FROM dba_users u, dba_users_with_defpwd d
WHERE u.username=d.username ORDER BY u.username;
'@
    $open=@(); $rows=@()
    foreach ($l in (Clean-Lines $r)) { $f=$l -split '~'; if ($f.Count -eq 2) { $rows += "$($f[0].Trim()) ($($f[1].Trim()))"; if ($f[1] -notmatch 'LOCKED|EXPIRED') { $open += $f[0].Trim() } } }
    $raw = if ($rows.Count) { "기본(초기) 비밀번호 보유 계정(상태):`n" + ($rows -join "`n") } else { "기본 비밀번호 보유 계정 없음(모두 변경/제거됨)" }
    if ($open.Count -gt 0) { Add-Result 'D-01' $VULN 'dba_users_with_defpwd' $raw ("초기 비밀번호 미변경 활성 계정: " + ($open -join ', ')) }
    else                   { Add-Result 'D-01' $PASS 'dba_users_with_defpwd' $raw "기본 계정의 초기 비밀번호가 변경/잠금됨" }
} else { Add-Result 'D-01' $NA 'dba_users_with_defpwd' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-02 불필요(데모) 계정 제거/잠금 ───────────────────────
if ($dbOk) {
    $r = Run-Sql ("SELECT username||'~'||account_status FROM dba_users WHERE username IN (" + (To-In $Conf.DemoAccounts) + ");")
    $open = @()
    foreach ($l in (Clean-Lines $r)) { $f=$l -split '~'; if ($f.Count -eq 2 -and $f[1] -notmatch 'LOCKED|EXPIRED') { $open += "$($f[0])($($f[1]))" } }
    # 데모/샘플 계정만으론 '불필요 계정' 전수가 안 되므로(퇴직자·테스트·인가외) 전체 사용자 계정을 수동 검토용으로 함께 제시
    $allAcc = Run-Sql "SELECT username||'~'||account_status FROM dba_users WHERE oracle_maintained='N' ORDER BY username;"
    # 표시는 SQL 구분자(~) 노출 없이 "USER (STATUS)" 형태로 정리
    $fmtAcc = { param($q) $o=@(); foreach ($l in (Clean-Lines $q)) { $f=$l -split '~'; if ($f.Count -eq 2) { $o += "$($f[0].Trim()) ($($f[1].Trim()))" } elseif ($f[0].Trim()) { $o += $f[0].Trim() } }; ,$o }
    $demoFmt = & $fmtAcc $r
    $allFmt  = & $fmtAcc $allAcc
    $demoRaw = if ($demoFmt.Count) { "데모/샘플 계정 상태:`n" + ($demoFmt -join "`n") } else { "조회된 데모/샘플 계정 없음" }
    $raw = $demoRaw + "`n전체 사용자 계정(수동 검토 — 퇴직/테스트/인가외):`n" + $(if ($allFmt.Count) { ($allFmt -join "`n") } else { '(없음)' })
    if ($open.Count -eq 0) { Add-Result 'D-02' $PASS 'dba_users' $raw "데모/샘플 계정이 없거나 모두 잠금/만료 (※ 퇴직·테스트 등 불필요 계정 여부는 위 전체 계정 목록 수동 확인)" }
    else                   { Add-Result 'D-02' $VULN 'dba_users' $raw ("활성 상태 데모/샘플 계정 존재: " + ($open -join ', ')) }
} else { Add-Result 'D-02' $NA 'dba_users' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-03 비밀번호 사용기간/복잡도 (사용 프로파일 전수) ──────
#   KISA 기준: 사용기간(<= PassLifeTimeMax 일) 및 복잡도(VERIFY_FUNCTION) 적용 시 양호.
if ($dbOk) {
    $bad = @(); $rows = @()
    foreach ($p in $OpenProfiles) {
        $life = Eff $p 'PASSWORD_LIFE_TIME'; $vf = Eff $p 'PASSWORD_VERIFY_FUNCTION'
        $rows += "$p : PASSWORD_LIFE_TIME=$life, PASSWORD_VERIFY_FUNCTION=$vf"
        $lifeOk = (Is-Num $life) -and ([double]$life -le $Conf.PassLifeTimeMax)
        $vfOk   = $vf -and ($vf -notin @('NULL','UNLIMITED','DEFAULT',''))
        if (-not ($lifeOk -and $vfOk)) { $bad += "$p(LIFE=$life,VERIFY=$vf)" }
    }
    $raw = "사용 프로파일별 정책(기준 LIFE_TIME<=$($Conf.PassLifeTimeMax)일·VERIFY_FUNCTION 설정):`n" + ($rows -join "`n")
    if ($bad.Count -eq 0) { Add-Result 'D-03' $PASS 'dba_profiles' $raw "모든 사용 프로파일이 사용기간(<= $($Conf.PassLifeTimeMax)일) 및 복잡도(VERIFY_FUNCTION) 충족" }
    else                  { Add-Result 'D-03' $VULN 'dba_profiles' ($raw+"`n미흡: "+($bad -join ', ')) "사용기간/복잡도 정책 미흡 프로파일 존재" }
} else { Add-Result 'D-03' $NA 'dba_profiles' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-04 관리자 권한 최소화 (기본 유지관리 객체 제외) ──────
if ($dbOk) {
    $allow = To-In $Conf.AdminAccounts
    $q = @"
SELECT grantee FROM dba_role_privs WHERE granted_role='DBA'
  AND grantee NOT IN ($allow) AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole
UNION
SELECT username FROM v`$pwfile_users WHERE sysdba='TRUE'
  AND username NOT IN ($allow) AND username NOT IN $ExclMaintUser
  AND username NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
UNION
SELECT grantee FROM dba_sys_privs WHERE admin_option='YES'
  AND grantee NOT IN ($allow) AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole
  AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA');
"@
    $r = Run-Sql $q
    # 양호 근거: 현재 관리자권한(DBA Role / SYSDBA) 보유자 전수 표기
    $holders = Run-Sql "SELECT grantee FROM dba_role_privs WHERE granted_role='DBA' UNION SELECT username||' (SYSDBA)' FROM v`$pwfile_users WHERE sysdba='TRUE' ORDER BY 1;"
    $holdersRaw = "현재 관리자권한(DBA Role/SYSDBA) 보유자:`n" + $(if(Has-Row $holders){ ((Clean-Lines $holders) -join "`n") }else{'(없음)'})
    if (Has-Row $r) { Add-Result 'D-04' $VULN 'dba_role_privs | v$pwfile_users | dba_sys_privs' ($holdersRaw+"`n`n부적합(허용 외) 관리자권한 보유:`n"+$r) "허용 계정 외에 DBA/SYSDBA/ADMIN OPTION 권한 부여됨" }
    else            { Add-Result 'D-04' $PASS 'dba_role_privs | v$pwfile_users | dba_sys_privs' $holdersRaw "관리자 권한이 허용 계정으로 제한됨(기본 유지관리 객체 제외)" }
} else { Add-Result 'D-04' $NA 'dba_role_privs' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-05 비밀번호 재사용 제약 (사용 프로파일 전수) ──────────
#   KISA 기준: REUSE_MAX(>= PassReuseMaxMin) 및 REUSE_TIME(>= PassReuseTimeMin) 설정 시 양호.
if ($dbOk) {
    $bad = @(); $rows = @()
    foreach ($p in $OpenProfiles) {
        $rmax = Eff $p 'PASSWORD_REUSE_MAX'; $rtime = Eff $p 'PASSWORD_REUSE_TIME'
        $rows += "$p : PASSWORD_REUSE_MAX=$rmax, PASSWORD_REUSE_TIME=$rtime"
        $maxOk  = (Is-Num $rmax)  -and ([double]$rmax  -ge $Conf.PassReuseMaxMin)
        $timeOk = (Is-Num $rtime) -and ([double]$rtime -ge $Conf.PassReuseTimeMin)
        if (-not ($maxOk -and $timeOk)) { $bad += "$p(MAX=$rmax,TIME=$rtime)" }
    }
    $raw = "사용 프로파일별 재사용 제약(기준 REUSE_MAX>=$($Conf.PassReuseMaxMin)·REUSE_TIME>=$($Conf.PassReuseTimeMin)):`n" + ($rows -join "`n")
    if ($bad.Count -eq 0) { Add-Result 'D-05' $PASS 'dba_profiles' $raw "모든 사용 프로파일에 재사용 제약(REUSE_MAX>= $($Conf.PassReuseMaxMin), REUSE_TIME>= $($Conf.PassReuseTimeMin)) 설정됨" }
    else                  { Add-Result 'D-05' $VULN 'dba_profiles' ($raw+"`n미흡: "+($bad -join ', ')) "비밀번호 재사용 제약 미설정/미달 프로파일 존재" }
} else { Add-Result 'D-05' $NA 'dba_profiles' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-06 개별 계정 사용 (사용자 생성 계정 중 미확인 개별성=공유 의심) ──
#   상태(OPEN/LOCKED/EXPIRED) 무관하게 사용자 생성(ORACLE_MAINTAINED='N')
#   전체 계정을 열거한다. 잠긴 응용 스키마 계정(예: BOOKSTORE)도 누락 없이 점검.
if ($dbOk) {
    $r06 = Run-Sql "SELECT username||'~'||account_status FROM dba_users WHERE oracle_maintained='N' ORDER BY username;"
    $appList = @()      # 표시용 "USER(STATUS)"
    $appNames = @()     # 판정용 username
    $d06excl = @($Conf.D06ExcludeAccounts)   # PDB 자동생성 관리계정 등 시스템성 계정 제외
    foreach ($l in (Clean-Lines $r06)) {
        $f = $l -split '~'
        $uname = $f[0].Trim()
        if ($d06excl -contains $uname) { continue }   # 점검 대상에서 제외
        if ($f.Count -ge 2) { $appNames += $uname; $appList += "$uname($($f[1]))" }
        elseif ($f.Count -eq 1 -and $uname -ne '') { $appNames += $uname; $appList += $uname }
    }
    $shared = @($appNames | Where-Object { $Conf.IndividualAccounts -notcontains $_ })
    $raw = "사용자 생성 계정: " + ($(if($appList){($appList -join ', ')}else{'없음'}))
    # 계정의 '공유/개별 사용' 여부는 DB 구성만으로 단정할 수 없으므로(운영 형태 확인 필요)
    # 자동 판정은 양호로 두되, 점검자의 수동 확인이 필요함을 요약에 명시한다.
    if ($shared.Count -eq 0) {
        Add-Result 'D-06' $PASS 'dba_users' $raw "응용 계정이 없거나 모두 개별 사용 확인됨"
    } else {
        Add-Result 'D-06' $PASS 'dba_users' ($raw + "`n공유/개별 미확인 계정: " + ($shared -join ', ')) "[수동 진단 필요] 사용자 생성 계정의 공용/개별 사용 여부는 운영 형태 확인이 필요함 - 점검자 검토 요망"
    }
} else { Add-Result 'D-06' $NA 'dba_users' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-07 관리자(LocalSystem) 권한 서비스 구동 제한 ─────────
$svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Oracle*' -or $_.Name -like '*TNSListener*' }
if (-not $svcs) { Add-Result 'D-07' $NA 'Win32_Service' 'Oracle 관련 서비스 미발견' "Oracle 서비스가 감지되지 않음 - 해당없음" }
else {
    $info=@(); $bad=@()
    foreach ($s in $svcs) { $info += "$($s.Name) [$($s.StartName)]"; if ($Conf.HighPrivServiceAccounts -contains $s.StartName) { $bad += "$($s.Name) [$($s.StartName)]" } }
    $raw = "Oracle 서비스 기동 계정:`n" + ($info -join "`n")
    if ($bad.Count -gt 0) { Add-Result 'D-07' $VULN 'Win32_Service' $raw ("고권한 계정으로 구동 중: " + ($bad -join ', ')) }
    else                  { Add-Result 'D-07' $PASS 'Win32_Service' $raw "Oracle 서비스가 전용/제한 계정으로 구동 중" }
}

# ── D-08 안전한 암호화 알고리즘 (password_versions 약한 해시) ──
if ($dbOk) {
    $r = Run-Sql "SELECT username||'~'||password_versions FROM dba_users WHERE account_status='OPEN' ORDER BY username;"
    $pat = ($Conf.WeakPasswordVersions -join '|'); $weak=@(); $rows=@()
    foreach ($l in (Clean-Lines $r)) { $f=$l -split '~'; if ($f.Count -eq 2) { $rows += "$($f[0].Trim()) ($($f[1].Trim()))"; if ($f[1] -match $pat) { $weak += "$($f[0])($($f[1]))" } } }
    $raw = "활성(OPEN) 계정 해시 버전 (약한 해시 기준: $pat):`n" + $(if($rows.Count){($rows -join "`n")}else{'(활성 계정 없음)'})
    if ($weak.Count -gt 0) { Add-Result 'D-08' $VULN 'dba_users.password_versions' ($raw+"`n약한 해시 보유: "+($weak -join ', ')) ("SHA-2 미만 해시($pat) 보유 활성 계정 존재") }
    else                   { Add-Result 'D-08' $PASS 'dba_users.password_versions' $raw "모든 활성 계정이 안전한 해시 사용" }
} else { Add-Result 'D-08' $NA 'dba_users' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-09 로그인 실패 잠금정책 (사용 프로파일 전수) ─────────
#   KISA 기준: FAILED_LOGIN_ATTEMPTS(<= FailedLoginMax 회) 설정 시 양호.
if ($dbOk) {
    $bad = @(); $rows = @()
    foreach ($p in $OpenProfiles) { $fla = Eff $p 'FAILED_LOGIN_ATTEMPTS'; $rows += "$p : FAILED_LOGIN_ATTEMPTS=$fla"; if (-not ((Is-Num $fla) -and ([double]$fla -le $Conf.FailedLoginMax))) { $bad += "$p(FLA=$fla)" } }
    $raw = "사용 프로파일별 로그인 실패 잠금(기준 FAILED_LOGIN_ATTEMPTS<=$($Conf.FailedLoginMax)회):`n" + ($rows -join "`n")
    if ($bad.Count -eq 0) { Add-Result 'D-09' $PASS 'dba_profiles' $raw "모든 사용 프로파일에 로그인 실패 잠금(<= $($Conf.FailedLoginMax)회) 설정됨" }
    else                  { Add-Result 'D-09' $VULN 'dba_profiles' ($raw+"`n미흡: "+($bad -join ', ')) "로그인 실패 잠금 미설정/초과 프로파일 존재(UNLIMITED 포함)" }
} else { Add-Result 'D-09' $NA 'dba_profiles' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-10 원격 접속 제한 (sqlnet.ora valid node checking OR Windows 방화벽) ──
$sqlnetOk = $false; $sqlnetState = '미발견'
if ($SQLNET_ORA -and (Test-Path $SQLNET_ORA)) {
    $c = Get-Content $SQLNET_ORA
    $vn = $c | Where-Object { $_ -match '(?i)tcp\.validnode_checking' -and $_ -match '(?i)yes' -and $_ -notmatch '^\s*#' }
    $iv = $c | Where-Object { $_ -match '(?i)tcp\.invited_nodes' -and $_ -notmatch '^\s*#' }
    if ($vn -and $iv) { $sqlnetOk = $true; $sqlnetState = 'VALIDNODE_CHECKING+INVITED_NODES 설정' } else { $sqlnetState = '설정 미흡' }
}
$fwRestricted = $false; $fwNote = '방화벽 미점검'
try {
    $profs = Get-NetFirewallProfile -ErrorAction Stop
    $fwOn  = (@($profs | Where-Object { $_.Enabled }).Count -eq @($profs).Count)
    $port  = "$($Conf.ListenerPort)"
    $exposed = $false; $has = $false
    $allowRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    foreach ($r in $allowRules) {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $lp = @($pf.LocalPort)
        if ($lp -contains $port -or $lp -contains 'Any') {
            $af = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $ra = @($af.RemoteAddress)
            if ($lp -contains $port) { $has = $true }
            if (($lp -contains $port) -and ($ra -contains 'Any' -or $ra.Count -eq 0)) { $exposed = $true }
        }
    }
    if ($fwOn -and -not $exposed) { $fwRestricted = $true }
    $fwNote = "방화벽 전프로필 활성=$fwOn, ${port} 인바운드 허용규칙=$has, 전체개방=$exposed"
} catch { $fwNote = '방화벽 정보 조회 불가(NetSecurity 모듈 확인)' }
$raw = "sqlnet.ora: $sqlnetState`n$fwNote"
if ($sqlnetOk)         { Add-Result 'D-10' $PASS $SQLNET_ORA $raw "sqlnet.ora IP 접근통제(valid node checking) 적용" }
elseif ($fwRestricted) { Add-Result 'D-10' $PASS '(sqlnet.ora | Windows 방화벽)' $raw "방화벽으로 리스너 포트 외부 노출이 제한됨" }
elseif ($Conf.TrustExternalAccessControl) {
    $extNote = if ($Conf.ExternalAccessControlNote) { $Conf.ExternalAccessControlNote } else { '외부 네트워크 통제로 원격 접속 제한(설정 override)' }
    Add-Result 'D-10' $PASS '(sqlnet.ora | Windows 방화벽 | 외부통제)' ($raw+"`n외부통제 신뢰(override): "+$extNote) "DB(sqlnet)·호스트 방화벽 자체에는 제한 없음 — 외부 네트워크 통제(보안그룹 등) override로 양호 처리(스크립트 미검증, 점검자 증빙 필요)"
}
else                   { Add-Result 'D-10' $VULN '(sqlnet.ora | Windows 방화벽)' $raw "DB(sqlnet.ora)·방화벽 어느 쪽에서도 원격 접속 제한이 확인되지 않음" }

# ── D-11 시스템 테이블 접근 제한 (기본 유지관리 grantee 제외) ──
if ($dbOk) {
    $allow = To-In $Conf.SystemTableAllowed
    $q = @"
SELECT grantee||' : '||privilege FROM dba_sys_privs
  WHERE privilege LIKE '%ANY TABLE%' AND grantee NOT IN ($allow)
  AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole
  AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
UNION
SELECT grantee||' : '||owner||'.'||table_name FROM dba_tab_privs
  WHERE (owner='SYS' OR table_name LIKE 'DBA\_%' ESCAPE '\') AND privilege<>'EXECUTE'
  AND grantee NOT IN ($allow,'PUBLIC')
  AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole
  AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
  AND ROWNUM<=50;
"@
    $r = Run-Sql $q
    $allAny = Run-Sql "SELECT grantee||' : '||privilege FROM dba_sys_privs WHERE privilege LIKE '%ANY TABLE%' AND ROWNUM<=50;"
    $anyRaw = "현재 %ANY TABLE% 시스템권한 보유자:`n" + $(if(Has-Row $allAny){((Clean-Lines $allAny) -join "`n")}else{'(없음)'})
    if (Has-Row $r) { Add-Result 'D-11' $VULN 'dba_sys_privs | dba_tab_privs' ($anyRaw+"`n`n부적합(DBA 외) 시스템 테이블 접근권한:`n"+$r) "DBA 외 계정에 시스템 테이블 접근 권한 부여됨" }
    else            { Add-Result 'D-11' $PASS 'dba_sys_privs | dba_tab_privs' $anyRaw "시스템 테이블이 DBA로 접근 제한됨(부적합 grantee 없음)" }
} else { Add-Result 'D-11' $NA 'dba_sys_privs' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-12 안전한 리스너 비밀번호 (12cR2+ 미지원=해당없음) ────
if ($oraMaj -gt 12 -or ($oraMaj -eq 12 -and $oraMin -ge 2)) {
    Add-Result 'D-12' $NA $LISTENER_ORA "Oracle $oraVer" "Oracle 12cR2 이상은 리스너 비밀번호 미지원 - 해당없음"
} elseif ($LISTENER_ORA -and (Test-Path $LISTENER_ORA)) {
    $pw = Get-Content $LISTENER_ORA | Where-Object { $_ -match '(?i)^\s*PASSWORDS_' -and $_ -notmatch '^\s*#' }
    if ($pw) { Add-Result 'D-12' $PASS $LISTENER_ORA 'PASSWORDS_ 설정 존재' "리스너 비밀번호(PASSWORDS_) 설정됨" }
    else     { Add-Result 'D-12' $VULN $LISTENER_ORA 'PASSWORDS_ 미설정' "listener.ora 에 리스너 비밀번호 미설정" }
} else { Add-Result 'D-12' $VULN $LISTENER_ORA 'listener.ora 미발견' "리스너 설정 파일이 없어 비밀번호 미설정으로 판정" }

# ── D-13 불필요한 ODBC/OLE-DB 데이터 소스 ──────────────────
$dsn = @()
foreach ($p in @('HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\ODBC Data Sources','HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources')) {
    if (Test-Path $p) { foreach ($n in (Get-Item $p).Property) { $dsn += $n } }
}
$dsn = @($dsn | Select-Object -Unique)
$badDsn = @($dsn | Where-Object { $Conf.AllowedOdbcDsn -notcontains $_ })
if ($dsn.Count -eq 0)        { Add-Result 'D-13' $PASS 'Registry ODBC.INI' '등록된 ODBC DSN 없음' "불필요한 ODBC/OLE-DB 데이터 소스 없음" }
elseif ($badDsn.Count -eq 0) { Add-Result 'D-13' $PASS 'Registry ODBC.INI' ("DSN: " + ($dsn -join ', ')) "등록된 DSN이 모두 허용 목록에 포함됨" }
else                         { Add-Result 'D-13' $VULN 'Registry ODBC.INI' ("DSN: " + ($dsn -join ', ')) ("허용 외 ODBC DSN 등록됨: " + ($badDsn -join ', ')) }

# ── D-14 주요 설정/비밀번호 파일 접근 권한 (NTFS ACL) ──────
$files = New-Object System.Collections.ArrayList
foreach ($f in @($LISTENER_ORA,$SQLNET_ORA,$TNSNAMES_ORA)) { if ($f -and (Test-Path $f)) { [void]$files.Add($f) } }
if ($dbOk) {
    $sp = First-Val (Run-Sql "SELECT value FROM v`$parameter WHERE name='spfile';")
    if ($sp -and (Test-Path $sp)) { [void]$files.Add($sp) }
}
# 비밀번호 파일 후보 (읽기전용 홈/베이스 포함)
foreach ($base in @($Conf.OracleHome,$OraBaseHome,$OraBase) | Select-Object -Unique) {
    if (-not $base) { continue }
    foreach ($f in @((Join-Path $base "database\PWD$($Conf.OracleSid).ora"), (Join-Path $base "database\orapw$($Conf.OracleSid)"), (Join-Path $base "dbs\orapw$($Conf.OracleSid)"))) {
        if (Test-Path $f) { [void]$files.Add($f) }
    }
}
$files = @($files | Select-Object -Unique)
if ($files.Count -eq 0) { Add-Result 'D-14' $NA 'Oracle 설정 파일' '점검 대상 파일 미발견' "주요 설정/비밀번호 파일을 찾지 못함 - 해당없음" }
else {
    $bad=@(); foreach ($f in $files) { if ((Has-InsecureWrite $f) -eq $true) { $bad += (Split-Path $f -Leaf) } }
    $raw = "점검 파일: " + (($files | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')
    if ($bad.Count -gt 0) { Add-Result 'D-14' $VULN 'Oracle 설정 파일' $raw ("일반사용자(Everyone/Users 등) 쓰기 권한 존재: " + ($bad -join ', ')) }
    else                  { Add-Result 'D-14' $PASS 'Oracle 설정 파일' $raw "주요 파일에 일반사용자 광범위 쓰기 권한 없음" }
}

# ── D-15 리스너 로그/trace 변경 제한 (ADMIN_RESTRICTIONS=ON + 설정/로그 파일 권한) ──
#   KISA: listener.ora 권한 관리자 제한 AND ADMIN_RESTRICTIONS_<listener>=ON(LSNRCTL SET 변경 차단)
#   둘 다 충족 시 양호. 로그 디렉터리 ACL만 보던 기존 로직은 핵심(ADMIN_RESTRICTIONS) 누락이라 보완.
$adminRestr = $false; $arState = 'listener.ora 미발견'
if ($LISTENER_ORA -and (Test-Path $LISTENER_ORA)) {
    $ar = Get-Content $LISTENER_ORA | Where-Object { $_ -match '(?i)ADMIN_RESTRICTIONS_\w+\s*=\s*ON' -and $_ -notmatch '^\s*#' }
    if ($ar) { $adminRestr = $true; $arState = ($ar | Select-Object -First 1).Trim() } else { $arState = 'ADMIN_RESTRICTIONS_<listener>=ON 미설정' }
}
# 리스너 로그/trace 디렉터리 탐색
$adrBase = ''
if ($dbOk) { $adrBase = First-Val (Run-Sql "SELECT value FROM v`$diag_info WHERE name='ADR Base';") }
if (-not $adrBase -and $OraBase) { $adrBase = $OraBase }
$logDir = ''
foreach ($cand in @(
    $(if($adrBase){ Join-Path $adrBase ("diag\tnslsnr\$HostN\" + $Conf.ListenerName.ToLower() + "\trace") }),
    $(if($adrBase){ Join-Path $adrBase 'diag\tnslsnr' }),
    $(if($Conf.OracleHome){ Join-Path $Conf.OracleHome 'network\log' }) )) {
    if ($cand -and (Test-Path $cand)) { $logDir = $cand; break }
}
# 설정 파일(listener.ora) + 로그 디렉터리/파일의 일반사용자 쓰기 권한 여부
$permBad = $false; $permNote = @()
if ($LISTENER_ORA -and (Test-Path $LISTENER_ORA) -and (Has-InsecureWrite $LISTENER_ORA) -eq $true) { $permBad = $true; $permNote += 'listener.ora 일반사용자 쓰기' }
if ($logDir) {
    if ((Has-InsecureWrite $logDir) -eq $true) { $permBad = $true; $permNote += '로그 디렉터리 일반사용자 쓰기' }
    foreach ($lf in (Get-ChildItem $logDir -Recurse -Filter *.log -ErrorAction SilentlyContinue | Select-Object -First 5)) { if ((Has-InsecureWrite $lf.FullName) -eq $true) { $permBad = $true; $permNote += "$($lf.Name) 일반사용자 쓰기" } }
}
$raw = "ADMIN_RESTRICTIONS: $arState`n로그 경로: " + $(if($logDir){$logDir}else{'미발견'}) + "`n설정/로그 파일 권한: " + $(if($permBad){($permNote -join ', ')}else{'일반사용자 쓰기 권한 없음'})
if ($adminRestr -and -not $permBad) { Add-Result 'D-15' $PASS 'listener.ora | 리스너 로그' $raw "ADMIN_RESTRICTIONS=ON + 설정/로그 파일 관리자 권한 — 비인가 변경 제한 적정" }
else {
    $rs = @(); if (-not $adminRestr) { $rs += 'ADMIN_RESTRICTIONS 미설정(LSNRCTL SET 변경 가능)' }; if ($permBad) { $rs += '설정/로그 파일 권한 과다' }
    Add-Result 'D-15' $VULN 'listener.ora | 리스너 로그' $raw ("리스너 로그/trace 변경 제한 미흡: " + ($rs -join ', '))
}

# ── D-16 Windows 인증 모드 (MSSQL 전용) ────────────────────
Add-Result 'D-16' $NA '(Oracle 대상)' 'MSSQL 전용 항목' "Windows 인증 모드는 MSSQL 전용 - Oracle 진단 해당없음"

# ── D-17 Audit Table 접근 제한 (비인가 grantee 존재 여부로 판정) ──
if ($dbOk) {
    $pv = Run-Sql @"
SELECT grantee||' : '||privilege FROM dba_tab_privs
WHERE table_name IN ('AUD`$','FGA_LOG`$')
  AND grantee NOT IN ('SYS','SYSTEM','DBA','DELETE_CATALOG_ROLE')
  AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole;
"@
    $allAud = Run-Sql "SELECT grantee||' : '||privilege FROM dba_tab_privs WHERE table_name IN ('AUD`$','FGA_LOG`$') AND ROWNUM<=50;"
    $audRaw = "감사테이블(AUD`$/FGA_LOG`$) 접근권한 보유자:`n" + $(if(Has-Row $allAud){((Clean-Lines $allAud) -join "`n")}else{'(없음 — 통합감사 환경이면 정상)'})
    if (Has-Row $pv) { Add-Result 'D-17' $VULN 'dba_tab_privs' ($audRaw+"`n`n비인가(관리자 외) 접근권한:`n"+$pv) "관리자 외 계정에 감사 테이블(AUD`$/FGA_LOG`$) 접근권한 부여됨" }
    else             { Add-Result 'D-17' $PASS 'dba_tab_privs' $audRaw "감사 테이블 접근권한이 관리자 계정으로 제한됨" }
} else { Add-Result 'D-17' $NA 'dba_tab_privs' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-18 Role 이 Public 으로 설정 금지 (KISA 기준: PUBLIC 부여 Role) ──
if ($dbOk) {
    $r = Run-Sql "SELECT granted_role FROM dba_role_privs WHERE grantee='PUBLIC';"
    $pubRoles = @(Clean-Lines $r | Where-Object { $_ -notmatch 'no rows selected' })
    if ($pubRoles.Count -gt 0) { Add-Result 'D-18' $VULN 'dba_role_privs' ("PUBLIC 에 부여된 Role ($($pubRoles.Count)개):`n"+($pubRoles -join "`n")) "PUBLIC 에 Role 이 부여됨(DBA/응용 Role 여부 확인 후 회수)" }
    else                       { Add-Result 'D-18' $PASS 'dba_role_privs' 'PUBLIC 에 부여된 Role: 0개 (없음 확인)' "PUBLIC 에 부여된 Role 없음" }
} else { Add-Result 'D-18' $NA 'dba_role_privs' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-19 OS 인증 우회 파라미터 FALSE ───────────────────────
if ($dbOk) {
    $want = @('os_roles','remote_os_authent','remote_os_roles')
    $r = Run-Sql "SELECT name||'~'||value FROM v`$parameter WHERE name IN ('os_roles','remote_os_authent','remote_os_roles');"
    $valMap=@{}; foreach ($l in (Clean-Lines $r)) { $f=$l -split '~'; if ($f.Count -eq 2) { $valMap[$f[0].Trim().ToLower()] = $f[1].Trim().ToUpper() } }
    # 3개 파라미터를 각각 명시 표기 — 미존재 사유(21c desupported 등)도 그대로 드러내 근거-판정 일치.
    # REMOTE_OS_AUTHENT: 11.1 deprecated → 21c desupported(완전 폐기). 21c+ 에선 원격 OS 인증 기능 자체가 제거되어 v$parameter 미존재 = 우회 위험 없음.
    $trueP=@(); $lines=@()
    foreach ($n in $want) {
        if ($valMap.ContainsKey($n)) { $v=$valMap[$n]; $lines += "$n = $v"; if ($v -eq 'TRUE') { $trueP += $n } }
        elseif ($n -eq 'remote_os_authent' -and $oraMaj -ge 21) { $lines += "$n = (21c desupported·폐기 — 원격 OS 인증 기능 제거, 우회 불가)" }
        else { $lines += "$n = (파라미터 미존재/기본 FALSE)" }
    }
    $raw = "파라미터 상태:`n" + ($lines -join "`n")
    $authentNote = if ($oraMaj -ge 21) { " (remote_os_authent는 21c 폐기로 미존재)" } else { "" }
    if ($trueP.Count -eq 0) { Add-Result 'D-19' $PASS 'v$parameter' $raw ("OS 인증 우회 파라미터 중 TRUE 없음" + $authentNote) }
    else                    { Add-Result 'D-19' $VULN 'v$parameter' $raw ("TRUE 설정 파라미터 존재: " + ($trueP -join ', ')) }
} else { Add-Result 'D-19' $NA 'v$parameter' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-20 인가되지 않은 Object Owner (기본 유지관리/허용 응용스키마 제외) ──
if ($dbOk) {
    $appOwners = To-In $Conf.AppSchemaOwners
    $r = Run-Sql @"
SELECT DISTINCT owner FROM dba_objects
WHERE owner NOT IN $ExclMaintUser
  AND owner NOT IN ($appOwners)
  AND owner <> 'PUBLIC'
  AND owner NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA');
"@
    $own = Clean-Lines $r
    $allOwners = Run-Sql "SELECT DISTINCT owner FROM dba_objects ORDER BY owner;"
    $ownersRaw = "전체 Object 소유자:`n" + ((Clean-Lines $allOwners) -join ', ')
    if ($own.Count -eq 0) { Add-Result 'D-20' $PASS 'dba_objects' ($ownersRaw + "`n→ 비인가(허용 외) 소유자 없음") "Object 소유자가 시스템/허용 응용 스키마로 제한됨" }
    else                  { Add-Result 'D-20' $VULN 'dba_objects' ($ownersRaw + "`n→ 비인가 추정 소유자: "+($own -join ', ')) ("허용 외 스키마가 객체 소유: " + ($own -join ', ') + " (정상 응용 스키마면 설정 AppSchemaOwners 등록)") }
} else { Add-Result 'D-20' $NA 'dba_objects' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-21 인가되지 않은 GRANT OPTION (객체권한 WITH GRANT OPTION) ──
if ($dbOk) {
    $q = @"
SELECT grantee||' : '||owner||'.'||table_name FROM dba_tab_privs
WHERE grantable='YES'
  AND owner NOT IN $ExclMaintUser
  AND grantee NOT IN $ExclMaintUser AND grantee NOT IN $ExclMaintRole
  AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
  AND grantee<>'PUBLIC'
  AND ROWNUM<=50;
"@
    $r = Run-Sql $q
    $allGrant = Run-Sql "SELECT grantee||' : '||owner||'.'||table_name FROM dba_tab_privs WHERE grantable='YES' AND grantee NOT IN $ExclMaintUser AND grantee<>'PUBLIC' AND ROWNUM<=50;"
    $grantRaw = "WITH GRANT OPTION(grantable=YES) 보유 일반계정 객체권한:`n" + $(if(Has-Row $allGrant){((Clean-Lines $allGrant) -join "`n")}else{'(없음)'})
    if (Has-Row $r) { Add-Result 'D-21' $VULN 'dba_tab_privs' $grantRaw "일반사용자에게 객체 GRANT OPTION 부여됨" }
    else            { Add-Result 'D-21' $PASS 'dba_tab_privs' $grantRaw "일반사용자 객체 GRANT OPTION 미부여" }
} else { Add-Result 'D-21' $NA 'dba_tab_privs' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-22 RESOURCE_LIMIT TRUE ───────────────────────────────
#   value(VARCHAR2 긴 컬럼)가 LINESIZE 로 줄바꿈/패딩되어 빈 값으로 잡히던 문제 해결:
#   '<<'||value||'>>' 마커로 감싸 Marked-Val 로 추출한다.
if ($dbOk) {
    $v = Marked-Val (Run-Sql "SELECT '<<'||value||'>>' FROM v`$parameter WHERE name='resource_limit';")
    if (-not $v) { $v = Marked-Val (Run-Sql "SELECT '<<'||value||'>>' FROM v`$system_parameter WHERE name='resource_limit';") }
    $vU = if ($v) { "$v".ToUpper() } else { '' }
    if ($vU -eq 'TRUE')      { Add-Result 'D-22' $PASS 'v$parameter' "RESOURCE_LIMIT=$v" "자원 제한 기능 활성화(TRUE)" }
    elseif ($vU -eq 'FALSE') { Add-Result 'D-22' $VULN 'v$parameter' "RESOURCE_LIMIT=$v" "자원 제한 기능 비활성화(FALSE)" }
    else                     { Add-Result 'D-22' $NA   'v$parameter' "RESOURCE_LIMIT 조회 불가" "파라미터 조회 불가 - 해당없음" }
} else { Add-Result 'D-22' $NA 'v$parameter' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-23 xp_cmdshell (MSSQL 전용) ──────────────────────────
Add-Result 'D-23' $NA '(Oracle 대상)' 'MSSQL 전용 항목' "xp_cmdshell 은 MSSQL 전용 - Oracle 진단 해당없음"

# ── D-24 Registry Procedure (MSSQL 전용) ───────────────────
Add-Result 'D-24' $NA '(Oracle 대상)' 'MSSQL 전용 항목' "Registry Procedure 는 MSSQL 전용 - Oracle 진단 해당없음"

# ── D-25 보안 패치 신선도 ──────────────────────────────────
if ($dbOk) {
    $last = First-Val (Run-Sql "SELECT TO_CHAR(MAX(action_time),'YYYY-MM-DD') FROM dba_registry_sqlpatch;")
    $raw = "최근 패치 적용일: " + ($(if($last){$last}else{'기록 없음'})) + " / 버전: $oraVer"
    if ($last -and ($last -match '^\d{4}-\d{2}-\d{2}$')) {
        $age = ((Get-Date) - [datetime]$last).Days
        if ($age -le $Conf.PatchMaxAgeDays) { Add-Result 'D-25' $PASS 'dba_registry_sqlpatch' ($raw+" (경과 ${age}일)") "최근 $($Conf.PatchMaxAgeDays)일 이내 보안패치 적용 이력 존재" }
        else                                { Add-Result 'D-25' $VULN 'dba_registry_sqlpatch' ($raw+" (경과 ${age}일)") "최근 패치 적용이 $($Conf.PatchMaxAgeDays)일을 초과" }
    } else { Add-Result 'D-25' $VULN 'dba_registry_sqlpatch' $raw "보안패치(RU/CPU) 적용 이력이 확인되지 않음" }
} else { Add-Result 'D-25' $NA 'dba_registry_sqlpatch' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# ── D-26 감사 기록 설정 (AUDIT_TRAIL 또는 통합감사 활성 정책) ──
if ($dbOk) {
    $at  = First-Val (Run-Sql "SELECT value FROM v`$parameter WHERE name='audit_trail';")
    $ua  = First-Val (Run-Sql "SELECT value FROM v`$option WHERE parameter='Unified Auditing';")
    $pol = First-Val (Run-Sql "SELECT TO_CHAR(COUNT(*)) FROM audit_unified_enabled_policies;")
    $atU = if ($at) { "$at".Trim().ToUpper() } else { 'NONE' }
    $uaU = if ($ua) { "$ua".Trim().ToUpper() } else { 'FALSE' }
    $polN = 0; if ($pol -and ("$pol".Trim() -match '^\d+$')) { $polN = [int]("$pol".Trim()) }
    $raw = "AUDIT_TRAIL=$atU / Unified Auditing=$uaU / 활성 통합감사정책 수=$polN"
    if ( ($uaU -eq 'TRUE' -and $polN -gt 0) -or ($atU -ne 'NONE' -and $atU -ne 'FALSE' -and $atU -ne '') ) {
        Add-Result 'D-26' $PASS 'v$parameter | v$option | audit_unified_enabled_policies' $raw "감사 기록(통합감사 정책 또는 AUDIT_TRAIL) 활성화됨"
    } else {
        Add-Result 'D-26' $VULN 'v$parameter | v$option | audit_unified_enabled_policies' $raw "감사 기록이 비활성화(AUDIT_TRAIL=NONE 이고 활성 통합감사 정책 없음)"
    }
} else { Add-Result 'D-26' $NA 'v$parameter' '(DB 미접속)' "DB 조회 불가 - 해당없음" }

# =====================================================================
#  출력 (보고서 TXT + 로우데이터 CSV)
# =====================================================================
$Total = $Results.Count
function Format-Block($r){
    "[{0} ({1}) {2}]" -f $r.Code,$r.Sev,$r.Name
    "점검 결과    : {0}" -f $r.Result
    "점검 파일 명 : {0}" -f $r.File
    "점검 요약    :"
    (Trunc8 $r.Raw) -split "`n" | ForEach-Object { "    $_" }
    "판단 기준    :"
    $r.Std -split "`n" | ForEach-Object { "    $_" }
    "----------------------------------------------------------------"
}
$rep = New-Object System.Collections.ArrayList
[void]$rep.Add( ((Show-PreInfo) -join "`n") )
[void]$rep.Add("")
[void]$rep.Add(("[종합] 총 {0}개 | 양호 {1} | 취약 {2} | N/A {3}" -f $Total,$Cnt[$PASS],$Cnt[$VULN],$Cnt[$NA]))
[void]$rep.Add("================================================================")
foreach($r in $Results){ [void]$rep.Add( ((Format-Block $r) -join "`n") ) }
[void]$rep.Add("※ N/A = 해당없음(MSSQL 전용·버전 미해당·조회 불가). 취약 항목은 담당자 검토 후 조치 권고.")
[System.IO.File]::WriteAllText($History, ($rep -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

function CsvF($s){ '"' + (("$s" -replace '"','""') -replace "`r?`n",' | ') + '"' }
$csv = New-Object System.Collections.ArrayList
# 호스트명/버전정보: 진단대상 시트용 메타 — 첫 데이터 행에만 채워 CSV 경량화(중복 0).
[void]$csv.Add( (@('항목코드','분류','항목','판단기준','결과','점검내용','조치방법','진단대상','진단대상IP','중요도','점검파일','호스트명','버전정보') | ForEach-Object { CsvF $_ }) -join ',' )
$ri = 0
foreach($r in $Results){
    $cat = if ($CatMap.ContainsKey($r.Cat)) { $CatMap[$r.Cat] } else { $r.Cat }
    $h = if ($ri -eq 0) { $HostN } else { '' }
    $v = if ($ri -eq 0) { $VersionMeta } else { '' }
    [void]$csv.Add( (@($r.Code,$cat,$r.Name,$r.Std,$r.Result,$r.Raw,$r.Fix,$TargetSys,$IP,$r.Sev,$r.File,$h,$v) | ForEach-Object { CsvF $_ }) -join ',' )
    $ri++
}
[System.IO.File]::WriteAllText($RawCsv, ($csv -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

Write-Host "================================================================"
Write-Host ("[종합] 총 {0}개 | 양호 {1} | 취약 {2} | N/A {3}" -f $Total,$Cnt[$PASS],$Cnt[$VULN],$Cnt[$NA])
Write-Host (" 히스토리(TXT)   : {0}" -f $History)
Write-Host (" 로우데이터(CSV) : {0}" -f $RawCsv)
Write-Host "진단 스크립트 종료"
Write-Host ""
$null = Read-Host "Enter 키를 누르면 종료합니다"
