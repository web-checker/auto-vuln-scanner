# =====================================================================
#  Oracle DBMS 자동 진단 설정 (PowerShell, dot-source 용) - 수정본 v2
#   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 (DBMS D-01~D-26)
#   - dbms_diag_unified.ps1 이 이 파일을 dot-source 한다.
#   - 읽기 전용 진단. 환경 의존 값(경로·계정·임계값)을 여기서만 수정한다.
#   - 대상: Windows Server 에 설치된 Oracle Database (12c~21c)
#
#   [v2 변경점]
#   - 계정/권한/객체 점검에서 Oracle 기본 유지관리 객체(ORACLE_MAINTAINED='Y')를
#     일괄 제외 -> D-04/D-11/D-20 의 기본계정 대량 오탐 제거.
#   - 설정/로그 파일 경로를 21c 읽기전용 홈(ORACLE_BASE_HOME)·ADR 기반으로 탐색.
#   - 버전은 DB(v$instance)에서 직접 조회.
#   - D-06/D-20 은 환경 사실(개별계정/응용스키마)을 아래 목록에 등록해 자동 판정.
# =====================================================================

$Conf = @{
    # ── Oracle 환경 경로 ('auto' = 서비스/환경변수/레지스트리 자동탐지) ──
    OracleHome   = 'auto'
    OracleSid    = 'auto'
    TnsAdmin     = 'auto'
    ListenerName = 'LISTENER'
    ListenerPort = '1521'    # D-10 방화벽 점검에 사용하는 리스너 포트

    # ── D-10 외부 네트워크 통제 신뢰(override) ───────────────────────
    #   AWS 보안그룹/NACL, 클라우드 방화벽 등 OS에서 조회 불가한 외부 계층이
    #   리스너 포트(1521)의 외부 접근을 제한하는 것이 '확인된' 경우에만 $true.
    #   $true 이면 sqlnet.ora·Windows 방화벽 통제가 없어도 D-10을 양호로 판정한다.
    #   (외부 통제 실재는 점검자가 책임지고 확인해야 함. 기본값 $false = 보수적 취약)
    TrustExternalAccessControl = $true
    ExternalAccessControlNote  = 'AWS 보안그룹이 외부에서 1521 포트 접근을 제한(인가 IP만 허용) - 점검자 확인'

    # ── 접속 (계정 인증: system 계정 사용) ──────────────
    #   기본은 SID/기본서비스 접속(직전 실행에서 접속 성공이 확인된 방식).
    #   멀티테넌트(CDB/PDB) 환경에서는 아래 PdbContainer 로 점검 시점에 PDB 로 전환한다.
    #   ※ EZConnect 직접 접속(...@//host:port/PDB)이 가능한 환경이면 그 방식이 더
    #     확실하지만, 서비스명/리스너 의존성이 커서 기본값은 SID 접속으로 둔다.
    SqlplusConn  = 'system/bookstore1234!'

    # ── PDB 컨테이너 전환 (CDB/PDB 구조 대응) ─────────────
    #   값을 넣으면 각 조회 전에 ALTER SESSION SET CONTAINER 로 해당 PDB 로 전환한다.
    #   전환 성공 여부는 리포트 '사전 정보 > 점검 컨테이너' 에서 반드시 확인할 것.
    #   - 점검 컨테이너가 'XEPDB1' 로 찍히면 정상.
    #   - 'CDB$ROOT' 또는 '확인불가' 면 전환 실패 -> 응용계정/프로파일 오탐 발생.
    #     이 경우 SqlplusConn 을 EZConnect 직접 접속으로 바꾸고 PdbContainer 는 비운다.
    #     예: SqlplusConn='system/bookstore1234!@//localhost:1521/XEPDB1', PdbContainer=''
    PdbContainer = 'XEPDB1'

    # ── D-02 불필요(잠금/제거 권고) 데모 계정 ────────────────────────
    DemoAccounts = @('SCOTT','HR','OE','PM','IX','SH','BI','DEMO','TEST',
                     'GUEST','MDDATA','SPATIAL_CSW_ADMIN_USR','SPATIAL_WFS_ADMIN_USR')

    # ── D-04 정상 DBA 보유 허용 계정 ─────────────────────────────────
    #   (Oracle 기본 유지관리 계정/롤은 자동 제외되므로 여기에 적지 않아도 됨)
    AdminAccounts = @('SYS','SYSTEM')

    # ── D-06 개별 사용 확인된 계정(allowlist) ────────────────────────
    #   사용자 생성(ORACLE_MAINTAINED='N') 활성 계정 중 이 목록에 없는 계정은
    #   '공유 의심'으로 취약 처리(개별성은 DB 구성으로 확인 불가하므로 보수적 판정).
    #   개별 사용이 확인된 계정만 여기에 등록하면 양호로 전환된다.
    IndividualAccounts = @()

    # ── D-06 점검 제외 계정 (기본: 비움) ──────────────────────────────
    #   D-06 은 공용/개별 사용 여부를 자동 단정하지 않고 '수동 진단 필요'로 표기하므로
    #   사용자 생성 계정(PDBADMIN 등)을 제외하지 않고 그대로 노출한다.
    #   특정 계정을 점검에서 완전히 빼고 싶을 때만 여기에 등록한다.
    D06ExcludeAccounts = @()

    # ── D-07 Windows 서비스 고권한 실행 계정(이 계정으로 구동 시 취약) ──
    HighPrivServiceAccounts = @('LocalSystem','NT AUTHORITY\SYSTEM','.\Administrator','Administrator')

    # ── 비밀번호 정책 임계값 (KISA 기준) ──────────────────────────────
    PassLifeTimeMax  = 90    # D-03 PASSWORD_LIFE_TIME (일, 이하면 양호)
    PassReuseMaxMin  = 10    # D-05 PASSWORD_REUSE_MAX (이상이면 양호)
    PassReuseTimeMin = 365   # D-05 PASSWORD_REUSE_TIME (일, 이상이면 양호)
    FailedLoginMax   = 5     # D-09 FAILED_LOGIN_ATTEMPTS (이하면 양호)

    # ── D-08 약한 해시 버전(이 해시를 보유한 OPEN 계정 존재 시 취약) ────
    WeakPasswordVersions = @('10G')

    # ── D-11 시스템 테이블 접근 허용 grantee (기본 유지관리 롤은 자동 제외) ──
    SystemTableAllowed = @('SYS','SYSTEM','DBA')

    # ── D-13 허용 ODBC DSN 이름(이 외 DSN 등록 시 취약. 빈 목록=모든 DSN 취약) ──
    AllowedOdbcDsn = @()

    # ── D-18 (KISA 기준: PUBLIC 에 부여된 Role 존재 시 취약. 추가 옵션 없음) ──

    # ── D-20 인가된(정상) 응용 객체 소유 스키마 ──────────────────────
    #   Oracle 기본 유지관리 스키마는 자동 제외된다. 정상 응용 스키마만 등록.
    #   ※ 이 환경의 응용 스키마 예시로 BOOKSTORE 를 등록함(환경에 맞게 수정).
    AppSchemaOwners = @('BOOKSTORE')

    # ── D-25 패치 신선도: 최근 패치가 이 일수보다 오래되면(또는 없으면) 취약 ──
    PatchMaxAgeDays = 365

    # ── 출력 ─────────────────────────────────────────────────────────
    OutputDir   = '.\dbms_diag_result'
    TargetLabel = ''   # 비우면 hostname 사용
}
