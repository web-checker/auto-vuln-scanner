# =====================================================================
#  Windows 서버 자동 진단 설정 (PowerShell, dot-source 됨)
#   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 (Windows W-01~W-64)
#   - win_diag.ps1 이 이 파일을 dot-source 한다.
#   - 읽기 전용. 환경 의존 값(계정명·임계값·서비스목록)을 여기서 입력.
# =====================================================================

$Conf = @{
    # ── 계정 (W-01/W-06/W-14) ─────────────────────────────
    # 변경된 관리자(기본 Administrator) 계정명. 비워두면 'Administrator'면 취약 판정.
    AdminAccountName   = 'mynameisad'
    # 관리자 그룹에 허용된 정상 계정(이 외 계정이 Administrators에 있으면 검토)
    AllowedAdmins      = @('mynameisad')
    # 원격 데스크톱 허용 그룹(과다 여부 참고)
    RDPAllowedGroups   = @('Administrators','Remote Desktop Users')

    # ── 비밀번호/잠금 정책 임계값 (KISA 기준) ─────────────
    PasswordMinLength  = 8        # W-09 최소 길이 (이상)
    MaxPasswordAge     = 90       # W-09 최대 사용기간 일 (이하)
    MinPasswordAge     = 1        # W-09 최소 사용기간 일 (이상)
    PasswordHistory    = 4        # W-09 기억 개수 (이상; KISA 조치 기준 4개)
    LockoutThreshold   = 5        # W-04 계정 잠금 임계값 (1~5, 이하)
    LockoutDuration    = 60       # W-08 계정 잠금 기간 분 (이상)

    # ── 화면보호기/타임아웃 (W-47/W-36) ──────────────────
    ScreenSaverTimeout = 600      # W-47 화면보호기 시간(초) (이하)
    RDPIdleTimeout     = 900000   # W-36 RDP 유휴 타임아웃 ms (설정 존재)

    # ── 인증/암호화 수준 ─────────────────────────────────
    LmCompatLevelMin   = 3        # W-59 LAN Manager 인증 수준 (이상; 5 권고)
    RDPMinEncryption   = 2        # W-28 터미널 암호화 수준 (2=클라이언트호환(중간) 이상; 1=낮음만 취약)
    RDPIdleTimeoutMaxMs= 1800000  # W-36 원격터미널 유휴 타임아웃 (30분 이하)

    # ── 불필요 서비스 (W-18) — 구동 시 취약 ───────────────
    UnnecessaryServices = @(
        'Alerter','Messenger','Telnet','TlntSvr','Simptcp','SNMP','RemoteRegistry',
        'SharedAccess','RemoteAccess','SSDPSRV','upnphost','WebClient','seclogon'
    )

    # ── 출력 ─────────────────────────────────────────────
    OutputDir   = '.\win_diag_result'
    TargetLabel = ''              # 비우면 hostname
}
