#!/usr/bin/env bash
#############################################################################
# 리눅스(UNIX) 서버 자동 진단 스크립트
#   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 - UNIX(U-01~U-67)
#   대상: Amazon Linux 2023 / RHEL(Fedora) 계열 (systemd)
#
#   - 읽기 전용(READ-ONLY): cat/grep/stat/ls/ps/find/systemctl(상태조회) 등만 사용.
#   - 판정값: 양호 / 취약 / N/A 3가지만.
#   - 출력: 항목별 구조화(콘솔 실시간) + 보고서(TXT) + 로우데이터(CSV).
#   - 일부 판단은 자동화 한계로 '수동 확인' 표기(근거는 제공).
#
#   사용법: sudo ./linux_diag.sh [-c linux_diag.conf] [-o 출력디렉터리]
#############################################################################
set -u
LC_ALL=C.UTF-8 2>/dev/null || true
export TZ='Asia/Seoul'   # 진단 시각 KST 기록(서버 TZ가 UTC여도 점검시각/파일명 KST로)
R_PASS="양호"; R_VULN="취약"; R_NA="N/A"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/linux_diag.conf"; OVERRIDE_OUTPUT=""
while getopts "c:o:h" opt; do case "$opt" in
  c) CONF_FILE="$OPTARG" ;; o) OVERRIDE_OUTPUT="$OPTARG" ;;
  h) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 0 ;;
  *) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 1 ;;
esac; done
[ -f "$CONF_FILE" ] || { echo "[ERROR] 설정 파일 없음: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF_FILE"
[ -n "$OVERRIDE_OUTPUT" ] && OUTPUT_DIR="$OVERRIDE_OUTPUT"

TS="$(date '+%Y-%m-%d %H:%M:%S')"; TS_FILE="$(date '+%Y%m%d_%H%M%S')"
HOSTN="$(hostname 2>/dev/null || echo unknown)"; LABEL="${TARGET_LABEL:-$HOSTN}"
OS_NAME="$( ( . /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME" ) || true )"
[ -z "$OS_NAME" ] && OS_NAME="$(uname -sr 2>/dev/null || echo unknown)"
KERNEL="$(uname -r 2>/dev/null)"
IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -z "$IP_ADDR" ] && IP_ADDR="$HOSTN"
OS_ID="$( ( . /etc/os-release 2>/dev/null && printf '%s' "$ID" ) || true )"
TARGET_SYS="Linux(${OS_ID:-unix})"   # 진단대상(자산 종류) — CSV/화면 공통 표기(호스트 배포판)
VERSION_META="$OS_NAME"              # 진단대상 시트 '버전정보' — Linux 는 OS 버전

mkdir -p "$OUTPUT_DIR" 2>/dev/null || { echo "[ERROR] 출력 디렉터리 생성 실패: $OUTPUT_DIR" >&2; exit 1; }
RAW_CSV="${OUTPUT_DIR}/linux_diag_raw_${LABEL}_${TS_FILE}.csv"
HISTORY="${OUTPUT_DIR}/linux_diag_history_${LABEL}_${TS_FILE}.txt"

F_CODE=(); F_SEV=(); F_NAME=(); F_CAT=(); F_FILE=(); F_RAW=(); F_RESULT=(); F_SUMMARY=(); F_STD=(); F_ACTION=()
CNT_PASS=0; CNT_VULN=0; CNT_NA=0

# ── 항목명/중요도/분류 ─────────────────────────────────────
declare -A NAME SEV ACTION
set_meta(){ NAME[$1]="$3"; SEV[$1]="$2"; }
set_action(){ ACTION[$1]="$2"; }
set_meta U-01 상 "root 계정 원격 접속 제한";            set_meta U-02 상 "비밀번호 관리정책 설정"
set_meta U-03 상 "계정 잠금 임계값 설정";               set_meta U-04 상 "비밀번호 파일 보호"
set_meta U-05 상 "root 이외의 UID '0' 금지";            set_meta U-06 하 "사용자 계정 su 기능 제한"
set_meta U-07 하 "불필요한 계정 제거";                  set_meta U-08 중 "관리자 그룹에 최소한의 계정 포함"
set_meta U-09 하 "계정이 존재하지 않는 GID 금지";       set_meta U-10 중 "동일한 UID 금지"
set_meta U-11 하 "사용자 Shell 점검";                   set_meta U-12 하 "세션 종료 시간 설정"
set_meta U-13 중 "안전한 비밀번호 암호화 알고리즘 사용"
set_meta U-14 상 "root 홈, 패스 디렉터리 권한 및 패스 설정"; set_meta U-15 상 "파일 및 디렉터리 소유자 설정"
set_meta U-16 상 "/etc/passwd 파일 소유자 및 권한 설정";     set_meta U-17 상 "시스템 시작 스크립트 권한 설정"
set_meta U-18 상 "/etc/shadow 파일 소유자 및 권한 설정";     set_meta U-19 상 "/etc/hosts 파일 소유자 및 권한 설정"
set_meta U-20 상 "/etc/(x)inetd.conf 파일 소유자 및 권한 설정"; set_meta U-21 상 "/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
set_meta U-22 상 "/etc/services 파일 소유자 및 권한 설정";   set_meta U-23 상 "SUID,SGID,Sticky bit 설정 파일 점검"
set_meta U-24 상 "사용자/시스템 환경변수 파일 소유자 및 권한 설정"; set_meta U-25 상 "world writable 파일 점검"
set_meta U-26 상 "/dev에 존재하지 않는 device 파일 점검";    set_meta U-27 상 "\$HOME/.rhosts, hosts.equiv 사용 금지"
set_meta U-28 상 "접속 IP 및 포트 제한";                set_meta U-29 하 "hosts.lpd 파일 소유자 및 권한 설정"
set_meta U-30 중 "UMASK 설정 관리";                     set_meta U-31 중 "홈 디렉터리 소유자 및 권한 설정"
set_meta U-32 중 "홈 디렉터리로 지정한 디렉터리의 존재 관리"; set_meta U-33 하 "숨겨진 파일 및 디렉터리 검색 및 제거"
set_meta U-34 상 "Finger 서비스 비활성화";              set_meta U-35 상 "Anonymous FTP 비활성화"
set_meta U-36 상 "r 계열 서비스 비활성화";              set_meta U-37 상 "cron 파일 소유자 및 권한 설정"
set_meta U-38 상 "DoS 공격에 취약한 서비스 비활성화";   set_meta U-39 상 "불필요한 NFS 서비스 비활성화"
set_meta U-40 상 "NFS 접근 통제";                       set_meta U-41 상 "불필요한 automountd 제거"
set_meta U-42 상 "불필요한 RPC 서비스 비활성화";        set_meta U-43 상 "NIS, NIS+ 점검"
set_meta U-44 상 "tftp, talk 서비스 비활성화";          set_meta U-45 상 "메일 서비스 버전 점검"
set_meta U-46 중 "일반 사용자의 메일 서비스 실행 방지"; set_meta U-47 상 "스팸 메일 릴레이 제한"
set_meta U-48 중 "expn, vrfy 명령어 제한";              set_meta U-49 상 "DNS 보안 버전 패치"
set_meta U-50 상 "DNS Zone Transfer 설정";              set_meta U-51 중 "DNS 취약한 동적 업데이트 설정 금지"
set_meta U-52 중 "Telnet 서비스 비활성화";              set_meta U-53 하 "FTP 서비스 정보 노출 제한"
set_meta U-54 중 "암호화되지 않는 FTP 서비스 비활성화"; set_meta U-55 중 "FTP 계정 Shell 제한"
set_meta U-56 하 "FTP 서비스 접근 제어 설정";           set_meta U-57 중 "Ftpusers 파일 설정"
set_meta U-58 중 "불필요한 SNMP 서비스 구동 점검";      set_meta U-59 중 "안전한 SNMP 버전 사용"
set_meta U-60 상 "SNMP Community String 복잡성 설정";   set_meta U-61 상 "SNMP Access Control 설정"
set_meta U-62 하 "로그인 시 경고 메시지 설정";          set_meta U-63 중 "sudo 명령어 접근 관리"
set_meta U-64 상 "주기적 보안 패치 및 벤더 권고사항 적용"
set_meta U-65 중 "NTP 및 시각 동기화 설정";             set_meta U-66 중 "정책에 따른 시스템 로깅 설정"
set_meta U-67 중 "로그 디렉터리 및 파일 권한 설정"

while IFS=$'\t' read -r code action; do ACTION[$code]="$action"; done <<'EOF'
U-01	원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정
U-02	root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수문자를 포함하여 최소 8자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정
U-03	계정 잠금 임계값을 10회 이하로 설정
U-04	비밀번호 암호화 저장·관리 설정
U-05	ŸUID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록 설정Ÿ(사용 중인 계정인 경우 명령어를 통한 조치가 적용되지 않을 수 있으므로 /etc/passwd 파일을 통해 변경)
U-06	PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정
U-07	시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정
U-08	관리자 그룹에 등록된 계정 확인 후 불필요한 계정 제거하도록 설정
U-09	불필요한 그룹이 존재하는 경우 관리자와 검토하여 제거하도록 설정※/etc/group 파일과 /etc/passwd 파일을 비교하여 점검하기를 권고함
U-10	동일한 UID를 가진 사용자 계정의 UID를 중복되지 않도록 변경하도록 설정
U-11	로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin) 쉘 부여 설정
U-12	600초(10분) 동안 입력이 없는 경우 접속된 Session을 끊도록 설정
U-13	SHA-2 이상의 안전한 비밀번호 암호화 알고리즘 적용 설정
U-14	root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 “.”을 PATH 환경변수의 마지막으로 이동하도록 설정※/etc/profile 파일, root 계정, 일반 사용자 계정의 환경설정 파일을 순차적으로 검색하여 확인
U-15	소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정
U-16	/etc/passwd 파일 소유자 및 권한 변경 설정
U-17	시스템 시작 스크립트 파일 소유자 및 권한 변경 설정
U-18	/etc/shadow 파일 소유자 및 권한 변경 설정
U-19	/etc/hosts 파일 소유자 및 권한 변경 설정
U-20	/etc/(x)inetd.conf 파일 소유자 및 권한 변경 설정
U-21	/etc/(r)syslog.conf 파일 소유자 및 권한 변경 설정
U-22	/etc/ services 파일 소유자 및 권한 변경 설정
U-23	Ÿ불필요한 SUID, SGID 권한 또는 해당 파일 제거하도록 설정Ÿ애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정
U-24	환경변수 파일의 일반 사용자 쓰기 권한 제거하도록 설정
U-25	world writable 파일 존재 여부를 확인하고 불필요한 경우 제거하도록 설정
U-26	major, minor number를 가지지 않는 device 파일 제거하도록 설정
U-27	/etc/hosts.equiv, $HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정
U-28	OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 설정
U-29	/etc/hosts.lpd 파일 제거 또는 /etc/hosts.lpd 파일 소유자 및 권한 변경 설정
U-30	설정 파일에 UMASK 값을 022로 설정
U-31	사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거하도록 설정(/etc/passwd 파일에서 홈 디렉토리 확인, 사용자 홈 디렉토리 외 개별적으로 만들어 사용하는 사용자 디렉토리 존재 여부 확인하여 점검)
U-32	홈 디렉토리가 존재하지 않는 계정에 홈 디렉토리 설정 또는 계정 제거하도록 설정
U-33	ls -al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정
U-34	Finger 서비스 비활성화 설정
U-35	공유 서비스의 익명 접근 제한 설정
U-36	불필요한 r 계열 서비스 중지 및 비활성화 설정※NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512) 서비스 중지※rlogin, rsh, rexec 서비스는 backup, 클러스터링 등의 용도로 종종 사용되고 있으므로 해당 서비스 사용 유무를 확인하여 미사용시 서비스 중지※/etc/hosts.equiv 또는 $HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)
U-37	crontab 및 at 명령어 파일 권한 750 이하, cron 및 at 관련 파일 소유자 및 파일 권한 640 이하 설정
U-38	echo, discard, daytime, chargen, ntp, dns, snmp 등의 서비스 비활성화 설정
U-39	NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정※로컬 서버에 마운트 되어 있는 디렉터리 제거 및 공유 디렉터리 제거 후 서비스 중지 가능
U-40	ŸNFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정Ÿ불가피하게 사용 시 접근 통제 설정 및 NFS 설정 파일 접근 권한 644 설정
U-41	automountd 서비스 비활성화 설정
U-42	불필요한 RPC 서비스 중지 및 비활성화 설정
U-43	NIS 관련 서비스 비활성화 설정
U-44	불필요한 tftp, talk, ntalk 서비스 비활성화 설정
U-45	Ÿ메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정Ÿ메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정
U-46	Ÿ메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정Ÿ메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정
U-47	Ÿ메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정Ÿ메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정
U-48	Ÿ메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정Ÿ메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정
U-49	ŸDNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸDNS 서비스 사용 시 패치 관리 정책 수립 및 주기적으로 패치 적용 설정※DNS 서비스의 경우 대부분의 버전에서 취약점이 보고되고 있으므로 OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수리 후 적용
U-50	ŸDNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸDNS 서비스 사용 시 DNS Zone Transfer를 허가된 사용자에게만 전송 허용하도록 설정
U-51	ŸDNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸDNS 서비스 사용 시 일반적으로 동적 업데이트 기능이 필요 없으나 확인 필요함
U-52	Telnet, FTP 등 안전하지 않은 서비스 사용을 중지하고 SSH 설치 및 사용하도록 설정
U-53	ŸFTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸFTP 서비스 사용 시 FTP 설정 파일을 통해 접속 배너 설정※접속 배너에 서비스 이름이나 버전 정보를 노출하지 않는 것을 권고
U-54	암호화되지 않은 FTP 서비스 중지 및 비활성화 설정
U-55	ŸFTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸFTP 서비스 사용 시 FTP 계정에 /bin/false 쉘 부여 설정
U-56	ŸFTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸFTP 서비스 사용 시 접근 제어 설정
U-57	ŸFTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸFTP 서비스 사용 시 root 계정으로 직접 접속할 수 없도록 설정
U-58	SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
U-59	ŸSNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸSNMP 서비스 사용 시 SNMP 버전을 v3 이상으로 적용하도록 설정
U-60	ŸSNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸSNMP 서비스 사용 시 SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상으로 설정
U-61	ŸSNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정ŸSNMP 서비스 사용 시 SNMP 접근 제어 설정하도록 설정
U-62	Telnet, FTP, SMTP, DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정
U-63	/etc/sudoers 파일 소유자 및 권한 변경 설정
U-64	OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정※OS 패치의 경우 지속해서 취약점이 발표되고 있으므로 O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책을 수립하여 적용해야 함
U-65	NTP 설정 및 동기화 주기 설정
U-66	로그 기록 정책을 수립하고, 정책에 따라 (r)syslog.conf 파일을 설정
U-67	디렉터리 내 로그 파일 소유자 및 권한 변경 설정
EOF

# ── KISA 판단기준(원문) U-01~U-67 ── (01_Unix_서버.pdf 양호/취약 원문 그대로, 판단기준 필드용)
declare -A STD_PASS STD_VULN
STD_PASS[U-01]="원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
STD_VULN[U-01]="원격터미널 서비스 사용 시 root 직접 접속을 허용한 경우"
STD_PASS[U-02]="비밀번호 관리 정책이 설정된 경우"
STD_VULN[U-02]="비밀번호 관리 정책이 설정되지 않은 경우"
STD_PASS[U-03]="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
STD_VULN[U-03]="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
STD_PASS[U-04]="쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우"
STD_VULN[U-04]="쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우"
STD_PASS[U-05]="root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
STD_VULN[U-05]="root 계정과 동일한 UID를 갖는 계정이 존재하는 경우"
STD_PASS[U-06]="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우"
STD_VULN[U-06]="su 명령어를 모든 사용자가 사용하도록 설정된 경우"
STD_PASS[U-07]="불필요한 계정이 존재하지 않는 경우"
STD_VULN[U-07]="불필요한 계정이 존재하는 경우"
STD_PASS[U-08]="관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
STD_VULN[U-08]="관리자 그룹에 불필요한 계정이 등록된 경우"
STD_PASS[U-09]="시스템 관리나 운용에 불필요한 그룹이 제거된 경우"
STD_VULN[U-09]="시스템 관리나 운용에 불필요한 그룹이 존재하는 경우"
STD_PASS[U-10]="동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
STD_VULN[U-10]="동일한 UID로 설정된 사용자 계정이 존재하는 경우"
STD_PASS[U-11]="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
STD_VULN[U-11]="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않은 경우"
STD_PASS[U-12]="Session Timeout이 600초(10분) 이하로 설정된 경우"
STD_VULN[U-12]="Session Timeout이 600초(10분) 이하로 설정되지 않은 경우"
STD_PASS[U-13]="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우"
STD_VULN[U-13]="취약한 비밀번호 암호화 알고리즘을 사용하는 경우"
STD_PASS[U-14]="PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"
STD_VULN[U-14]="PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함된 경우"
STD_PASS[U-15]="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
STD_VULN[U-15]="소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우"
STD_PASS[U-16]="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"
STD_VULN[U-16]="/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우"
STD_PASS[U-17]="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
STD_VULN[U-17]="시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우"
STD_PASS[U-18]="/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우"
STD_VULN[U-18]="/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우"
STD_PASS[U-19]="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우"
STD_VULN[U-19]="/etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우"
STD_PASS[U-20]="/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"
STD_VULN[U-20]="/etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
STD_PASS[U-21]="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
STD_VULN[U-21]="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우"
STD_PASS[U-22]="/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우"
STD_VULN[U-22]="/etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우"
STD_PASS[U-23]="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
STD_VULN[U-23]="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우"
STD_PASS[U-24]="홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우"
STD_VULN[U-24]="홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되지 않거나, 홈 디렉터리 환경변수 파일에 root 계정과 소유자 외에 쓰기 권한이 부여된 경우"
STD_PASS[U-25]="world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
STD_VULN[U-25]="world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우"
STD_PASS[U-26]="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
STD_VULN[U-26]="/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우"
STD_PASS[U-27]="rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우"
STD_VULN[U-27]="rlogin, rsh, rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우"
STD_PASS[U-28]="접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우"
STD_VULN[U-28]="접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정하지 않은 경우"
STD_PASS[U-29]="/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우"
STD_VULN[U-29]="/etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
STD_PASS[U-30]="UMASK 값이 022 이상으로 설정된 경우"
STD_VULN[U-30]="UMASK 값이 022 미만으로 설정된 경우"
STD_PASS[U-31]="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우"
STD_VULN[U-31]="홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우"
STD_PASS[U-32]="홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우"
STD_VULN[U-32]="홈 디렉토리가 존재하지 않는 계정이 발견된 경우"
STD_PASS[U-33]="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
STD_VULN[U-33]="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우"
STD_PASS[U-34]="Finger 서비스가 비활성화된 경우"
STD_VULN[U-34]="Finger 서비스가 활성화된 경우"
STD_PASS[U-35]="공유 서비스에 대해 익명 접근을 제한한 경우"
STD_VULN[U-35]="공유 서비스에 대해 익명 접근을 허용한 경우"
STD_PASS[U-36]="불필요한 r 계열 서비스가 비활성화된 경우"
STD_VULN[U-36]="불필요한 r 계열 서비스가 활성화된 경우"
STD_PASS[U-37]="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우"
STD_VULN[U-37]="crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우"
STD_PASS[U-38]="DoS 공격에 취약한 서비스가 비활성화된 경우"
STD_VULN[U-38]="DoS 공격에 취약한 서비스가 활성화된 경우"
STD_PASS[U-39]="불필요한 NFS 서비스 관련 데몬이 비활성화된 경우"
STD_VULN[U-39]="불필요한 NFS 서비스 관련 데몬이 활성화된 경우"
STD_PASS[U-40]="접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우"
STD_VULN[U-40]="접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우"
STD_PASS[U-41]="automountd 서비스가 비활성화된 경우"
STD_VULN[U-41]="automountd 서비스가 활성화된 경우"
STD_PASS[U-42]="불필요한 RPC 서비스가 비활성화된 경우"
STD_VULN[U-42]="불필요한 RPC 서비스가 활성화된 경우"
STD_PASS[U-43]="NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우"
STD_VULN[U-43]="NIS 서비스가 활성화된 경우"
STD_PASS[U-44]="tftp, talk, ntalk 서비스가 비활성화된 경우"
STD_VULN[U-44]="tftp, talk, ntalk 서비스가 활성화된 경우"
STD_PASS[U-45]="메일 서비스 버전이 최신 버전인 경우"
STD_VULN[U-45]="메일 서비스 버전이 최신 버전이 아닌 경우"
STD_PASS[U-46]="일반 사용자의 메일 서비스 실행 방지가 설정된 경우"
STD_VULN[U-46]="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우"
STD_PASS[U-47]="릴레이 제한이 설정된 경우"
STD_VULN[U-47]="릴레이 제한이 설정되어 있지 않은 경우"
STD_PASS[U-48]="noexpn, novrfy 옵션이 설정된 경우"
STD_VULN[U-48]="noexpn, novrfy 옵션이 설정되어 있지 않은 경우"
STD_PASS[U-49]="주기적으로 패치를 관리하는 경우"
STD_VULN[U-49]="주기적으로 패치를 관리하고 있지 않은 경우"
STD_PASS[U-50]="Zone Transfer를 허가된 사용자에게만 허용한 경우"
STD_VULN[U-50]="Zone Transfer를 모든 사용자에게 허용한 경우"
STD_PASS[U-51]="DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우"
STD_VULN[U-51]="DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근통제를 수행하고 있지 않은 경우"
STD_PASS[U-52]="원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우"
STD_VULN[U-52]="원격 접속 시 Telnet 프로토콜을 사용하는 경우"
STD_PASS[U-53]="FTP 접속 배너에 노출되는 정보가 없는 경우"
STD_VULN[U-53]="FTP 접속 배너에 노출되는 정보가 있는 경우"
STD_PASS[U-54]="암호화되지 않은 FTP 서비스가 비활성화된 경우"
STD_VULN[U-54]="암호화되지 않은 FTP 서비스가 활성화된 경우"
STD_PASS[U-55]="FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
STD_VULN[U-55]="FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있지 않은 경우"
STD_PASS[U-56]="특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우"
STD_VULN[U-56]="FTP 서버에 접근 제어 설정을 적용하지 않은 경우"
STD_PASS[U-57]="root 계정 접속을 차단한 경우"
STD_VULN[U-57]="root 계정 접속을 허용한 경우"
STD_PASS[U-58]="SNMP 서비스를 사용하지 않는 경우"
STD_VULN[U-58]="SNMP 서비스를 사용하는 경우"
STD_PASS[U-59]="SNMP 서비스를 v3 이상으로 사용하는 경우"
STD_VULN[U-59]="SNMP 서비스를 v2 이하로 사용하는 경우"
STD_PASS[U-60]="SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우"
STD_VULN[U-60]="아래의 내용 중 하나라도 해당되는 경우"
STD_PASS[U-61]="SNMP 서비스에 접근 제어 설정이 되어 있는 경우"
STD_VULN[U-61]="SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우"
STD_PASS[U-62]="서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
STD_VULN[U-62]="서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우"
STD_PASS[U-63]="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
STD_VULN[U-63]="/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우"
STD_PASS[U-64]="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
STD_VULN[U-64]="패치 적용 정책을 수립하지 않고 주기적으로 패치 관리를 하지 않거나, 패치 관련 내용을 확인하지 않고 적용하지 않고 있는 경우"
STD_PASS[U-65]="NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우"
STD_VULN[U-65]="NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우"
STD_PASS[U-66]="로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우"
STD_VULN[U-66]="로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나, 로그를 남기고 있지 않은 경우"
STD_PASS[U-67]="디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우"
STD_VULN[U-67]="디렉터리 내 로그 파일의 소유자가 root가 아니거나, 권한이 644를 초과하는 경우"

cat_of(){ local n="${1#U-}"; n=$((10#$n))
  if [ "$n" -le 13 ]; then printf '계정 관리'
  elif [ "$n" -le 33 ]; then printf '파일 및 디렉토리 관리'
  elif [ "$n" -le 63 ]; then printf '서비스 관리'
  elif [ "$n" -eq 64 ]; then printf '패치 관리'
  else printf '로그 관리'; fi; }

# ── 헬퍼 ───────────────────────────────────────────────────
perm_of(){ [ -e "$1" ] && stat -L -c '%a' "$1" 2>/dev/null || echo ""; }
owner_of(){ [ -e "$1" ] && stat -L -c '%U:%G' "$1" 2>/dev/null || echo ""; }
stat_line(){ [ -e "$1" ] && stat -L -c '%A (%a) %U:%G  %n' "$1" 2>/dev/null; }
perm_subset(){ [ -n "$1" ] && [ "$(( (8#$1) & ~(8#$2) ))" -eq 0 ]; }   # 파일 권한이 기준 권한의 '칸별 부분집합'이면 통과(통째 정수비교가 아니라 owner/group/other 비트별 판정)
others_has_access(){ local p="$1"; [ -n "$p" ] && [ "$(( 8#$p % 8 ))" -ne 0 ]; }
others_has_write(){ local p="$1"; [ -n "$p" ] && [ "$(( (8#$p % 8) & 2 ))" -ne 0 ]; }
group_has_write(){ local p="$1"; [ -n "$p" ] && [ "$(( ((8#$p/8) % 8) & 2 ))" -ne 0 ]; }
has_cmd(){ command -v "$1" >/dev/null 2>&1; }
# 서비스 구동 여부 (systemd active 또는 프로세스 존재)
svc_running(){ local s
  for s in "$@"; do
    systemctl is-active "$s" 2>/dev/null | grep -q '^active' && return 0
    systemctl is-active "${s}.service" 2>/dev/null | grep -q '^active' && return 0
  done
  return 1; }
svc_enabled(){ local s; for s in "$@"; do systemctl is-enabled "$s" 2>/dev/null | grep -qE 'enabled' && return 0; done; return 1; }
proc_running(){ pgrep -x "$1" >/dev/null 2>&1; }   # 정확 매칭(-f 금지: login/exec 등 generic 오매칭 방지)
# 서비스 구동 상태 표기 통일: svc_stat "<대상 목록>" ["<상태문구>"]  (2번째 생략 시 '비활성')
svc_stat(){ printf '대상 서비스(%s) 구동: %s' "$1" "${2:-비활성}"; }
# login.defs 값
defs(){ grep -E "^[[:space:]]*$1[[:space:]]" "$LOGIN_DEFS" 2>/dev/null | grep -vE '^\s*#' | awk '{print $2}' | tail -1; }

# 점검 요약은 화면·TXT 모두 8줄까지만 출력(전문은 CSV에 전수).
truncate8(){
  printf '%s' "$1" | awk '
    { ln[NR]=$0 }
    END {
      n=NR; lim=(n>8?8:n)
      for (i=1;i<=lim;i++) print ln[i]
      if (n>8) printf "... (이하 %d줄 생략 — 상세는 로우데이터 CSV 참조)\n", n-8
    }'
}
# 화면/보고서(TXT) 출력 블록 — 점검요약은 8줄까지만(전문은 CSV)
# emit_screen CODE SEV NAME STD RESULT RAW FILE ACTION
emit_screen(){
  local action="${8:-}"
  printf '[%s (%s) %s]\n' "$1" "$2" "$3"
  printf '점검 결과    : %s\n' "$5"
  printf '점검 파일 명 : %s\n' "$7"
  printf '점검 요약    :\n'
  if [ -n "$6" ]; then truncate8 "$6" | sed 's/^/    /'; else printf '    (없음)\n'; fi
  printf '판단 기준    :\n'; printf '%s\n' "$4" | sed 's/^/    /'
  printf '조치 방법    :\n'
  if [ -n "$action" ]; then printf '%s\n' "$action" | sed 's/^/    /'; else printf '    (없음)\n'; fi
  printf -- '----------------------------------------------------------------\n'
}
# rec CODE RESULT FILE RAW SUMMARY
rec(){
  local code="$1" result="$2" file="$3" raw="$4" summary="$5"
  local sev="${SEV[$code]}" name="${NAME[$code]}" cat std action; cat="$(cat_of "$code")"; action="${ACTION[$code]:-}"
  case "$result" in
    "$R_PASS") CNT_PASS=$((CNT_PASS+1)) ;;
    "$R_VULN") CNT_VULN=$((CNT_VULN+1)) ;;
    *)         CNT_NA=$((CNT_NA+1)) ;;
  esac
  # 점검내용이 '결과 없음(자연어)'일 때 감싼 괄호 제거 — 전체가 한 줄이고 (…)로 통째 감싸진 경우만.
  case "$raw" in
    *$'\n'*) : ;;
    "("*")") raw="${raw#\(}"; raw="${raw%\)}" ;;
  esac
  # 판단기준(원문) — 양호/취약 모두. CSV·화면 공통.
  std="양호 : ${STD_PASS[$code]:-(기준 미정의)}"$'\n'"취약 : ${STD_VULN[$code]:-(기준 미정의)}"
  local i=${#F_CODE[@]}
  F_CODE[i]="$code"; F_SEV[i]="$sev"; F_NAME[i]="$name"; F_CAT[i]="$cat"
  F_FILE[i]="$file"; F_RAW[i]="$raw"; F_RESULT[i]="$result"; F_SUMMARY[i]="$summary"; F_STD[i]="$std"; F_ACTION[i]="$action"
  emit_screen "$code" "$sev" "$name" "$std" "$result" "$raw" "$file" "$action"
}

show_preinfo(){
  echo "진단 스크립트 시작"
  echo "================================================================"
  echo "[사전 정보]"
  echo "현재 OS      : ${OS_NAME} (kernel ${KERNEL})"
  echo "점검 환경 IP : ${IP_ADDR}"
  if [ "${1:-}" = "full" ]; then   # 히스토리 전용(stdout 출력화면엔 미표기)
    echo "호스트명     : ${HOSTN}"
    echo "버전 정보    : ${VERSION_META}"
  fi
  echo "점검 분류    : INFRA - Linux(UNIX)    [전체 분류: WAS / DB / WEB / INFRA]"
  echo "점검 대상    : ${HOSTN}"
  echo "점검 시각    : ${TS}"
  echo "점검 방식    : 읽기 전용(설정 변경 없음)"
  echo "기준         : KISA 2026 UNIX U-01~U-67 (총 67항목)"
  echo "설정 파일    : ${CONF_FILE}"
  echo "================================================================"
}

#############################################################################
# 계정 관리 U-01 ~ U-13
#############################################################################
diag_u01(){ local raw="" v="" pr tel=""
  # securetty 파일 점검이 아님: 최신 OS(우분투 20.04↑/AL2023 등)는 Telnet이 기본 비활성이며,
  # root 원격 접속 제한은 SSH(PermitRootLogin)로 판단한다.
  pr="$(grep -hiE '^[[:space:]]*PermitRootLogin' "$SSHD_CONFIG" "$SSHD_CONFIG".d/* 2>/dev/null | grep -vE '^\s*#' | tail -1)"
  svc_running telnet telnetd "telnet.socket" && tel="활성" || tel="비활성(미설치/미사용)"
  raw="sshd_config: ${pr:-(PermitRootLogin 미설정 → 기본 prohibit-password)}"$'\n'"Telnet 서비스: ${tel}"
  if has_cmd sshd || [ -f "$SSHD_CONFIG" ]; then
    if printf '%s' "$pr" | grep -qiE 'PermitRootLogin[[:space:]]+(no|prohibit-password|forced-commands-only)'; then v="$R_PASS"
    elif [ -z "$pr" ]; then v="$R_PASS"   # 기본값 prohibit-password
    else v="$R_VULN"; fi
  else v="$R_PASS"; fi
  [ "$v" = "$R_PASS" ] && rec U-01 "$R_PASS" "$SSHD_CONFIG" "$raw" "Telnet 비활성 + SSH root 직접 접속 차단됨" \
    || rec U-01 "$R_VULN" "$SSHD_CONFIG" "$raw" "SSH root 직접 접속 허용(PermitRootLogin yes)"
}

diag_u02(){ local mx mn raw="" v="$R_VULN" pampw="" pwq minlen="" f
  mx="$(defs PASS_MAX_DAYS)"; mn="$(defs PASS_MIN_DAYS)"
  # 활성 PAM 비밀번호 파일 탐지 (RHEL=system-auth / Ubuntu=common-password)
  for f in "$PAM_DIR/system-auth" "$PAM_DIR/password-auth" "$PAM_DIR/common-password"; do [ -e "$f" ] && { pampw="$f"; break; }; done
  pwq="$(grep -hE 'pam_pwquality|pam_cracklib' "$pampw" 2>/dev/null | grep -vE '^\s*#' | head -1)"
  # 최소 길이: pwquality.conf 우선 → PAM 인라인
  minlen="$(grep -iE '^[[:space:]]*minlen[[:space:]]*=' "$PWQUALITY_CONF" 2>/dev/null | grep -vE '^\s*#' | grep -oE '[0-9]+' | head -1)"
  [ -z "$minlen" ] && minlen="$(printf '%s' "$pwq" | grep -oE 'minlen=[0-9]+' | cut -d= -f2 | head -1)"
  # ── raw: 참조 파일별로 실제 설정 라인을 파일경로(#) 헤더와 함께 표기(출처 명확 + 완전성) ──
  local d_lines q_lines p_lines h_lines
  d_lines="$(grep -E '^[[:space:]]*PASS_(MAX|MIN)_DAYS' "$LOGIN_DEFS" 2>/dev/null | sed 's/^[[:space:]]*//' | tr -s ' \t' ' ')"
  q_lines="$(grep -iE 'minlen|[dulo]credit|minclass|maxrepeat|enforce_for_root' "$PWQUALITY_CONF" 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$' | sed 's/^[[:space:]]*//')"
  p_lines="$(grep -E 'pam_pwquality|pam_cracklib|pam_pwhistory|pam_unix' "$pampw" 2>/dev/null | grep -vE '^[[:space:]]*#' | sed 's/^[[:space:]]*//' | tr -s ' \t' ' ')"
  h_lines="$(grep -iE 'remember|enforce_for_root' "$PWHISTORY_CONF" 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$' | sed 's/^[[:space:]]*//')"
  raw="# ${LOGIN_DEFS}"$'\n'"${d_lines:-(PASS_MAX/MIN_DAYS 미설정)}"
  raw="${raw}"$'\n'"# ${PWQUALITY_CONF}"$'\n'"${q_lines:-(활성 복잡도 설정 없음)}"
  raw="${raw}"$'\n'"# ${pampw:-(PAM 비밀번호 파일 없음)}"$'\n'"${p_lines:-(pam_pwquality 미적용)}"
  raw="${raw}"$'\n'"# ${PWHISTORY_CONF}"$'\n'"${h_lines:-(활성 재사용제한 설정 없음 — PAM 인라인 remember 또는 미설정)}"
  # ── 판정: 최대사용기간 ≤기준 + 복잡도 모듈(pam_pwquality) 적용 + 최소길이 ≥기준 ──
  if { [ -n "$mx" ] && [ "$mx" -le "$PASS_MAX_DAYS_MAX" ] 2>/dev/null; } \
     && [ -n "$pwq" ] && { [ -n "$minlen" ] && [ "$minlen" -ge "$PASS_MIN_LEN_MIN" ] 2>/dev/null; }; then v="$R_PASS"; fi
  local files="$LOGIN_DEFS | $PWQUALITY_CONF | ${pampw:-PAM} | $PWHISTORY_CONF"
  [ "$v" = "$R_PASS" ] && rec U-02 "$R_PASS" "$files" "$raw" "비밀번호 관리정책 설정됨(최대사용기간≤${PASS_MAX_DAYS_MAX}·복잡도 pam_pwquality·최소길이≥${PASS_MIN_LEN_MIN})" \
    || rec U-02 "$R_VULN" "$files" "$raw" "비밀번호 관리정책 미흡(최대사용기간/복잡도/최소길이 중 미충족 — 위 파일별 설정 확인)"
}

diag_u03(){ local fl raw deny=""
  fl="$(grep -rhE 'pam_faillock|pam_tally2' "$PAM_DIR" 2>/dev/null | grep -vE '^\s*#')"
  deny="$(printf '%s' "$fl" | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)"
  raw="${fl:-(pam_faillock/pam_tally2 설정 없음)}"
  if [ -n "$deny" ] && [ "$deny" -le "$ACCOUNT_LOCK_MAX" ] 2>/dev/null; then
    rec U-03 "$R_PASS" "$PAM_DIR" "$raw" "계정 잠금 임계값 ${deny} (기준 ${ACCOUNT_LOCK_MAX} 이하)"
  else rec U-03 "$R_VULN" "$PAM_DIR" "$raw" "계정 잠금 임계값 미설정 또는 ${ACCOUNT_LOCK_MAX} 초과"; fi
}

diag_u04(){ local nox raw
  # passwd 2번째 필드가 x/*/! 가 아닌(암호 직접 저장 가능) 계정 — '계정명만' 출력(암호값 노출 금지).
  nox="$(awk -F: '$2!="x" && $2!="*" && $2!="!" {print $1}' "$PASSWD_FILE" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  # shadow는 해시 노출 방지 위해 '내용 미수록' — 존재·권한(stat)만 근거로 표기.
  raw="# ${PASSWD_FILE} 평문 암호필드(2번째 비-x) 계정: ${nox:-없음}"$'\n'"# ${SHADOW_FILE} (해시 노출 방지 — 내용 미수록, 존재·권한만)"$'\n'"$( [ -f "$SHADOW_FILE" ] && stat_line "$SHADOW_FILE" || echo '(파일 없음)' )"
  if [ -z "$nox" ] && [ -f "$SHADOW_FILE" ]; then rec U-04 "$R_PASS" "$PASSWD_FILE | $SHADOW_FILE" "$raw" "쉐도우 비밀번호 사용(passwd 내 암호 미저장)"
  else rec U-04 "$R_VULN" "$PASSWD_FILE | $SHADOW_FILE" "$raw" "쉐도우 미사용 또는 passwd에 암호 평문 저장"; fi
}

diag_u05(){ local u0 raw
  u0="$(awk -F: '$3==0 {print $1}' "$PASSWD_FILE" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  raw="UID 0 계정: ${u0}"
  if [ "$(echo $u0 | tr ' ' '\n' | grep -vxE "$(echo $ADMIN_ACCOUNTS | tr ' ' '|')" | grep -c .)" -eq 0 ]; then
    rec U-05 "$R_PASS" "$PASSWD_FILE" "$raw" "UID 0 계정이 root뿐(동일 UID 0 계정 없음)"
  else rec U-05 "$R_VULN" "$PASSWD_FILE" "$raw" "root 외 UID 0 계정 존재"; fi
}

diag_u06(){ local pw raw grp gname
  pw="$(grep -E 'pam_wheel' "$PAM_DIR/su" 2>/dev/null | grep -vE '^\s*#')"
  # pam_wheel 의 group= 옵션이 있으면 그 그룹, 없으면 기본 wheel. (su 허용 그룹의 멤버를 /etc/group 에서 확인)
  gname="$(printf '%s' "$pw" | grep -oE 'group=[A-Za-z0-9_]+' | cut -d= -f2 | head -1)"; gname="${gname:-wheel}"
  grp="$(grep -E "^(${gname}|sudo):" "$GROUP_FILE" 2>/dev/null)"
  raw="# ${PAM_DIR}/su"$'\n'"${pw:-(pam_wheel 미설정)}"$'\n'"# ${GROUP_FILE} (su 허용 그룹 '${gname}' 멤버)"$'\n'"${grp:-(${gname}/sudo 그룹 없음)}"
  if printf '%s' "$pw" | grep -q 'pam_wheel'; then rec U-06 "$R_PASS" "$PAM_DIR/su | $GROUP_FILE" "$raw" "su를 특정 그룹(pam_wheel: ${gname})으로 제한함"
  else rec U-06 "$R_VULN" "$PAM_DIR/su | $GROUP_FILE" "$raw" "su 사용이 모든 사용자에게 허용됨(pam_wheel 미설정)"; fi
}

diag_u07(){ local found="" raw="" a all
  for a in $UNNECESSARY_ACCOUNTS; do grep -q "^${a}:" "$PASSWD_FILE" 2>/dev/null && found="$found $a"; done
  found="$(echo $found)"
  # 로우데이터엔 전체 계정을 수록 — '불필요' 판단은 사전목록 외 계정도 AI/담당자가 식별해야 하므로.
  all="$(awk -F: '{print $1" (uid="$3", shell="$7")"}' "$PASSWD_FILE" 2>/dev/null)"
  raw="# 불필요(권고 제거) 후보 매칭: ${found:-없음}"$'\n'"# 전체 계정 목록 (불필요 계정 식별용 — 사전목록 외도 검토)"$'\n'"$all"
  if [ -z "$found" ]; then rec U-07 "$R_PASS" "$PASSWD_FILE" "$raw" "사전목록상 불필요 계정 없음 — 그 외 계정의 불필요 여부는 전체 목록 기준 수동/AI 확인"
  else rec U-07 "$R_VULN" "$PASSWD_FILE" "$raw" "불필요(권고 제거) 계정 존재: ${found} — 사용 여부 수동 확인"; fi
}

diag_u08(){ local m raw
  m="$(grep -E '^root:' "$GROUP_FILE" 2>/dev/null | awk -F: '{print $4}')"
  raw="root 그룹(gid 0) 멤버: ${m:-없음}"
  if [ -z "$m" ]; then rec U-08 "$R_PASS" "$GROUP_FILE" "$raw" "관리자 그룹에 불필요한 계정 없음(불필요 계정 포함 여부 수동 확인 권장)"
  else rec U-08 "$R_VULN" "$GROUP_FILE" "$raw" "관리자(root) 그룹에 추가 계정 존재 — 필요 여부 수동 확인"; fi
}

diag_u09(){ local found="" raw g all
  for g in $UNNECESSARY_GROUPS; do grep -q "^${g}:" "$GROUP_FILE" 2>/dev/null && found="$found $g"; done
  found="$(echo $found)"
  # 로우데이터엔 전체 그룹을 수록 — 사전목록 외 불필요 그룹도 식별 가능하도록.
  all="$(awk -F: '{print $1" (gid="$3", 멤버="$4")"}' "$GROUP_FILE" 2>/dev/null)"
  raw="# 불필요(권고 제거) 후보 매칭: ${found:-없음}"$'\n'"# 전체 그룹 목록 (불필요 그룹 식별용)"$'\n'"$all"
  if [ -z "$found" ]; then rec U-09 "$R_PASS" "$GROUP_FILE" "$raw" "사전목록상 불필요 그룹 없음 — 그 외 그룹의 불필요 여부는 전체 목록 기준 수동/AI 확인"
  else rec U-09 "$R_VULN" "$GROUP_FILE" "$raw" "불필요(권고 제거) 그룹 존재: ${found} — 사용 여부 수동 확인"; fi
}

diag_u10(){ local dup raw all
  dup="$(awk -F: '{print $3}' "$PASSWD_FILE" 2>/dev/null | sort | uniq -d | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  # 전체 계정의 UID를 수록(UID 정렬) — 중복 여부를 AI/담당자가 직접 검증 가능하도록.
  all="$(awk -F: '{print $3": "$1}' "$PASSWD_FILE" 2>/dev/null | sort -n)"
  raw="# 중복 UID: ${dup:-없음}"$'\n'"# 전체 계정(UID: 계정명)"$'\n'"$all"
  if [ -z "$dup" ]; then rec U-10 "$R_PASS" "$PASSWD_FILE" "$raw" "동일 UID 계정 없음"
  else rec U-10 "$R_VULN" "$PASSWD_FILE" "$raw" "동일 UID를 가진 계정 존재:${dup}"; fi
}

diag_u11(){ local bad="" raw="" line u sh uid
  while IFS=: read -r u _ uid _ _ _ sh; do
    [ -z "$u" ] && continue
    for s in $SYSTEM_ACCOUNTS; do
      if [ "$u" = "$s" ]; then
        case "$sh" in */nologin|*/false|/bin/sync|"") : ;; *) bad="$bad ${u}(${sh})" ;; esac
      fi
    done
  done < "$PASSWD_FILE"
  # 로우데이터엔 전체 계정:셸 수록 — 로그인 가능 계정의 적정성을 AI/담당자가 판단하도록.
  local all; all="$(awk -F: '{print $1": "$7}' "$PASSWD_FILE" 2>/dev/null)"
  raw="# 로그인 셸 부여된 불필요(시스템) 계정: ${bad:-없음}"$'\n'"# 전체 계정:셸 목록"$'\n'"$all"
  if [ -z "$bad" ]; then rec U-11 "$R_PASS" "$PASSWD_FILE" "$raw" "로그인 불필요(시스템) 계정에 nologin/false 셸 부여됨 — 그 외 계정 셸 적정성은 전체 목록 확인"
  else rec U-11 "$R_VULN" "$PASSWD_FILE" "$raw" "로그인 불필요 계정에 로그인 셸 부여됨:${bad}"; fi
}

diag_u12(){ local t raw hits
  # grep 원문 라인(파일:내용)을 그대로 근거로 표기
  hits="$(grep -rHE '^[[:space:]]*(export[[:space:]]+)?TMOUT[[:space:]=]' "$PROFILE_FILE" /etc/profile.d/ /etc/bashrc /etc/bash.bashrc 2>/dev/null | grep -vE ':[[:space:]]*#' | tr -s ' \t' ' ')"
  t="$(printf '%s' "$hits" | grep -oE 'TMOUT[[:space:]=]+[0-9]+' | grep -oE '[0-9]+' | head -1)"
  raw="${hits:-(TMOUT 설정 라인 없음 — /etc/profile · /etc/profile.d/ · /etc/bashrc)}"
  if [ -n "$t" ] && [ "$t" -le "$SESSION_TIMEOUT_MAX" ] 2>/dev/null; then rec U-12 "$R_PASS" "/etc/profile | /etc/profile.d | /etc/bashrc" "$raw" "세션 타임아웃 ${t}초 (기준 ${SESSION_TIMEOUT_MAX} 이하)"
  else rec U-12 "$R_VULN" "/etc/profile | /etc/profile.d | /etc/bashrc" "$raw" "세션 타임아웃 미설정 또는 ${SESSION_TIMEOUT_MAX}초 초과"; fi
}

diag_u13(){ local em raw d_line p_lines
  # 원문 라인 표기: login.defs ENCRYPT_METHOD + pam_unix 해시 옵션 라인
  d_line="$(grep -iE '^[[:space:]]*ENCRYPT_METHOD' "$LOGIN_DEFS" 2>/dev/null | grep -vE '^[[:space:]]*#' | tr -s ' \t' ' ' | head -1)"
  p_lines="$(grep -rHE 'pam_unix\.so' "$PAM_DIR" 2>/dev/null | grep -iE 'yescrypt|sha512|sha256|md5|bigcrypt|blowfish' | grep -vE ':[[:space:]]*#' | tr -s ' \t' ' ' | head -3)"
  em="$(printf '%s' "$d_line" | awk '{print $2}')"
  [ -z "$em" ] && em="$(printf '%s' "$p_lines" | grep -ioE 'yescrypt|sha512|sha256|md5|bigcrypt|blowfish' | head -1)"
  raw="# ${LOGIN_DEFS}"$'\n'"${d_line:-(ENCRYPT_METHOD 미설정)}"$'\n'"# ${PAM_DIR} (pam_unix 해시 옵션)"$'\n'"${p_lines:-(pam_unix 해시 알고리즘 옵션 라인 없음)}"
  case "$(printf '%s' "$em" | tr 'A-Z' 'a-z')" in
    sha512|sha256|yescrypt|sha-512|sha-256) rec U-13 "$R_PASS" "$LOGIN_DEFS | $PAM_DIR" "$raw" "SHA-2 이상 안전한 암호화 알고리즘 사용(${em})" ;;
    *) rec U-13 "$R_VULN" "$LOGIN_DEFS | $PAM_DIR" "$raw" "취약하거나 미확인 암호화 알고리즘(SHA-2 이상 권고)" ;;
  esac
}

#############################################################################
# 파일 및 디렉터리 U-14 ~ U-33
#############################################################################
diag_u14(){ local p raw
  # root 의 '실제' 로그인 PATH 평가 (기존 grep은 /etc/profile 의 pathmunge 함수 본문 'PATH=$1:$PATH' 를 오매칭했음)
  p="$(runuser -l root -c 'printf "%s" "$PATH"' 2>/dev/null)"
  [ -z "$p" ] && p="$PATH"
  raw="root 로그인 PATH = ${p}"
  if printf '%s' "$p" | grep -qE '(^|:)\.(:|$)|::'; then rec U-14 "$R_VULN" "root 로그인 PATH (runuser -l root)" "$raw" "PATH에 '.'(현재 디렉터리) 또는 빈 항목(::) 포함"
  else rec U-14 "$R_PASS" "root 로그인 PATH (runuser -l root)" "$raw" "PATH에 '.'/빈 항목 미포함"; fi
}

diag_u15(){ local n raw
  n="$(find / -xdev \( -nouser -o -nogroup \) ! -path '/proc/*' 2>/dev/null | head -5)"
  raw="소유자/그룹 없는 파일(표본): ${n:-없음}"
  if [ -z "$n" ]; then rec U-15 "$R_PASS" "/ (xdev)" "$raw" "소유자가 존재하지 않는 파일/디렉터리 없음"
  else rec U-15 "$R_VULN" "/ (xdev)" "$raw" "소유자/그룹이 존재하지 않는 파일/디렉터리 존재"; fi
}

# 공통 파일 권한 점검: code file ownerregex maxperm
chk_file_perm(){ local code="$1" f="$2" ownre="$3" mx="$4"
  if [ ! -e "$f" ]; then rec "$code" "$R_NA" "$f" "(파일 없음)" "${f} 없음 — 미해당"; return; fi
  local p o raw reason=""; p="$(perm_of "$f")"; o="$(owner_of "$f")"; raw="$(stat_line "$f")"
  printf '%s' "$o" | grep -qiE "^(${ownre}):" || reason="소유자 부적정(${o}, 기준 ${ownre})"
  perm_subset "$p" "$mx" || reason="${reason:+$reason / }권한 과다(${p} — 기준 ${mx} 부분집합 아님)"
  if [ -z "$reason" ]; then rec "$code" "$R_PASS" "$f" "$raw" "소유자 적정 + 권한 ${p} (기준 ${mx} 충족)"
  else rec "$code" "$R_VULN" "$f" "$raw" "$reason"; fi
}

diag_u16(){ chk_file_perm U-16 "$PASSWD_FILE" "root" "$PERM_PASSWD_MAX"; }
diag_u17(){ local bad="" raw="" f p
  # 존재하는 시스템 시작 스크립트 파일을 stat(권한 표현)으로 그대로 표기
  for f in /etc/rc.d/init.d/* /etc/init.d/* /etc/rc.d/rc.local /etc/rc.local /etc/rc.d/rc.sysinit; do
    [ -e "$f" ] || continue
    raw="${raw}$(stat_line "$f")"$'\n'
    p="$(perm_of "$f")"; others_has_write "$p" && bad="$bad $(basename "$f")(${p})"
  done
  [ -z "$raw" ] && raw="(점검 대상 시작 스크립트 파일 없음 — systemd 유닛으로 관리)"
  if [ -z "$bad" ]; then rec U-17 "$R_PASS" "/etc/rc.d/init.d | /etc/init.d | /etc/rc.local" "$raw" "시스템 시작 스크립트 소유자 root + 일반사용자 쓰기 권한 없음"
  else rec U-17 "$R_VULN" "/etc/rc.d/init.d | /etc/init.d | /etc/rc.local" "$raw" "시작 스크립트에 일반사용자 쓰기 권한 존재:${bad}"; fi
}
diag_u18(){ chk_file_perm U-18 "$SHADOW_FILE" "root" "$PERM_SHADOW_MAX"; }
diag_u19(){ chk_file_perm U-19 "$HOSTS_FILE" "root" "$PERM_HOSTS_MAX"; }
diag_u20(){
  if [ ! -e "$INETD_CONF" ] && [ ! -d "$XINETD_DIR" ]; then
    # inetd/xinetd 미설치 시 systemd socket 활성화 방식을 사용하므로 활성 socket 유닛을 추가 확인
    local socks; socks="$(systemctl list-units --type=socket --state=active --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    rec U-20 "$R_NA" "$INETD_CONF | systemd .socket 유닛" "(inetd/xinetd 미설치)"$'\n'"systemd 활성 socket 유닛: ${socks:-없음}" "inetd/xinetd 미사용 — systemd socket 활성화 방식 사용(불필요 socket 유닛 노출 여부 수동 확인)"
  else chk_file_perm U-20 "$INETD_CONF" "root" "$PERM_INETD_MAX"; fi
}
diag_u21(){ chk_file_perm U-21 "$SYSLOG_CONF" "root|bin|sys|syslog" "$PERM_SYSLOG_MAX"; }
diag_u22(){ chk_file_perm U-22 "$SERVICES_FILE" "root|bin|sys" "$PERM_SERVICES_MAX"; }

diag_u23(){ local suid sgid nsuid nsgid raw
  # SUID/SGID 파일 전부를 stat(권한 표현)로 나열 + 개수. 불필요/악성 여부는 목록 대조로 수동 판별(N/A).
  suid="$(find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -type f -perm -4000 -print 2>/dev/null | while IFS= read -r f; do stat_line "$f"; done | sed '/^$/d')"
  sgid="$(find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -type f -perm -2000 -print 2>/dev/null | while IFS= read -r f; do stat_line "$f"; done | sed '/^$/d')"
  nsuid="$(printf '%s' "$suid" | grep -c .)"; nsgid="$(printf '%s' "$sgid" | grep -c .)"
  raw="# SUID (find / -type f -perm -4000) — ${nsuid}개"$'\n'"${suid:-(없음)}"$'\n'"# SGID (find / -type f -perm -2000) — ${nsgid}개"$'\n'"${sgid:-(없음)}"
  rec U-23 "$R_NA" "find / -perm -4000 | -2000" "$raw" "SUID ${nsuid}개 · SGID ${nsgid}개 — 불필요/악성 여부 목록 수동 확인 대상"
}

diag_u24(){ local bad="" raw="" u sh h f p o
  # 로그인 가능한 계정(셸이 nologin/false 아님)별로 홈 디렉터리 환경변수 파일을 각각 나열·점검.
  #   기준: 소유자=root 또는 해당 계정 + 일반사용자(other) 쓰기 권한 없음.
  while IFS=: read -r u _ _ _ _ h sh; do
    [ -z "$u" ] && continue
    case "$sh" in */nologin|*/false|/bin/sync|"") continue ;; esac
    [ -d "$h" ] || continue
    raw="${raw}# ${u} (${h})"$'\n'
    for f in "$h/.profile" "$h/.bashrc" "$h/.bash_profile" "$h/.bash_login" "$h/.cshrc" "$h/.login" "$h/.kshrc" "$h/.zshrc"; do
      [ -e "$f" ] || continue
      raw="${raw}$(stat_line "$f")"$'\n'
      p="$(perm_of "$f")"; o="$(owner_of "$f")"
      { others_has_write "$p" || ! printf '%s' "$o" | grep -qiE "^(root|${u}):"; } && bad="$bad ${f}(${o},${p})"
    done
  done < "$PASSWD_FILE"
  [ -z "$raw" ] && raw="(로그인 가능 계정의 환경변수 파일 없음)"
  if [ -z "$bad" ]; then rec U-24 "$R_PASS" "로그인 계정 홈 환경변수 파일" "$raw" "환경변수 파일 소유자(root/해당계정) 적정 + 일반사용자 쓰기 권한 없음"
  else rec U-24 "$R_VULN" "로그인 계정 홈 환경변수 파일" "$raw" "환경변수 파일 소유자 부적정 또는 일반사용자 쓰기 권한:${bad}"; fi
}

diag_u25(){ local ww raw n
  # find / -type f -perm -0002 (other 쓰기 가능) 의 '모든' 파일을 stat(ls -l 형식)으로 수록.
  #   의사 파일시스템(/proc /sys /run /dev)만 prune. head 캡 없음(CSV에 전수).
  ww="$(find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null | while IFS= read -r f; do stat_line "$f"; done | sed '/^$/d')"
  n="$(printf '%s' "$ww" | grep -c .)"
  raw="# find / -type f -perm -0002 (world-writable, 의사FS 제외) — ${n}개"$'\n'"${ww:-(없음)}"
  if [ "$n" -eq 0 ]; then rec U-25 "$R_PASS" "/ (proc·sys·dev·run 제외)" "$raw" "world writable 파일 없음"
  else rec U-25 "$R_VULN" "/ (proc·sys·dev·run 제외)" "$raw" "world writable 파일 ${n}개 존재 — 설정 이유 수동 확인"; fi
}

diag_u26(){ local nd raw
  nd="$(find /dev -type f ! -name 'MAKEDEV' ! -name '.udev*' 2>/dev/null | head -5)"
  raw="/dev 내 일반 파일(device 아님): ${nd:-없음}"
  if [ -z "$nd" ]; then rec U-26 "$R_PASS" "/dev" "$raw" "/dev에 존재하지 않는 device(일반 파일) 없음"
  else rec U-26 "$R_VULN" "/dev" "$raw" "/dev에 device가 아닌 일반 파일 존재"; fi
}

diag_u27(){ local bad="" raw="" f p found=""
  # /etc/hosts.equiv + 각 사용자 $HOME/.rhosts 를 점검 — 존재 파일은 stat 으로 수록 + '+' 설정·권한 점검.
  for f in /etc/hosts.equiv $(awk -F: '$6!="" {print $6"/.rhosts"}' "$PASSWD_FILE" 2>/dev/null); do
    [ -e "$f" ] || continue
    found="yes"; raw="${raw}$(stat_line "$f")"$'\n'
    p="$(perm_of "$f")"
    grep -qE '^\+|[[:space:]]\+' "$f" 2>/dev/null && bad="$bad ${f}(+허용)"
    { others_has_access "$p" || ! printf '%s' "$(owner_of "$f")" | grep -qiE '^root:'; } && bad="$bad ${f}(${p})"
  done
  [ -z "$found" ] && raw="(/etc/hosts.equiv 및 모든 사용자 \$HOME/.rhosts 파일 없음 — r 계열 미사용)"
  [ -n "$bad" ] && raw="${raw}※ 문제:${bad}"
  if [ -z "$bad" ]; then rec U-27 "$R_PASS" "\$HOME/.rhosts /etc/hosts.equiv" "$raw" "rhosts/hosts.equiv 미사용 또는 적정(소유자 root·권한 제한·'+' 없음)"
  else rec U-27 "$R_VULN" "rhosts/hosts.equiv" "$raw" "rhosts/hosts.equiv 취약(권한 과다 또는 '+' 설정):${bad}"; fi
}

diag_u28(){ local ha hd deny_all fwout fw_active raw
  [ -f /etc/hosts.allow ] && ha="$(grep -vcE '^\s*#|^\s*$' /etc/hosts.allow 2>/dev/null)" || ha=0
  [ -f /etc/hosts.deny ] && hd="$(grep -vcE '^\s*#|^\s*$' /etc/hosts.deny 2>/dev/null)" || hd=0
  # 단순 rule 수가 아니라 실제 기본차단(ALL: ALL) 존재 여부로 TCP Wrapper 제한 성립을 판단
  deny_all="$(grep -icE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null)"
  # 방화벽 active 판단 — is-active 출력 중 '정확히' active 인 줄이 있을 때만 (※ 'inactive' 부분일치 버그 방지: -qxF)
  fwout="$( { systemctl is-active ufw; systemctl is-active firewalld; systemctl is-active nftables; } 2>/dev/null )"
  fw_active="비활성"; printf '%s\n' "$fwout" | grep -qxF active && fw_active="활성"
  raw="hosts.allow 규칙 ${ha}개 / hosts.deny 규칙 ${hd}개 (기본차단 ALL:ALL ${deny_all}개)"$'\n'"방화벽: ${fw_active} (AWS 보안그룹은 별도)"
  # 양호: 방화벽 활성 OR hosts.deny 기본차단(ALL:ALL) 설정 — 실제 접근제한이 성립할 때만
  if [ "$fw_active" = "활성" ] || [ "${deny_all:-0}" -gt 0 ]; then
    rec U-28 "$R_PASS" "/etc/hosts.allow | /etc/hosts.deny | firewall" "$raw" "접속 IP/포트 제한(방화벽 또는 TCP Wrapper 기본차단) 적용됨"
  else rec U-28 "$R_VULN" "hosts.allow/deny | firewall" "$raw" "호스트 기반 접근제한 미설정(방화벽 비활성·기본차단 없음) — AWS 보안그룹 등 별도 통제 수동 확인"; fi
}

diag_u29(){ if [ ! -e "$HOSTS_LPD" ]; then rec U-29 "$R_PASS" "$HOSTS_LPD" "(hosts.lpd 파일 없음)" "hosts.lpd 미사용(파일 없음)"; else chk_file_perm U-29 "$HOSTS_LPD" "root" "$PERM_HOSTSLPD_MAX"; fi; }

diag_u30(){ local raw="" uhits phits low_bad="" has_ok="" upg="" line f val
  # umask/UMASK 설정 라인 수집(파일:내용 원문). 맨 앞 값 하나가 아니라 '전체'를 평가.
  uhits="$(grep -rHiE '^[[:space:]]*(export[[:space:]]+)?umask[[:space:]=]+[0-7]{3}|^[[:space:]]*UMASK[[:space:]]+[0-7]{3}' "$PROFILE_FILE" "$LOGIN_DEFS" /etc/profile.d/ /etc/bashrc /etc/bash.bashrc 2>/dev/null | grep -vE ':[[:space:]]*#' | tr -s ' \t' ' ')"
  phits="$(grep -rHE 'pam_umask' "$PAM_DIR" 2>/dev/null | grep -vE ':[[:space:]]*#' | tr -s ' \t' ' ' | head -2)"
  # 각 umask 값 평가: ≥022면 양호 근거, <022면 해당 파일이 UPG 가드(id -gn==id -un / UID -gt)를 가지면
  #   사설그룹 한정 조건부(안전), 가드 없으면 '무조건 느슨' → 취약.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    f="${line%%:*}"; val="$(printf '%s' "$line" | grep -oE '[0-7]{3}' | tail -1)"
    [ -z "$val" ] && continue
    if [ "$((8#$val))" -ge "$((8#$UMASK_MIN))" ] 2>/dev/null; then has_ok="yes"
    elif grep -qE 'id -gn|id -un|UID[[:space:]]*-gt' "$f" 2>/dev/null; then upg="yes"
    else low_bad="$low_bad ${f}=${val}"; fi
  done <<EOF
$uhits
EOF
  raw="${uhits:-(명시적 UMASK 설정 라인 없음)}"$'\n'"${phits:-(pam_umask 미사용)}"
  [ -n "$upg" ] && raw="${raw}"$'\n'"※ 022 미만 umask 는 UPG(사설그룹·uid==gid명) 조건부 → 안전"
  [ -n "$low_bad" ] && raw="${raw}"$'\n'"※ 무조건 022 미만 UMASK:${low_bad}"
  if [ -n "$low_bad" ]; then
    rec U-30 "$R_VULN" "/etc/profile | login.defs | $PAM_DIR" "$raw" "무조건 022 미만 UMASK 존재(과도한 기본 권한 부여):${low_bad}"
  elif [ -n "$has_ok" ] || [ -n "$phits" ]; then
    rec U-30 "$R_PASS" "/etc/profile | login.defs | $PAM_DIR" "$raw" "UMASK ${UMASK_MIN} 이상 적용$( [ -n "$upg" ] && printf ' (UPG 조건부 002 는 사설그룹 한정으로 안전)')"
  else rec U-30 "$R_VULN" "/etc/profile | login.defs | $PAM_DIR" "$raw" "UMASK 미설정 또는 ${UMASK_MIN} 미만"; fi
}

diag_u31(){ local bad="" raw="" u h uid o p
  # 일반 사용자(UID≥1000) 홈 디렉터리를 각각 stat 으로 나열 + 소유자=계정·타 사용자 쓰기 점검.
  while IFS=: read -r u _ uid _ _ h _; do
    [ "${uid:-0}" -ge 1000 ] 2>/dev/null || continue
    [ "${uid}" -eq 65534 ] 2>/dev/null && continue       # nobody
    case "$h" in ""|/|/nonexistent|/dev/null|/sbin*|/usr/sbin*|/bin*|/run/*|/var/run/*) continue ;; esac
    [ -d "$h" ] || continue
    raw="${raw}$(stat_line "$h")  [계정:${u}]"$'\n'
    o="$(stat -c '%U' "$h" 2>/dev/null)"; p="$(perm_of "$h")"
    { [ "$o" != "$u" ] || others_has_write "$p"; } && bad="$bad ${h}(소유:${o},${p})"
  done < "$PASSWD_FILE"
  [ -z "$raw" ] && raw="(점검 대상(UID≥1000) 홈 디렉터리 없음)"
  [ -n "$bad" ] && raw="${raw}※ 문제:${bad}"
  if [ -z "$bad" ]; then rec U-31 "$R_PASS" "사용자 홈 디렉터리" "$raw" "홈 디렉터리 소유자 적정 + 타 사용자 쓰기 권한 없음"
  else rec U-31 "$R_VULN" "사용자 홈 디렉터리" "$raw" "홈 디렉터리 소유자 부적정 또는 타 사용자 쓰기 권한:${bad}"; fi
}

diag_u32(){ local bad="" raw="" u h uid
  # 일반 사용자(UID≥1000) 각각의 홈 디렉터리 지정 경로와 실제 존재 여부를 나열.
  while IFS=: read -r u _ uid _ _ h _; do
    [ "${uid:-0}" -ge 1000 ] 2>/dev/null || continue
    [ "${uid}" -eq 65534 ] 2>/dev/null && continue       # nobody
    case "$h" in ""|/nonexistent|/dev/null|/run/*|/var/run/*) continue ;; esac
    if [ -d "$h" ]; then raw="${raw}${u}: ${h} (존재)"$'\n'
    else raw="${raw}${u}: ${h} (없음)"$'\n'; bad="$bad ${u}(${h})"; fi
  done < "$PASSWD_FILE"
  [ -z "$raw" ] && raw="(점검 대상(UID≥1000) 계정 없음)"
  [ -n "$bad" ] && raw="${raw}※ 홈 디렉터리 없는 계정:${bad}"
  if [ -z "$bad" ]; then rec U-32 "$R_PASS" "$PASSWD_FILE" "$raw" "홈 디렉터리가 존재하지 않는 계정 없음"
  else rec U-32 "$R_VULN" "$PASSWD_FILE" "$raw" "홈 디렉터리가 존재하지 않는 계정:${bad}"; fi
}

diag_u33(){ local raw="" all n
  # 시스템 전체(/) 숨김 파일/디렉터리 검색(의사 파일시스템만 제외). 필터 없이 전부 나열 → 비정상/불필요 항목은 사람이 판별(수동 확인).
  all="$(find / \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o -name '.*' ! -name '.' ! -name '..' -print 2>/dev/null | while IFS= read -r f; do stat_line "$f"; done | sed '/^$/d')"
  n="$(printf '%s' "$all" | grep -c .)"
  if [ "$n" -eq 0 ]; then raw="(숨김 파일/디렉터리 없음)"
  else raw="$all"; [ "$n" -gt 100 ] && raw="$(printf '%s' "$all" | head -100)"$'\n'"... 외 $((n-100))개 (전체는 raw CSV 참조)"; fi
  rec U-33 "$R_NA" "find / (의사FS 제외)" "$raw" "숨김 파일/디렉터리 총 ${n}개 — 비정상/불필요 항목 목록 수동 확인 대상"
}

#############################################################################
# 서비스 관리 U-34 ~ U-63
#############################################################################
# 서비스 비활성 점검 공통: code names... → 구동중이면 취약
chk_svc_off(){ local code="$1"; shift; local raw run=""
  for s in "$@"; do svc_running "$s" && run="$run $s"; proc_running "$s" && run="$run $s"; done
  run="$(echo $run | tr ' ' '\n' | grep -vE '^$' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  raw="$([ -n "$run" ] && svc_stat "${*}" "활성 [${run}]" || svc_stat "${*}")"
  if [ -z "$run" ]; then rec "$code" "$R_PASS" "systemd/process" "$raw" "${NAME[$code]} — 미구동(비활성)"
  else rec "$code" "$R_VULN" "systemd/process" "$raw" "서비스 구동중:${run}"; fi
}

diag_u34(){ chk_svc_off U-34 finger fingerd; }
diag_u35(){ # Anonymous FTP
  if ! svc_running vsftpd proftpd pure-ftpd && ! proc_running vsftpd; then rec U-35 "$R_PASS" "ftp" "$(svc_stat "vsftpd proftpd pure-ftpd")" "공유(FTP) 서비스 미사용"; return; fi
  local an; an="$(grep -iE '^[[:space:]]*anonymous_enable' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | tail -1)"
  if printf '%s' "$an" | grep -qiE 'anonymous_enable[[:space:]=]+NO'; then rec U-35 "$R_PASS" "/etc/vsftpd.conf" "$an" "익명 FTP 접근 제한됨"
  else rec U-35 "$R_VULN" "/etc/vsftpd.conf" "${an:-anonymous_enable 미설정}" "익명 FTP 접근 허용 가능 — 수동 확인"; fi
}
diag_u36(){ chk_svc_off U-36 rsh rlogin rexec in.rshd in.rlogind in.rexecd rsh.socket rlogin.socket; }
diag_u37(){ local bad="" raw="" f p o
  # cron/at 설정 파일: 소유자 root + 권한 640 이하 (검사한 파일을 stat 라인 그대로 표기)
  for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.d/*; do
    [ -e "$f" ] || continue
    raw="${raw}$(stat_line "$f")"$'\n'
    p="$(perm_of "$f")"; o="$(owner_of "$f")"
    { ! printf '%s' "$o" | grep -qiE '^root:' || ! perm_subset "$p" "$PERM_CRON_MAX"; } && bad="$bad $(basename "$f")(${o},${p})"
  done
  [ -z "$raw" ] && raw="(점검 대상 cron/at 설정 파일 없음)"
  if [ -z "$bad" ]; then rec U-37 "$R_PASS" "/etc/crontab /etc/cron.* /etc/cron.d" "$raw" "crontab 설정파일 소유자(root) 및 권한(${PERM_CRON_MAX} 이하) 적정"
  else rec U-37 "$R_VULN" "/etc/crontab /etc/cron.*" "$raw" "crontab 설정파일 권한 설정 미흡(>${PERM_CRON_MAX} 또는 비-root):${bad}"; fi
}
diag_u38(){ chk_svc_off U-38 echo discard daytime chargen; }
diag_u39(){ chk_svc_off U-39 nfs-server nfs rpcbind; }
diag_u40(){ local active="" ev p raw bad="" d dperm
  # 1차: NFS 서비스 활성 여부. 비활성 + exports 없음이면 미사용(양호).
  svc_running nfs-server nfs && active="yes"
  ev="$(grep -vE '^\s*#|^\s*$' "$NFS_EXPORTS" 2>/dev/null)"
  if [ -z "$active" ] && [ -z "$ev" ]; then
    rec U-40 "$R_PASS" "nfs-server | $NFS_EXPORTS" "$(svc_stat "nfs-server nfs")"$'\n'"exports: (없음/비어있음)" "NFS 서비스 미사용(공유 없음)"; return
  fi
  # 활성(또는 exports 존재) → 접근통제 + exports 파일 권한 + 공유 디렉터리 권한·내용 점검
  raw="$([ -n "$active" ] && svc_stat "nfs-server nfs" 활성 || svc_stat "nfs-server nfs")"$'\n'"# ${NFS_EXPORTS}"$'\n'"$(stat_line "$NFS_EXPORTS")"$'\n'"${ev:-(내용 없음)}"
  p="$(perm_of "$NFS_EXPORTS")"
  printf '%s' "$ev" | grep -qE '\*|everyone' && bad="모든 호스트(*) 허용"
  [ -n "$p" ] && { perm_subset "$p" "$PERM_EXPORTS_MAX" || bad="${bad:+$bad / }exports 권한 과다(${p}>${PERM_EXPORTS_MAX})"; }
  # 공유 디렉터리(첫 필드) 권한 점검
  raw="${raw}"$'\n'"# 공유 디렉터리 권한"
  while read -r d _; do [ -n "$d" ] && [ -d "$d" ] || continue
    raw="${raw}"$'\n'"$(stat_line "$d")"; dperm="$(perm_of "$d")"
    others_has_write "$dperm" && bad="${bad:+$bad / }공유디렉터리 $(basename "$d") other쓰기(${dperm})"
  done <<EOF
$ev
EOF
  if [ -z "$bad" ]; then rec U-40 "$R_PASS" "$NFS_EXPORTS | 공유디렉터리" "$raw" "NFS 접근통제(특정 호스트) + exports/공유디렉터리 권한 적정"
  else rec U-40 "$R_VULN" "$NFS_EXPORTS | 공유디렉터리" "$raw" "NFS 접근통제·권한 미흡: ${bad}"; fi
}
diag_u41(){ chk_svc_off U-41 autofs automountd; }
diag_u42(){ chk_svc_off U-42 rpcbind "rpc.cmsd" "rpc.ttdbserverd" "rusersd" "sprayd" "walld"; }
diag_u43(){ chk_svc_off U-43 ypserv ypbind nis; }
diag_u44(){ chk_svc_off U-44 tftp talk ntalk "tftp.socket"; }
diag_u45(){ if ! svc_running postfix sendmail && ! proc_running master && ! proc_running sendmail; then rec U-45 "$R_NA" "postfix/sendmail (메일 서비스)" "$(svc_stat "postfix sendmail")" "메일 서비스 미사용 — 미해당"; return; fi
  local v; v="$(postconf mail_version 2>/dev/null || sendmail -d0.1 -bt </dev/null 2>/dev/null | grep -i version | head -1)"
  rec U-45 "$R_NA" "postfix/sendmail" "${v:-버전 확인 필요}" "메일 서비스 버전 최신 여부 — 수동 확인 대상"; }
diag_u46(){ if ! svc_running postfix sendmail; then rec U-46 "$R_PASS" "mail" "$(svc_stat "postfix sendmail")" "메일 서비스 미사용"; return; fi
  rec U-46 "$R_NA" "mail config" "메일 서비스 구동중 — restrictqrun 등 설정 확인 필요" "일반 사용자 메일 실행 방지 — 수동 확인 대상"; }
diag_u47(){ if ! svc_running postfix sendmail; then rec U-47 "$R_PASS" "mail" "$(svc_stat "postfix sendmail")" "메일 서비스 미사용(릴레이 불가)"; return; fi
  local r; r="$(postconf smtpd_relay_restrictions mynetworks 2>/dev/null | head -3)"
  rec U-47 "$R_NA" "postfix/sendmail" "${r:-릴레이 설정 확인 필요}" "스팸 릴레이 제한 — 수동 확인 대상"; }
diag_u48(){ if ! svc_running sendmail; then rec U-48 "$R_PASS" "sendmail" "$(svc_stat "sendmail")" "sendmail 미사용(expn/vrfy 무관)"; return; fi
  local p; p="$(grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null | head -1)"
  if printf '%s' "$p" | grep -qiE 'noexpn.*novrfy|novrfy.*noexpn|goaway'; then rec U-48 "$R_PASS" "sendmail.cf" "$p" "noexpn/novrfy 설정됨"
  else rec U-48 "$R_VULN" "sendmail.cf" "${p:-PrivacyOptions 미설정}" "expn/vrfy 제한(noexpn,novrfy) 미설정"; fi
}
diag_u49(){ if ! svc_running named bind9; then rec U-49 "$R_NA" "DNS" "$(svc_stat "named bind9")" "DNS 서비스 미사용 — 미해당"; return; fi
  local v; v="$(named -v 2>/dev/null)"; rec U-49 "$R_NA" "named" "${v:-버전 확인 필요}" "DNS(BIND) 최신 패치 여부 — 수동 확인 대상"; }
diag_u50(){ if ! svc_running named bind9; then rec U-50 "$R_PASS" "DNS" "$(svc_stat "named bind9")" "DNS 미사용(Zone Transfer 무관)"; return; fi
  local t; t="$(grep -iE 'allow-transfer' /etc/bind/named.conf* /etc/named.conf 2>/dev/null | head -2)"
  if [ -n "$t" ]; then rec U-50 "$R_PASS" "named.conf" "$t" "Zone Transfer 허용 대상 제한됨"
  else rec U-50 "$R_VULN" "named.conf" "(allow-transfer 미설정)" "Zone Transfer가 모든 호스트에 허용될 수 있음"; fi
}
diag_u51(){ if ! svc_running named bind9; then rec U-51 "$R_PASS" "DNS" "$(svc_stat "named bind9")" "DNS 미사용(동적 업데이트 무관)"; return; fi
  local u; u="$(grep -iE 'allow-update' /etc/bind/named.conf* /etc/named.conf 2>/dev/null | head -2)"
  if [ -z "$u" ] || printf '%s' "$u" | grep -qiE 'none'; then rec U-51 "$R_PASS" "named.conf" "${u:-allow-update none(기본)}" "동적 업데이트 비활성 또는 접근통제됨"
  else rec U-51 "$R_VULN" "named.conf" "$u" "동적 업데이트 허용 — 접근통제 수동 확인"; fi
}
diag_u52(){ chk_svc_off U-52 telnet "telnet.socket" telnetd; }
diag_u53(){ if ! svc_running vsftpd proftpd; then rec U-53 "$R_PASS" "ftp" "$(svc_stat "vsftpd proftpd")" "FTP 미사용(배너 노출 무관)"; return; fi
  local b; b="$(grep -iE 'ftpd_banner|banner_file' /etc/vsftpd.conf 2>/dev/null | head -1)"
  rec U-53 "$R_NA" "/etc/vsftpd.conf" "${b:-배너 설정 확인 필요}" "FTP 배너 정보 노출 — 수동 확인 대상"; }
diag_u54(){ if svc_running vsftpd proftpd pure-ftpd || proc_running vsftpd; then
    local ssl; ssl="$(grep -iE 'ssl_enable' /etc/vsftpd.conf 2>/dev/null | tail -1)"
    if printf '%s' "$ssl" | grep -qiE 'ssl_enable[[:space:]=]+YES'; then rec U-54 "$R_PASS" "/etc/vsftpd.conf" "$ssl" "FTP에 SSL/TLS 적용됨"
    else rec U-54 "$R_VULN" "/etc/vsftpd.conf" "${ssl:-ssl_enable 미설정}" "암호화되지 않은 FTP 서비스 활성화"; fi
  else rec U-54 "$R_PASS" "ftp" "$(svc_stat "vsftpd proftpd pure-ftpd")" "암호화되지 않은 FTP 서비스 미사용"; fi
}
diag_u55(){ if ! grep -qE '^ftp:' "$PASSWD_FILE" 2>/dev/null; then rec U-55 "$R_PASS" "$PASSWD_FILE" "(ftp 계정 없음)" "FTP 전용 계정 없음"; return; fi
  local sh; sh="$(grep -E '^ftp:' "$PASSWD_FILE" | awk -F: '{print $7}')"
  case "$sh" in */nologin|*/false) rec U-55 "$R_PASS" "$PASSWD_FILE" "ftp 셸: $sh" "FTP 계정에 nologin/false 셸 부여됨" ;;
    *) rec U-55 "$R_VULN" "$PASSWD_FILE" "ftp 셸: $sh" "FTP 계정에 로그인 셸 부여됨" ;; esac
}
diag_u56(){ if ! svc_running vsftpd proftpd; then rec U-56 "$R_PASS" "ftp" "$(svc_stat "vsftpd proftpd")" "FTP 미사용"; return; fi
  rec U-56 "$R_NA" "ftp config" "FTP 구동중 — 접근제어(tcp_wrapper/userlist) 확인 필요" "FTP 접근 제어 — 수동 확인 대상"; }
diag_u57(){ local f=/etc/ftpusers; [ -e /etc/vsftpd.user_list ] && f=/etc/vsftpd.user_list; [ -e /etc/ftpusers ] && f=/etc/ftpusers
  if [ ! -e "$f" ]; then
    if svc_running vsftpd proftpd; then rec U-57 "$R_VULN" "/etc/ftpusers" "$(svc_stat "vsftpd proftpd" 활성)"$'\n'"(ftpusers 파일 없음)" "FTP 구동중이나 ftpusers 미설정(root 차단 필요)"
    else rec U-57 "$R_PASS" "/etc/ftpusers" "$(svc_stat "vsftpd proftpd")"$'\n'"(ftpusers 파일 없음)" "FTP 미사용"; fi; return; fi
  if grep -qE '^root$' "$f" 2>/dev/null; then rec U-57 "$R_PASS" "$f" "$(grep -E '^root$' "$f")" "ftpusers에 root 포함(FTP 접속 차단)"
  else rec U-57 "$R_VULN" "$f" "(root 미포함)" "ftpusers에 root 미포함(root FTP 접속 가능)"; fi
}
diag_u58(){ chk_svc_off U-58 snmpd snmp; }
diag_u59(){ if ! svc_running snmpd; then rec U-59 "$R_PASS" "snmp" "$(svc_stat "snmpd")" "SNMP 미사용"; return; fi
  local v; v="$(grep -iE '^[[:space:]]*(rouser|rwuser|createUser)' "$SNMPD_CONF" 2>/dev/null | head -2)"
  if [ -n "$v" ]; then rec U-59 "$R_PASS" "$SNMPD_CONF" "$v" "SNMP v3(사용자 기반) 설정 존재"
  else rec U-59 "$R_VULN" "$SNMPD_CONF" "(v3 user 미설정, community 기반 추정)" "SNMP v2 이하 사용 추정 — v3 권고"; fi
}
diag_u60(){ if ! svc_running snmpd; then rec U-60 "$R_PASS" "snmp" "$(svc_stat "snmpd")" "SNMP 미사용"; return; fi
  local c; c="$(grep -iE '^[[:space:]]*(rocommunity|rwcommunity|com2sec)' "$SNMPD_CONF" 2>/dev/null | grep -oiE 'public|private' | head -1)"
  if [ -n "$c" ]; then rec U-60 "$R_VULN" "$SNMPD_CONF" "기본 community 사용: $c" "SNMP Community가 기본값(public/private)"
  else rec U-60 "$R_PASS" "$SNMPD_CONF" "(public/private 미사용)" "SNMP Community 기본값 미사용"; fi
}
diag_u61(){ if ! svc_running snmpd; then rec U-61 "$R_PASS" "snmp" "$(svc_stat "snmpd")" "SNMP 미사용"; return; fi
  local a; a="$(grep -iE 'com2sec|rouser|rwuser' "$SNMPD_CONF" 2>/dev/null | grep -vE 'default' | head -2)"
  if [ -n "$a" ]; then rec U-61 "$R_PASS" "$SNMPD_CONF" "$a" "SNMP 접근 제어(소스 제한) 설정됨"
  else rec U-61 "$R_VULN" "$SNMPD_CONF" "(접근 제어 미설정 또는 default)" "SNMP 접근 제어 미설정"; fi
}
diag_u62(){ local raw="" hit="" f line b
  # 배너 파일은 실제 내용(첫 줄)을 근거로 표기
  for f in /etc/motd /etc/issue /etc/issue.net; do
    if [ -s "$f" ]; then hit="yes"; line="$(head -1 "$f" 2>/dev/null | tr -s ' \t' ' ')"; raw="${raw}${f}: ${line}"$'\n'
    else raw="${raw}${f}: (비어있음/없음)"$'\n'; fi
  done
  b="$(grep -iE '^[[:space:]]*Banner[[:space:]]' "$SSHD_CONFIG" 2>/dev/null | grep -vE '^\s*#' | head -1 | sed 's/^[[:space:]]*//')"
  [ -n "$b" ] && { hit="yes"; raw="${raw}${SSHD_CONFIG}: ${b}"$'\n'; } || raw="${raw}${SSHD_CONFIG}: (Banner 미설정)"$'\n'
  if [ -n "$hit" ]; then rec U-62 "$R_PASS" "/etc/motd | /etc/issue | /etc/issue.net | sshd_config" "$raw" "로그온 경고 메시지 설정됨"
  else rec U-62 "$R_VULN" "/etc/motd | /etc/issue | /etc/issue.net | sshd_config" "$raw" "로그온 경고 메시지 미설정"; fi
}
diag_u63(){ chk_file_perm U-63 "$SUDOERS_FILE" "root" "$PERM_SUDOERS_MAX"; }

#############################################################################
# 패치 U-64 / 로그 U-65 ~ U-67
#############################################################################
diag_u64(){ local cur latest upd raw pm="" newer
  # 현재 커널(uname -r)을 conf의 기준(최신) 패치 버전과 비교 — 현재가 더 이전이면 취약.
  cur="$KERNEL"; latest="${LATEST_KERNEL_VERSION:-}"
  # 참고용: 적용 대기 업데이트 수 (dnf/yum/apt)
  if has_cmd dnf; then pm="dnf"; upd="$(dnf -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')"
  elif has_cmd yum; then pm="yum"; upd="$(yum -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')"
  elif has_cmd apt; then pm="apt"; upd="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"; fi
  if [ -z "$latest" ]; then
    raw="현재 커널: ${cur}"$'\n'"기준(최신) 패치 버전: 미입력"$'\n'"적용 대기 업데이트(${pm:-pkg}): ${upd:-?}개"
    rec U-64 "$R_VULN" "커널 | conf:LATEST_KERNEL_VERSION" "$raw" "conf에 최신 패치 기준 버전(LATEST_KERNEL_VERSION) 미입력 — 보안 담당자 입력 후 재점검 필요"
    return
  fi
  # 버전 정렬 비교: 두 값 중 더 높은(최신) 것이 현재 커널이면 양호
  newer="$(printf '%s\n%s\n' "$cur" "$latest" | sort -V | tail -1)"
  raw="현재 커널: ${cur}"$'\n'"기준(최신) 패치 버전: ${latest}"$'\n'"적용 대기 업데이트(${pm:-pkg}): ${upd:-?}개"
  if [ "$cur" = "$latest" ] || [ "$newer" = "$cur" ]; then
    rec U-64 "$R_PASS" "커널 | conf:LATEST_KERNEL_VERSION" "$raw" "현재 커널이 기준(최신) 버전 이상 — 최신 보안 패치 적용됨"
  else
    rec U-64 "$R_VULN" "커널 | conf:LATEST_KERNEL_VERSION" "$raw" "현재 커널(${cur})이 기준(최신) 버전(${latest})보다 이전 — 보안 패치 적용 필요"
  fi
}

diag_u65(){ local raw="" active=""
  for s in systemd-timesyncd chronyd ntpd; do svc_running "$s" && active="$active $s"; done
  active="${active# }"
  raw="시각 동기화 서비스: 구동중=[${active:-없음}]"
  has_cmd timedatectl && raw="${raw}"$'\n'"$(timedatectl 2>/dev/null | grep -iE 'synchronized|NTP service' | sed 's/^ *//')"
  if [ -n "$active" ] || timedatectl 2>/dev/null | grep -qiE 'NTP service: active|synchronized: yes'; then
    rec U-65 "$R_PASS" "timesyncd/chrony/ntp" "$raw" "NTP/시각 동기화 설정 적용됨"
  else rec U-65 "$R_VULN" "ntp/chrony" "$raw" "시각 동기화 미설정"; fi
}

diag_u66(){ local raw=""
  if svc_running rsyslog syslog systemd-journald; then
    raw="로깅 서비스 구동중(rsyslog/journald)"$'\n'"rsyslog.conf 규칙: $(grep -vcE '^\s*#|^\s*$' "$SYSLOG_CONF" 2>/dev/null)개"
    rec U-66 "$R_PASS" "$SYSLOG_CONF | journald" "$raw" "시스템 로깅(rsyslog/journald) 설정 및 구동됨"
  else rec U-66 "$R_VULN" "$SYSLOG_CONF" "로깅 서비스 미구동" "시스템 로깅 정책 미수립/미구동"; fi
}

diag_u67(){ local bad="" raw="" f fcount=0
  for f in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/wtmp /var/log/cron; do
    [ -e "$f" ] || continue; local p o; p="$(perm_of "$f")"; o="$(owner_of "$f")"
    raw="${raw}$(stat_line "$f")"$'\n'
    { ! printf '%s' "$o" | grep -qiE '^(root|syslog):' || ! perm_subset "$p" "$PERM_LOGFILE_MAX"; } && bad="$bad $(basename "$f")(${p})"
    fcount=$((fcount+1)); [ "$fcount" -ge 8 ] && break
  done
  [ -z "$raw" ] && raw="(주요 로그 파일 없음)"
  if [ -z "$bad" ]; then rec U-67 "$R_PASS" "$LOG_DIR" "$raw" "로그 파일 소유자 적정 + 권한 ${PERM_LOGFILE_MAX} 이하"
  else rec U-67 "$R_VULN" "$LOG_DIR" "$raw" "로그 파일 소유자 부적정 또는 권한 과다:${bad}"; fi
}

#############################################################################
# 실행
#############################################################################
show_preinfo; echo
# ── 권한 사전 점검: 관리자(root) 권한이 아니면 예외(중단) ──
#    /etc/shadow(640)·SUID 점검·환경설정 등 권한 제한 자원을 읽어야 정확하므로 root 필요.
if [ "${SKIP_ROOT_CHECK:-0}" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  {
    echo ""
    echo "================================================================"
    echo "[진단 중단] 관리자 권한(root/sudo)이 아닙니다."
    echo "  현재 계정 : $(id -un) (uid=$(id -u))"
    echo "  사유      : 권한 제한된 파일(예: $SHADOW_FILE)을 읽어야 정확히 진단됩니다."
    echo "  조치      : sudo 로 재실행하세요.  예) sudo ./linux_diag.sh"
    echo "================================================================"
  } >&2
  exit 2
fi

if [ -n "${TEST_ITEMS:-}" ]; then
  for n in $TEST_ITEMS; do
    "diag_u${n}"
  done
else
  for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 \
           24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 \
           47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67; do
    "diag_u${n}"
  done
fi

TOTAL=$((CNT_PASS+CNT_VULN+CNT_NA))

# ── 보고서 TXT ─────────────────────────────────────────────
{
  show_preinfo full; echo   # 히스토리엔 호스트명/버전정보 포함(stdout 호출은 그대로 미표기)
  printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
  echo "================================================================"
  i=0; while [ "$i" -lt "${#F_CODE[@]}" ]; do
    emit_screen "${F_CODE[$i]}" "${F_SEV[$i]}" "${F_NAME[$i]}" "${F_STD[$i]}" "${F_RESULT[$i]}" "${F_RAW[$i]}" "${F_FILE[$i]}"; i=$((i+1)); done
  echo "※ '수동 확인' 표기 항목과 취약 항목은 담당자의 실제 설정 검토로 최종 확정 필요."
} > "$HISTORY"

# ── 로우데이터 CSV ─────────────────────────────────────────
csv_field(){ local v; v="$(printf '%s' "$1" | sed 's/"/""/g' | awk '{a[NR]=$0} END{for(i=1;i<=NR;i++) printf "%s%s",(i>1?" | ":""),a[i]}')"; printf '"%s"' "$v"; }
{
  printf '\xEF\xBB\xBF'   # UTF-8 BOM — Excel 한글 깨짐 방지
  # 호스트명/버전정보: 진단대상 시트용 메타 — 첫 데이터 행에만 채워 CSV 경량화(중복 0).
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_field 항목코드)" "$(csv_field 분류)" "$(csv_field 항목)" "$(csv_field 판단기준)" "$(csv_field 결과)" "$(csv_field 점검내용)" "$(csv_field 조치방법)" "$(csv_field 진단대상)" "$(csv_field 진단대상IP)" "$(csv_field 중요도)" "$(csv_field 점검파일)" "$(csv_field 호스트명)" "$(csv_field 버전정보)"
  i=0; while [ "$i" -lt "${#F_CODE[@]}" ]; do
    if [ "$i" -eq 0 ]; then _h="$HOSTN"; _v="$VERSION_META"; else _h=""; _v=""; fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_field "${F_CODE[$i]}")" "$(csv_field "${F_CAT[$i]}")" "$(csv_field "${F_NAME[$i]}")" "$(csv_field "${F_STD[$i]}")" "$(csv_field "${F_RESULT[$i]}")" "$(csv_field "${F_RAW[$i]}")" "$(csv_field "${F_ACTION[$i]}")" "$(csv_field "$TARGET_SYS")" "$(csv_field "$IP_ADDR")" "$(csv_field "${F_SEV[$i]}")" "$(csv_field "${F_FILE[$i]}")" "$(csv_field "$_h")" "$(csv_field "$_v")"; i=$((i+1)); done
} > "$RAW_CSV"

echo "================================================================"
printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
echo " 히스토리(TXT)   : $HISTORY"
echo " 로우데이터(CSV) : $RAW_CSV"
echo "진단 스크립트 종료"
