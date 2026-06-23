#!/usr/bin/env bash
#############################################################################
# WAS(Tomcat) 자동 진단 스크립트
#   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 - 웹 서비스(WEB-01~26)
#   대상: Apache Tomcat 9 (WAS).
#
# 특징
#   - 읽기 전용(READ-ONLY): cat/grep/stat/ls/ps/systemctl(show) 만 사용. 설정 변경 없음.
#   - 판정값: 양호 / 취약 / N/A 3가지만.
#   - 점검 범위: Tomcat 컨테이너 설정(conf/) + (옵션) 현재 배포된 앱(webapp) 내부 설정.
#   - 출력: 항목별 구조화(콘솔 실시간) + 보고서(TXT) + 외부 진단용 로우데이터(CSV).
#   - 환경 의존 값은 was_diag.conf 에서 입력.
#
# 사용법
#   sudo ./was_diag.sh [-c was_diag.conf] [-o 출력디렉터리]
#############################################################################
set -u
LC_ALL=C.UTF-8 2>/dev/null || true
export TZ='Asia/Seoul'   # 진단 시각 KST 고정 (서버 TZ가 UTC여도 KST로 표기)

R_PASS="양호"; R_VULN="취약"; R_NA="N/A"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/was_diag.conf"
OVERRIDE_OUTPUT=""

while getopts "c:o:h" opt; do
  case "$opt" in
    c) CONF_FILE="$OPTARG" ;;
    o) OVERRIDE_OUTPUT="$OPTARG" ;;
    h) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 0 ;;
    *) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 1 ;;
  esac
done

[ -f "$CONF_FILE" ] || { echo "[ERROR] 설정 파일 없음: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF_FILE"
[ -n "$OVERRIDE_OUTPUT" ] && OUTPUT_DIR="$OVERRIDE_OUTPUT"
declare -p WEAK_PASSWORD_REGEX >/dev/null 2>&1 || WEAK_PASSWORD_REGEX=()
if printf '' | grep -qP '' 2>/dev/null; then GREP_P=1; else GREP_P=0; fi

# ── 앱 점검 대상 파일 목록 구성 ────────────────────────────
APP_ON="${CHECK_APP_CONFIG:-false}"
WEB_XML_LIST=("$WEB_XML")
CONTEXT_LIST=("$CONTEXT_XML")
APP_DB_FILES=()
APP_CFG_FILES=()
if [ "$APP_ON" = "true" ]; then
  [ -r "${APP_WEB_XML:-}" ] && WEB_XML_LIST+=("$APP_WEB_XML")
  [ -r "${APP_META_CONTEXT:-}" ] && CONTEXT_LIST+=("$APP_META_CONTEXT")
  if [ -n "${APP_CONFIG_DIR:-}" ] && [ -d "$APP_CONFIG_DIR" ]; then
    while IFS= read -r ff; do [ -n "$ff" ] && APP_DB_FILES+=("$ff"); done \
      < <(grep -rilE --include='*.xml' --include='*.properties' 'DataSource|jdbc:|password' "$APP_CONFIG_DIR" 2>/dev/null | head -20)
    # WEB-08 용: 앱 WEB-INF 전체의 설정 XML/properties.
    #   멀티파트 리졸버(multipartResolver)는 DispatcherServlet 컨텍스트(예: WEB-INF/config/action-servlet.xml)에
    #   정의되므로 classes/ 만 보면 놓친다 → WEB-INF 트리 전체를 스캔. 상한 40.
    _cfg_root="${APP_CONTEXT_DIR}/WEB-INF"; [ -d "$_cfg_root" ] || _cfg_root="$APP_CONFIG_DIR"
    while IFS= read -r ff; do [ -n "$ff" ] && APP_CFG_FILES+=("$ff"); done \
      < <(find "$_cfg_root" -type f \( -name '*.xml' -o -name '*.properties' \) 2>/dev/null | head -40)
  fi
fi

# ── 메타/환경 ───────────────────────────────────────────────
TS="$(date '+%Y-%m-%d %H:%M:%S')"; TS_FILE="$(date '+%Y%m%d_%H%M%S')"
HOSTN="$(hostname 2>/dev/null || echo unknown)"; LABEL="${TARGET_LABEL:-$HOSTN}"
OS_NAME="$( ( . /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME" ) || true )"
[ -z "$OS_NAME" ] && OS_NAME="$(uname -sr 2>/dev/null || echo unknown)"
IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -z "$IP_ADDR" ] && IP_ADDR="$HOSTN"
TARGET_SYS="WAS(Tomcat)"   # 진단대상(자산 종류) — CSV/화면/보고서 공통 표기

mkdir -p "$OUTPUT_DIR" 2>/dev/null || { echo "[ERROR] 출력 디렉터리 생성 실패: $OUTPUT_DIR" >&2; exit 1; }
RAW_CSV="${OUTPUT_DIR}/was_diag_raw_${LABEL}_${TS_FILE}.csv"
REPORT="${OUTPUT_DIR}/was_diag_report_${LABEL}_${TS_FILE}.txt"

# ── 저장소 ──────────────────────────────────────────────────
F_CODE=(); F_SEV=(); F_NAME=(); F_CAT=(); F_FILE=(); F_RAW=(); F_RESULT=(); F_SUMMARY=(); F_STD=()
CNT_PASS=0; CNT_VULN=0; CNT_NA=0

# ── KISA 판단기준 문구 ─────────────────────────────────────
declare -A CRIT_PASS CRIT_VULN
CRIT_PASS[WEB-01]="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않음"
CRIT_VULN[WEB-01]="계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을 사용함"
CRIT_PASS[WEB-02]="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정됨"
CRIT_VULN[WEB-02]="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정됨"
CRIT_PASS[WEB-03]="비밀번호 파일 권한이 600 이하로 설정됨"
CRIT_VULN[WEB-03]="비밀번호 파일 권한이 600 초과로 설정됨"
CRIT_PASS[WEB-04]="디렉터리 리스팅이 설정되지 않음"
CRIT_VULN[WEB-04]="디렉터리 리스팅이 설정됨"
CRIT_PASS[WEB-05]="CGI 스크립트를 사용하지 않거나 실행 가능한 디렉터리를 제한함"
CRIT_VULN[WEB-05]="CGI 스크립트를 사용하고 실행 가능한 디렉터리를 제한하지 않음"
CRIT_PASS[WEB-06]="상위 디렉터리 접근 기능을 제거함"
CRIT_VULN[WEB-06]="상위 디렉터리 접근 기능을 제거하지 않음"
CRIT_PASS[WEB-07]="기본 생성되는 불필요한 파일 및 디렉터리가 존재하지 않음"
CRIT_VULN[WEB-07]="기본 생성되는 불필요한 파일 및 디렉터리가 존재함"
CRIT_PASS[WEB-08]="파일 업로드 및 다운로드 용량을 제한함"
CRIT_VULN[WEB-08]="파일 업로드 및 다운로드 용량을 제한하지 않음"
CRIT_PASS[WEB-09]="웹 프로세스가 관리자 권한이 아닌 최소한의 권한을 가진 별도 계정으로 구동됨"
CRIT_VULN[WEB-09]="웹 프로세스가 관리자 권한이 부여된 계정으로 구동됨"
CRIT_PASS[WEB-10]="불필요한 Proxy 설정을 제한함"
CRIT_VULN[WEB-10]="불필요한 Proxy 설정을 제한하지 않음"
CRIT_PASS[WEB-11]="웹 서버 경로가 기타 업무와 분리된 경로로 설정되고 불필요한 경로가 없음"
CRIT_VULN[WEB-11]="웹 서버 경로가 분리되지 않았거나 불필요한 경로가 존재함"
CRIT_PASS[WEB-12]="심볼릭 링크/aliases/바로가기 등의 링크 사용을 허용하지 않음"
CRIT_VULN[WEB-12]="심볼릭 링크/aliases/바로가기 등의 링크 사용을 허용함"
CRIT_PASS[WEB-13]="DB 연결 파일에 대한 접근을 제한하고 불필요한 스크립트 매핑이 제거됨"
CRIT_VULN[WEB-13]="DB 연결 파일 접근을 제한하지 않거나 DB 연결정보가 노출됨"
CRIT_PASS[WEB-14]="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않음"
CRIT_VULN[WEB-14]="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여됨"
CRIT_PASS[WEB-15]="불필요한 스크립트 매핑이 존재하지 않음"
CRIT_VULN[WEB-15]="불필요한 스크립트 매핑이 존재함"
CRIT_PASS[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않음"
CRIT_VULN[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출됨"
CRIT_PASS[WEB-17]="불필요한 가상 디렉터리가 존재하지 않음"
CRIT_VULN[WEB-17]="불필요한 가상 디렉터리가 존재함"
CRIT_PASS[WEB-19]="웹 서비스 SSI 사용 설정이 비활성화되어 있음"
CRIT_VULN[WEB-19]="웹 서비스 SSI 사용 설정이 활성화되어 있음"
CRIT_PASS[WEB-22]="웹 서비스 에러 페이지가 별도로 지정됨"
CRIT_VULN[WEB-22]="에러 페이지가 별도로 지정되지 않았거나 에러 발생 시 중요 정보가 노출됨"
CRIT_PASS[WEB-23]="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용함"
CRIT_VULN[WEB-23]="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않음"
CRIT_PASS[WEB-24]="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않음"
CRIT_VULN[WEB-24]="별도의 업로드 경로를 사용하지 않거나 일반 사용자의 접근 권한이 부여됨"
CRIT_PASS[WEB-25]="최신 보안 패치가 적용되어 있으며 주기적인 패치 관리를 함"
CRIT_VULN[WEB-25]="최신 보안 패치가 적용되어 있지 않거나 주기적인 패치 관리를 하지 않음"
CRIT_PASS[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없음"
CRIT_VULN[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있음"

# ── KISA 판단기준(원문) ─────────────────────────────────────
#  2026 주요정보통신기반시설 상세가이드 - 웹 서비스 판단 기준 '양호/취약' 원문 그대로.
#  (판단기준 필드용 — 가공/요약하지 않는다. 판단 '근거'는 CRIT_*로 별도 생성)
declare -A STD_PASS STD_VULN
STD_PASS[WEB-01]="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
STD_VULN[WEB-01]="계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을 사용하는 경우"
STD_PASS[WEB-02]="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
STD_VULN[WEB-02]="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
STD_PASS[WEB-03]="비밀번호 파일에 권한이 600 이하로 설정된 경우"
STD_VULN[WEB-03]="비밀번호 파일에 권한이 600 초과로 설정된 경우"
STD_PASS[WEB-04]="디렉터리 리스팅이 설정되지 않은 경우"
STD_VULN[WEB-04]="디렉터리 리스팅이 설정된 경우"
STD_PASS[WEB-05]="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
STD_VULN[WEB-05]="CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
STD_PASS[WEB-06]="상위 디렉터리 접근 기능을 제거한 경우"
STD_VULN[WEB-06]="상위 디렉터리 접근 기능을 제거하지 않은 경우"
STD_PASS[WEB-07]="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
STD_VULN[WEB-07]="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
STD_PASS[WEB-08]="파일 업로드 및 다운로드 용량을 제한한 경우"
STD_VULN[WEB-08]="파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
STD_PASS[WEB-09]="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
STD_VULN[WEB-09]="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정으로 구동되고 있는 경우"
STD_PASS[WEB-10]="불필요한 Proxy 설정을 제한한 경우"
STD_VULN[WEB-10]="불필요한 Proxy 설정을 제한하지 않은 경우"
STD_PASS[WEB-11]="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
STD_VULN[WEB-11]="웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
STD_PASS[WEB-12]="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
STD_VULN[WEB-12]="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하는 경우"
STD_PASS[WEB-13]="일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
STD_VULN[WEB-13]="일반 사용자의 DB 연결 파일에 대한 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우"
STD_PASS[WEB-14]="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
STD_VULN[WEB-14]="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
STD_PASS[WEB-15]="불필요한 스크립트 매핑이 존재하지 않는 경우"
STD_VULN[WEB-15]="불필요한 스크립트 매핑이 존재하는 경우"
STD_PASS[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
STD_VULN[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
STD_PASS[WEB-17]="불필요한 가상 디렉터리가 존재하지 않는 경우"
STD_VULN[WEB-17]="불필요한 가상 디렉터리가 존재하는 경우"
STD_PASS[WEB-18]="WebDAV 서비스를 비활성화하고 있는 경우"
STD_VULN[WEB-18]="WebDAV 서비스를 활성화하고 있는 경우"
STD_PASS[WEB-19]="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
STD_VULN[WEB-19]="웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
STD_PASS[WEB-20]="SSL/TLS 설정이 활성화되어 있는 경우"
STD_VULN[WEB-20]="SSL/TLS 설정이 비활성화되어 있는 경우"
STD_PASS[WEB-21]="HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
STD_VULN[WEB-21]="HTTP 접근 시 HTTPS Redirection이 비활성화된 경우"
STD_PASS[WEB-22]="웹 서비스 에러 페이지가 별도로 지정된 경우"
STD_VULN[WEB-22]="웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
STD_PASS[WEB-23]="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
STD_VULN[WEB-23]="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
STD_PASS[WEB-24]="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
STD_VULN[WEB-24]="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
STD_PASS[WEB-25]="최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
STD_VULN[WEB-25]="최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지 않는 경우"
STD_PASS[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
STD_VULN[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"

cat_of() {
  case "$1" in
    WEB-01|WEB-02|WEB-03) printf '계정 관리' ;;
    WEB-19|WEB-20|WEB-21|WEB-22|WEB-23) printf '보안 설정' ;;
    WEB-24|WEB-25|WEB-26) printf '패치 및 로그 관리' ;;
    *) printf '서비스 관리' ;;
  esac
}

# ── 헬퍼 ────────────────────────────────────────────────────
perm_of() { [ -e "$1" ] && stat -c '%a' "$1" 2>/dev/null || echo ""; }
stat_line() { [ -e "$1" ] && stat -c '%A (%a) %U:%G  %n' "$1" 2>/dev/null; }
perm_subset() { [ -n "$1" ] && [ "$(( (8#$1) & ~(8#$2) ))" -eq 0 ]; }   # 파일 권한이 기준 권한의 '칸별 부분집합'이면 통과(통째 정수비교가 아니라 owner/group/other 비트별 판정)
others_has_access() { local p="$1"; [ -n "$p" ] && [ "$(( 8#$p % 8 ))" -ne 0 ]; }
join_files() { local o="" f; for f in "$@"; do o="${o:+$o / }$f"; done; printf '%s' "$o"; }
strip_xml_comments() {
  [ -r "$1" ] || return 0
  awk '
  BEGIN { inc=0 }
  { line=$0; out=""
    while (1) {
      if (inc) { idx=index(line,"-->"); if (idx==0) break; line=substr(line, idx+3); inc=0 }
      else { idx=index(line,"<!--"); if (idx==0){out=out line; break}
             out=out substr(line,1,idx-1); line=substr(line, idx+4); inc=1 } }
    if (inc==0) print out; else if (out!="") print out
  }' "$1" 2>/dev/null
}
# scan_list PATTERN FILE...  → 주석 제거 후 매칭 라인을 파일명 헤더와 함께 출력(없으면 빈 출력)
scan_list() {
  local pat="$1"; shift; local f m out=""
  for f in "$@"; do [ -r "$f" ] || continue
    m="$(strip_xml_comments "$f" | grep -iE "$pat")"
    [ -n "$m" ] && out="${out}# ${f}"$'\n'"${m}"$'\n'
  done
  printf '%s' "$out"
}
pw_matches_regex() {
  local s="$1" pat="$2"
  case "$pat" in
    *'\1'*|*'\2'*) [ "$GREP_P" -eq 1 ] && printf '%s' "$s" | grep -qiP "$pat" ;;
    *) if [ "$GREP_P" -eq 1 ]; then printf '%s' "$s" | grep -qiP "$pat"; else printf '%s' "$s" | grep -qiE "$pat"; fi ;;
  esac
}

# 점검내용(원문 증적)을 화면용으로 최대 8줄까지만 출력(나머지는 생략 — 상세는 CSV)
truncate8() {
  printf '%s' "$1" | awk '
    { ln[NR]=$0 }
    END {
      n=NR; lim=(n>8?8:n)
      for (i=1;i<=lim;i++) print ln[i]
      if (n>8) printf "... (이하 %d줄 생략 — 상세는 로우데이터 CSV 참조)\n", n-8
    }'
}

# 화면/보고서(TXT) 출력 블록 — 점검요약은 점검내용을 8줄까지만
# emit_screen CODE SEV NAME CAT STD RESULT RAW FILE  ($4 CAT 미사용: 화면 표기 제외, CSV에만)
emit_screen() {
  printf '[%s (%s) %s]\n' "$1" "$2" "$3"
  printf '점검 결과    : %s\n' "$6"
  printf '점검 파일 명 : %s\n' "$8"
  printf '점검 요약    :\n'
  if [ -n "$7" ]; then truncate8 "$7" | sed 's/^/    /'; else printf '    (없음)\n'; fi
  printf '판단 기준    :\n'; printf '%s\n' "$5" | sed 's/^/    /'
  printf -- '----------------------------------------------------------------\n'
}

# record CODE SEV NAME RESULT FILE RAW DETAIL
record() {
  local code="$1" sev="$2" name="$3" result="$4" file="$5" raw="$6" detail="$7" cat summary std
  cat="$(cat_of "$code")"
  case "$result" in
    "$R_PASS") summary="${CRIT_PASS[$code]:-양호}"; CNT_PASS=$((CNT_PASS+1)) ;;
    "$R_VULN") summary="${CRIT_VULN[$code]:-취약}"; CNT_VULN=$((CNT_VULN+1)) ;;
    *)         summary="${detail:-점검 대상 외/확인 불가}"; CNT_NA=$((CNT_NA+1)) ;;
  esac
  [ -n "$detail" ] && [ "$result" != "$R_NA" ] && summary="$summary (▸ ${detail})"
  # 점검내용이 '결과 없음(자연어)'일 때 감싼 괄호 제거 — 전체가 한 줄이고 (…)로 통째 감싸진 경우만.
  #   (권한 표기 '(750)' 등 라인 내부 괄호·다중라인 증적은 보존)
  case "$raw" in
    *$'\n'*) : ;;
    "("*")") raw="${raw#\(}"; raw="${raw%\)}" ;;
  esac
  # 판단기준(원문) — 양호/취약 모두. CSV·화면 공통.
  std="양호 : ${STD_PASS[$code]:-(기준 미정의)}"$'\n'"취약 : ${STD_VULN[$code]:-(기준 미정의)}"
  local i=${#F_CODE[@]}
  F_CODE[i]="$code"; F_SEV[i]="$sev"; F_NAME[i]="$name"; F_CAT[i]="$cat"
  F_FILE[i]="$file"; F_RAW[i]="$raw"; F_RESULT[i]="$result"; F_SUMMARY[i]="$summary"; F_STD[i]="$std"
  emit_screen "$code" "$sev" "$name" "$cat" "$std" "$result" "$raw" "$file"
}

show_preinfo() {
  echo "진단 스크립트 시작"
  echo "================================================================"
  echo "[사전 정보]"
  echo "현재 OS      : ${OS_NAME}"
  echo "점검 환경 IP : ${IP_ADDR}"
  echo "점검 분류    : WAS (Tomcat)    [전체 분류: WAS / DB / WEB / INFRA]"
  echo "점검 대상    : ${CATALINA_HOME}"
  echo "점검 시각    : ${TS}"
  echo "점검 방식    : 읽기 전용(설정 변경 없음)"
  if [ "$APP_ON" = "true" ]; then
    echo "점검 범위    : 컨테이너 설정(conf/) + 활성 앱 설정(${APP_CONTEXT_DIR}/WEB-INF, META-INF)"
    echo "앱 설정 파일 : web.xml=$( [ -r "${APP_WEB_XML:-}" ] && echo 있음 || echo 없음 ), DB/시크릿 파일 ${#APP_DB_FILES[@]}개"
  else
    echo "점검 범위    : Tomcat 컨테이너 설정(conf/) — 앱 레벨 점검 비활성(CHECK_APP_CONFIG=false)"
  fi
  echo "설정 파일    : ${CONF_FILE}"
  echo "================================================================"
}

#############################################################################
# 점검 함수
#############################################################################
diag_web01() {
  local nm="Default 관리자 계정명 변경" f="$TOMCAT_USERS_XML"
  if [ ! -r "$f" ]; then record "WEB-01" "상" "$nm" "$R_NA" "$f" "(읽기 불가 또는 부재)" "tomcat-users.xml 확인 불가 — 수동 확인"; return; fi
  local users mgr; users="$(strip_xml_comments "$f" | grep -i '<user ')"
  mgr="$(printf '%s' "$users" | grep -iE 'roles=("|'\'')[^"'\'']*manager-(gui|script|jmx|status)')"
  if [ -z "$mgr" ]; then record "WEB-01" "상" "$nm" "$R_PASS" "$f" "${users:-(활성 user 계정 없음)}" "활성 manager-* 역할 계정 없음"; return; fi
  local unames bad u d; unames="$(printf '%s' "$mgr" | grep -oiE 'username=("|'\'')[^"'\'']+' | sed -E 's/username=.//I')"
  bad=""
  for u in $unames; do for d in $DEFAULT_ADMIN_NAMES; do
    [ "$(printf '%s' "$u"|tr 'A-Z' 'a-z')" = "$(printf '%s' "$d"|tr 'A-Z' 'a-z')" ] && bad="$bad $u"; done; done
  if [ -n "$bad" ]; then record "WEB-01" "상" "$nm" "$R_VULN" "$f" "$mgr" "기본/추측쉬운 계정명:${bad}"
  else record "WEB-01" "상" "$nm" "$R_PASS" "$f" "$mgr" "관리자 계정명이 기본값 아님(${unames})"; fi
}

diag_web02() {
  local nm="취약한 비밀번호 사용 제한" f="$TOMCAT_USERS_XML"
  if [ ! -r "$f" ]; then record "WEB-02" "상" "$nm" "$R_NA" "$f" "(읽기 불가/부재)" "tomcat-users.xml 확인 불가"; return; fi
  local users; users="$(strip_xml_comments "$f" | grep -i '<user ')"
  if [ -z "$users" ]; then record "WEB-02" "상" "$nm" "$R_PASS" "$f" "(활성 user 계정 없음)" "활성 user 계정 없음"; return; fi
  local digest=""; [ -r "$SERVER_XML" ] && digest="$(strip_xml_comments "$SERVER_XML" | grep -ioE 'digest=("|'\'')[^"'\'']+' | head -1)"
  local weakhit="" line pw uname reason lpw w wl pat ulc
  while IFS= read -r line; do
    pw="$(printf '%s' "$line"|grep -oiE 'password=("|'\'')[^"'\'']*'|sed -E 's/password=.//I')"
    uname="$(printf '%s' "$line"|grep -oiE 'username=("|'\'')[^"'\'']*'|sed -E 's/username=.//I')"
    [ -z "$pw" ] && continue
    reason=""; lpw="$(printf '%s' "$pw"|tr 'A-Z' 'a-z')"
    for w in $WEAK_PASSWORDS; do wl="$(printf '%s' "$w"|tr 'A-Z' 'a-z')"; case "$lpw" in *"$wl"*) reason="사전단어(${w})"; break ;; esac; done
    if [ -z "$reason" ] && [ "${#WEAK_PASSWORD_REGEX[@]}" -gt 0 ]; then
      for pat in "${WEAK_PASSWORD_REGEX[@]}"; do pw_matches_regex "$pw" "$pat" && { reason="패턴(${pat})"; break; }; done; fi
    if [ -z "$reason" ] && [ -n "$uname" ]; then ulc="$(printf '%s' "$uname"|tr 'A-Z' 'a-z')"; case "$lpw" in *"$ulc"*) reason="ID포함" ;; esac; fi
    [ -n "$reason" ] && weakhit="$weakhit [${uname:-?}=>${reason}]"
  done <<< "$users"
  local raw; raw="$(printf '%s' "$users" | sed -E 's/(password=.)[^"'\'']*/\1********/I')"
  [ -n "$digest" ] && raw="${raw}"$'\n'"${SERVER_XML} ${digest}"
  if [ -n "$weakhit" ]; then record "WEB-02" "상" "$nm" "$R_VULN" "$f" "$raw" "취약/평문 비밀번호:${weakhit}"
  elif [ -n "$digest" ]; then record "WEB-02" "상" "$nm" "$R_PASS" "$f" "$raw" "digest 암호화 적용 + 약한 비밀번호 미발견"
  else record "WEB-02" "상" "$nm" "$R_PASS" "$f" "$raw" "약한 비밀번호 패턴 미발견(digest 적용 권고 — 수동 확인)"; fi
}

diag_web03() {
  local nm="비밀번호 파일 권한 관리" f="$TOMCAT_USERS_XML"
  if [ ! -e "$f" ]; then record "WEB-03" "상" "$nm" "$R_NA" "$f" "(파일 없음)" "tomcat-users.xml 없음"; return; fi
  local p; p="$(perm_of "$f")"
  if perm_subset "$p" "$PASSWD_FILE_MAX_PERM"; then record "WEB-03" "상" "$nm" "$R_PASS" "$f" "$(stat_line "$f")" "권한 ${p} (기준 ${PASSWD_FILE_MAX_PERM} 이하)"
  else record "WEB-03" "상" "$nm" "$R_VULN" "$f" "$(stat_line "$f")" "권한 ${p} (기준 ${PASSWD_FILE_MAX_PERM} 초과)"; fi
}

diag_web04() {
  local nm="웹 서비스 디렉터리 리스팅 방지 설정" files=("${WEB_XML_LIST[@]}")
  local readable=0 vuln="" raw="" ff body val
  for ff in "${files[@]}"; do [ -r "$ff" ] || continue; readable=1
    body="$(strip_xml_comments "$ff")"
    val="$(printf '%s' "$body" | tr -d '\n' | grep -ioE '<param-name>[[:space:]]*listings[[:space:]]*</param-name>[[:space:]]*<param-value>[[:space:]]*(true|false)' | grep -ioE '(true|false)$' | head -1)"
    [ -n "$val" ] && { raw="${raw}# ${ff}: listings=${val}"$'\n'; [ "$(printf '%s' "$val"|tr 'A-Z' 'a-z')" = "true" ] && vuln="yes"; }
  done
  [ "$readable" -eq 0 ] && { record "WEB-04" "상" "$nm" "$R_NA" "$(join_files "${files[@]}")" "(읽기 불가)" "web.xml 읽기 불가"; return; }
  [ -z "$raw" ] && raw="(listings 미설정 — Tomcat 기본값 false)"
  if [ -n "$vuln" ]; then record "WEB-04" "상" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$raw" "listings=true(디렉터리 리스팅 허용)"
  else record "WEB-04" "상" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "$raw" "listings 미설정/false"; fi
}

diag_web05() {
  local nm="지정하지 않은 CGI/ISAPI 실행 제한" files=("${WEB_XML_LIST[@]}")
  local cgi; cgi="$(scan_list 'servlet-name>[[:space:]]*cgi|org\.apache\.catalina\.servlets\.CGIServlet' "${files[@]}")"
  if [ -z "$cgi" ]; then record "WEB-05" "상" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "(활성 CGI 서블릿/매핑 없음 — 주석 제외)" "활성 CGI 서블릿/매핑 없음"
  else record "WEB-05" "상" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$cgi" "CGI 서블릿/매핑 활성화됨"; fi
}

diag_web06() {
  local nm="웹 서비스 상위 디렉터리 접근 제한 설정" files=("${CONTEXT_LIST[@]}" "$SERVER_XML")
  local m; m="$(scan_list 'allowLinking[[:space:]]*=[[:space:]]*("|'\'')?[[:space:]]*true|<Resources[^>]*allowLinking[[:space:]]*=[[:space:]]*("|'\'')?true' "${files[@]}")"
  if [ -n "$m" ]; then record "WEB-06" "상" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$m" "allowLinking=true 설정 존재"
  else record "WEB-06" "상" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "(allowLinking=true 미설정 — 기본 차단)" "allowLinking=true 미설정"; fi
}

diag_web07() {
  local nm="웹 서비스 경로 내 불필요한 파일 제거"
  if [ ! -d "$WEBAPPS_DIR" ]; then record "WEB-07" "중" "$nm" "$R_NA" "$WEBAPPS_DIR" "(webapps 없음)" "webapps 디렉터리 없음"; return; fi
  local found="" raw="" d ff
  for d in docs examples host-manager manager ROOT; do [ -d "${WEBAPPS_DIR}/${d}" ] && { found="$found ${d}"; raw="${raw}${WEBAPPS_DIR}/${d}"$'\n'; }; done
  for ff in RELEASE-NOTES BUILDING.txt; do [ -e "${CATALINA_HOME}/${ff}" ] && { found="$found ${ff}"; raw="${raw}${CATALINA_HOME}/${ff}"$'\n'; }; done
  if [ -n "$found" ]; then record "WEB-07" "중" "$nm" "$R_VULN" "$WEBAPPS_DIR" "$raw" "기본 샘플/매뉴얼 존재:${found}"
  else record "WEB-07" "중" "$nm" "$R_PASS" "$WEBAPPS_DIR" "(docs/examples/manager/host-manager 등 없음)" "기본 샘플/매뉴얼 없음"; fi
}

diag_web08() {
  local nm="웹 서비스 파일 업로드 및 다운로드 용량 제한"
  local scan=("${WEB_XML_LIST[@]}"); scan+=(${APP_CFG_FILES[@]+"${APP_CFG_FILES[@]}"})
  local mps="" upfeat="" limitval="" unlimited="" raw="" ff body mline ln
  # (1) Connector maxPostSize — 참고용(멀티파트엔 적용 안 될 수 있음). 판정엔 값, 표기엔 전체 라인.
  [ -r "$SERVER_XML" ] && mps="$(strip_xml_comments "$SERVER_XML" | grep -ioE 'maxPostSize[[:space:]]*=[[:space:]]*("|'\'')-?[0-9]+' | head -1)"
  [ -n "$mps" ] && { mline="$(strip_xml_comments "$SERVER_XML" | grep -iE 'maxPostSize' | head -1 | sed 's/^[[:space:]]*//' | tr -s ' \t' ' ')"; raw="${raw}# ${SERVER_XML}: ${mline}"$'\n'; }
  # (2) 앱/컨테이너 설정에서 업로드 기능 + 실제 단건/요청 용량 제한값(값까지) 추출
  for ff in "${scan[@]}"; do [ -r "$ff" ] || continue
    body="$(strip_xml_comments "$ff")"
    # 업로드 기능 탐지 — WEB-24와 동일 신호까지 포함(멀티파트 리졸버 없이 커스텀/commons-fileupload 처리 케이스 포착)
    printf '%s' "$body" | grep -iqE 'multipart-config|MultipartResolver|max-file-size|max-request-size|maxUploadSize|maxInMemorySize|fileupload|UploadConfig|upload\.[a-z.]*path|uploadDir|<servlet-(class|name)>[^<]*pload' && upfeat="yes"
    # 용량 제한값이 담긴 '전체 라인'을 근거로 표기 + 값으로 판정(무제한 -1 여부)
    while IFS= read -r ln; do [ -n "$ln" ] || continue
      raw="${raw}# ${ff}: $(printf '%s' "$ln" | sed 's/^[[:space:]]*//' | tr -s ' \t' ' ')"$'\n'; limitval="yes"
      printf '%s' "$ln" | grep -oE '\-?[0-9]+' | grep -qx -- -1 && unlimited="yes"
    done < <(printf '%s' "$body" | grep -iE '<max-(file|request)-size>[[:space:]]*-?[0-9]+|(maxUploadSize|maxInMemorySize)[^0-9-]{0,40}-?[0-9]+')
  done
  [ -z "$raw" ] && raw="(maxPostSize/multipart 단건 용량 제한 설정 없음)"
  local files; files="$SERVER_XML / $(join_files "${WEB_XML_LIST[@]}")"
  # 판정: 실제 업로드 단건/요청 제한값이 있고 무제한(-1)이 아니어야 양호.
  #        maxPostSize는 멀티파트에 적용 안 될 수 있어 단독으론 불충분.
  if [ -n "$limitval" ] && [ -z "$unlimited" ]; then
    record "WEB-08" "하" "$nm" "$R_PASS" "$files" "$raw" "업로드 단건/요청 용량 제한값 존재"
  elif [ -n "$unlimited" ]; then
    record "WEB-08" "하" "$nm" "$R_VULN" "$files" "$raw" "업로드 용량 제한이 무제한(-1)으로 설정됨"
  elif [ -n "$upfeat" ]; then
    record "WEB-08" "하" "$nm" "$R_VULN" "$files" "$raw" "업로드 기능 존재하나 설정상 단건 용량 제한(max-file-size/maxUploadSize) 없음 — maxPostSize는 멀티파트 미적용, 코드 레벨 제한 수동 확인"
  elif [ -n "$mps" ] && ! printf '%s' "$mps" | grep -qE '\-1'; then
    record "WEB-08" "하" "$nm" "$R_PASS" "$files" "$raw" "업로드 기능 미탐지 + maxPostSize 제한 존재"
  else
    record "WEB-08" "하" "$nm" "$R_VULN" "$files" "$raw" "용량 제한 미설정(또는 maxPostSize=-1)"
  fi
}

diag_web09() {
  local nm="웹 서비스 프로세스 권한 제한" pid runuser="" svcuser=""
  pid="$(pgrep -f 'org.apache.catalina.startup.Bootstrap' 2>/dev/null | head -1)"
  [ -n "$pid" ] && runuser="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
  command -v systemctl >/dev/null 2>&1 && svcuser="$(systemctl show "$TOMCAT_SERVICE" -p User 2>/dev/null | cut -d= -f2)"
  local effuser="${runuser:-$svcuser}"
  if [ -z "$effuser" ]; then record "WEB-09" "상" "$nm" "$R_NA" "systemd:${TOMCAT_SERVICE} / process" "(프로세스/서비스 사용자 확인 불가)" "구동 계정 확인 불가 — 수동 확인"; return; fi
  local grps; grps="$(id -nG "$effuser" 2>/dev/null)"
  local shell; shell="$(getent passwd "$effuser" 2>/dev/null | cut -d: -f7)"
  local shellnote
  case "$shell" in
    */nologin|*/false) shellnote="비로그인 셸(${shell})" ;;
    "")                shellnote="셸 확인 불가" ;;
    *)                 shellnote="로그인 셸 허용(${shell}) — 확인 권장" ;;
  esac
  local raw="pid=${pid:-N/A}  user=${effuser}  svcUser=${svcuser:-N/A}"$'\n'"groups=[${grps}]  shell=${shell:-N/A}"
  local isadmin="" a g pg
  for a in $ADMIN_RUN_USERS; do [ "$effuser" = "$a" ] && isadmin="root/관리자계정"; done
  if [ -z "$isadmin" ] && [ -n "$grps" ]; then for g in $grps; do for pg in $PRIVILEGED_GROUPS; do [ "$g" = "$pg" ] && isadmin="권한그룹:${g}"; done; done; fi
  local dedicated="" e; for e in $EXPECTED_RUN_USERS; do [ "$effuser" = "$e" ] && dedicated="yes"; done
  if [ -n "$isadmin" ]; then record "WEB-09" "상" "$nm" "$R_VULN" "systemd:${TOMCAT_SERVICE} / process" "$raw" "관리자 권한 계정(${effuser}, ${isadmin})으로 구동 — 최소권한 전용 계정 분리 필요"
  elif [ -n "$dedicated" ]; then record "WEB-09" "상" "$nm" "$R_PASS" "systemd:${TOMCAT_SERVICE} / process" "$raw" "최소권한 전용 계정(${effuser})으로 구동 — ${shellnote}"
  else record "WEB-09" "상" "$nm" "$R_PASS" "systemd:${TOMCAT_SERVICE} / process" "$raw" "비관리자/비권한그룹 계정(${effuser}) — 전용계정 목록 외, 권한 수동 확인 권장 (${shellnote})"; fi
}

diag_web10() {
  local nm="불필요한 프록시 설정 제한" f="$SERVER_XML"
  if [ ! -r "$f" ]; then record "WEB-10" "상" "$nm" "$R_NA" "$f" "(읽기 불가)" "server.xml 읽기 불가"; return; fi
  local px; px="$(strip_xml_comments "$f" | grep -iE 'proxyName|proxyPort')"
  if [ -z "$px" ]; then record "WEB-10" "상" "$nm" "$R_PASS" "$f" "(Connector proxyName/proxyPort 설정 없음)" "Connector proxy 설정 없음"
  else record "WEB-10" "상" "$nm" "$R_VULN" "$f" "$px" "프록시 설정 존재 — 필요 여부 수동 확인"; fi
}

diag_web11() {
  local nm="웹 서비스 경로 설정" f="$SERVER_XML"
  if [ ! -r "$f" ]; then record "WEB-11" "중" "$nm" "$R_NA" "$f" "(읽기 불가)" "server.xml 읽기 불가"; return; fi
  # appBase 추출 + 절대경로 resolve (상대값은 CATALINA_BASE 기준)
  local appbase abs_appbase raw db dbpath found_sep="" found_unsep="" lh
  appbase="$(strip_xml_comments "$f" | grep -ioE 'appBase[[:space:]]*=[[:space:]]*("|'\'')[^"'\'']*' | sed -E 's/.*appBase[[:space:]]*=[[:space:]]*.//I' | head -1)"
  [ -z "$appbase" ] && appbase="webapps"
  case "$appbase" in /*) abs_appbase="$appbase" ;; *) abs_appbase="${CATALINA_BASE%/}/$appbase" ;; esac
  raw="appBase=${appbase} (=> ${abs_appbase})"$'\n'
  # 명시적 docBase 수집: server.xml + conf/Catalina/localhost/*.xml (상대값은 appBase 기준 resolve)
  lh="${CATALINA_BASE%/}/conf/Catalina/localhost"
  while IFS= read -r db; do
    [ -n "$db" ] || continue
    case "$db" in /*) dbpath="$db" ;; *) dbpath="${abs_appbase%/}/$db" ;; esac
    raw="${raw}docBase=${db} (=> ${dbpath})"$'\n'
    case "${dbpath%/}/" in "${CATALINA_HOME%/}/"*|"${CATALINA_BASE%/}/"*) found_unsep="yes" ;; *) found_sep="yes" ;; esac
  done < <( { strip_xml_comments "$f"; [ -d "$lh" ] && cat "$lh"/*.xml 2>/dev/null; } | grep -ioE 'docBase[[:space:]]*=[[:space:]]*("|'\'')[^"'\'']+' | sed -E 's/.*docBase[[:space:]]*=[[:space:]]*.//' )
  # appBase 자체가 설치경로(CATALINA_HOME/BASE) 하위인지
  local appbase_unsep=""; case "${abs_appbase%/}/" in "${CATALINA_HOME%/}/"*|"${CATALINA_BASE%/}/"*) appbase_unsep="yes" ;; esac
  # 판정(기준 A): 웹 컨텐츠가 WAS 설치 경로 하위면 '미분리'=취약, 외부 분리경로면 양호
  if [ -n "$found_unsep" ]; then
    record "WEB-11" "중" "$nm" "$R_VULN" "$f" "$raw" "docBase가 WAS 설치 경로(${CATALINA_HOME}) 하위 — 기타 업무와 미분리"
  elif [ -n "$found_sep" ]; then
    record "WEB-11" "중" "$nm" "$R_PASS" "$f" "$raw" "웹 컨텐츠가 WAS 설치 경로 외부의 분리된 docBase로 설정됨"
  elif [ -n "$appbase_unsep" ]; then
    record "WEB-11" "중" "$nm" "$R_VULN" "$f" "$raw" "appBase가 WAS 설치 경로(${CATALINA_HOME}) 하위 — 웹 경로가 기타 업무와 미분리(별도 경로 분리 필요)"
  else
    record "WEB-11" "중" "$nm" "$R_PASS" "$f" "$raw" "웹 경로가 WAS 설치 경로 외부로 분리됨"
  fi
}

diag_web12() {
  local nm="웹 서비스 링크 사용 금지" files=("${CONTEXT_LIST[@]}" "$SERVER_XML")
  local m; m="$(scan_list 'allowLinking[[:space:]]*=[[:space:]]*("|'\'')?true|<.*Resources[^>]*allowLinking' "${files[@]}")"
  if [ -n "$m" ]; then record "WEB-12" "중" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$m" "심볼릭 링크 허용(allowLinking) 설정 존재"
  else record "WEB-12" "중" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "(allowLinking 허용 설정 없음)" "링크(allowLinking) 사용 미허용"; fi
}

diag_web13() {
  local nm="웹 서비스 설정 파일 노출 제한" raw="" vuln="" detail="" hasany="" ff p
  # 1) 컨테이너: server.xml/context.xml 의 노출 DB Resource + 권한
  for ff in "$SERVER_XML" "$CONTEXT_XML"; do [ -r "$ff" ] || continue
    if strip_xml_comments "$ff" | grep -iqE '<Resource[^>]*(javax\.sql\.DataSource|password=)'; then
      hasany=1; p="$(perm_of "$ff")"; raw="${raw}$(stat_line "$ff")"$'\n'
      others_has_access "$p" && { vuln="yes"; detail="${detail} $(basename "$ff")(other접근:${p})"; }
      perm_subset "$p" "$DB_CONF_MAX_PERM" || { vuln="yes"; detail="${detail} $(basename "$ff")(권한과다:${p}>${DB_CONF_MAX_PERM})"; }
    fi
  done
  # 2) 앱: Spring datasource/properties 의 DB 자격증명 파일 권한 + 웹 접근 가능 위치 여부
  if [ "$APP_ON" = "true" ] && [ "${#APP_DB_FILES[@]}" -gt 0 ]; then
    for ff in "${APP_DB_FILES[@]}"; do [ -e "$ff" ] || continue
      hasany=1; p="$(perm_of "$ff")"; raw="${raw}$(stat_line "$ff")"$'\n'
      others_has_access "$p" && { vuln="yes"; detail="${detail} $(basename "$ff")(other접근:${p})"; }
      perm_subset "$p" "$DB_CONF_MAX_PERM" || { vuln="yes"; detail="${detail} $(basename "$ff")(권한과다:${p}>${DB_CONF_MAX_PERM})"; }
      case "$ff" in *WEB-INF*|*META-INF*) : ;; "${APP_CONTEXT_DIR}"/*) vuln="yes"; detail="${detail} $(basename "$ff")(웹접근가능경로)" ;; esac
    done
  fi
  # 3) 불필요한 스크립트 매핑: 설정/소스 파일(.xml/.properties 등)을 직접 노출하는 url-pattern 매핑 존재 여부
  local mapraw; mapraw="$(scan_list '<url-pattern>[^<]*\.(xml|properties|config|conf|ini|bak|inc|sql)' "${WEB_XML_LIST[@]}")"
  [ -n "$mapraw" ] && { vuln="yes"; detail="${detail} 설정/소스파일 확장자 매핑"; raw="${raw}${mapraw}"$'\n'; }

  # 판정: vuln(권한/웹경로/매핑) 우선 → 취약. 그 외 DB리소스 유무에 따라 양호.
  if [ -n "$vuln" ]; then record "WEB-13" "상" "$nm" "$R_VULN" "DB 연결 설정 파일 / web.xml 매핑" "$raw" "DB 연결 파일 노출/접근권한·스크립트 매핑 부적절:${detail}"; return; fi
  if [ -z "$hasany" ]; then record "WEB-13" "상" "$nm" "$R_PASS" "$SERVER_XML / $CONTEXT_XML / 앱 설정" "(노출 DB 연결 설정 없음 + 설정파일 매핑 없음)" "노출 DB 연결 리소스/파일 없음 + 불필요한 스크립트 매핑 없음"; return; fi
  record "WEB-13" "상" "$nm" "$R_PASS" "DB 연결 설정 파일" "$raw" "DB 연결 파일 접근권한 적정(권한 ≤${DB_CONF_MAX_PERM}, other 접근 없음, WEB-INF 보호) + 불필요한 스크립트 매핑 없음"
}

diag_web14() {
  local nm="웹 서비스 경로 내 파일의 접근 통제" bad="" raw="" ff p
  local files=("$SERVER_XML" "$WEB_XML" "$CONTEXT_XML" "$TOMCAT_USERS_XML")
  [ "$APP_ON" = "true" ] && { [ -e "${APP_WEB_XML:-}" ] && files+=("$APP_WEB_XML"); files+=(${APP_DB_FILES[@]+"${APP_DB_FILES[@]}"}); }
  # 주요 설정 '디렉터리'도 점검 (KISA 기준: 주요 설정 파일 및 디렉터리에 불필요한 접근 권한 없을 것)
  local dirs=("$CONF_DIR")
  [ "$APP_ON" = "true" ] && { [ -d "${APP_CONTEXT_DIR}/WEB-INF" ] && dirs+=("${APP_CONTEXT_DIR}/WEB-INF"); }
  # 파일·디렉터리 권한이 CONF_FILE_MAX_PERM(750)의 칸별 부분집합이어야 양호 (기준 초과 = 취약, KISA 조치 chmod 750)
  for ff in "${files[@]}"; do [ -e "$ff" ] || continue
    raw="${raw}$(stat_line "$ff")"$'\n'
    p="$(perm_of "$ff")"; perm_subset "$p" "$CONF_FILE_MAX_PERM" || bad="$bad $(basename "$ff")(권한과다:${p}>${CONF_FILE_MAX_PERM})"
  done
  for ff in "${dirs[@]}"; do [ -d "$ff" ] || continue
    raw="${raw}$(stat_line "$ff")"$'\n'
    p="$(perm_of "$ff")"; perm_subset "$p" "$CONF_FILE_MAX_PERM" || bad="$bad $(basename "$ff")/(권한과다:${p}>${CONF_FILE_MAX_PERM})"
  done
  if [ -n "$bad" ]; then record "WEB-14" "상" "$nm" "$R_VULN" "conf/* + 앱 설정 파일·디렉터리" "$raw" "주요 설정 파일/디렉터리 권한 과다(기준 ${CONF_FILE_MAX_PERM} 부분집합 위반):${bad}"
  else record "WEB-14" "상" "$nm" "$R_PASS" "conf/* + 앱 설정 파일·디렉터리" "$raw" "주요 설정 파일 및 디렉터리 권한이 ${CONF_FILE_MAX_PERM} 부분집합(불필요한 접근 권한 없음)"; fi
}

diag_web15() {
  local nm="웹 서비스의 불필요한 스크립트 매핑 제거" files=("${WEB_XML_LIST[@]}")
  # 자동 취약 = 객관적으로 제거 대상인 스크립트 엔진(cgi/ssi). 일반 servlet-mapping의 '불필요' 여부는 앱별 수동 확인.
  local m; m="$(scan_list 'servlet-name>[[:space:]]*(cgi|ssi)[[:space:]]*<|CGIServlet|SSIServlet' "${files[@]}")"
  # 활성 servlet-mapping 원문 전수 나열(servlet-name/url-pattern) — UnuseServlet 류가 보이도록
  local maps="" ff body
  for ff in "${files[@]}"; do [ -r "$ff" ] || continue
    body="$(strip_xml_comments "$ff" | awk '/<servlet-mapping>/{p=1} p{print} /<\/servlet-mapping>/{p=0}' | grep -iE '<servlet-name>|<url-pattern>' | sed 's/^[[:space:]]*//')"
    [ -n "$body" ] && maps="${maps}# ${ff}"$'\n'"${body}"$'\n'
  done
  [ -z "$maps" ] && maps="(활성 servlet-mapping 없음)"
  if [ -n "$m" ]; then record "WEB-15" "상" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$maps" "활성 cgi/ssi 스크립트 매핑 존재(제거 필요) — 기타 매핑의 불필요 여부는 수동 확인"
  else record "WEB-15" "상" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "$maps" "객관적 불필요 스크립트(cgi/ssi) 매핑 없음 — 그 외 매핑의 불필요 여부는 앱별 수동 확인"; fi
}

diag_web16() {
  local nm="웹 서비스 헤더 정보 노출 제한" f="$SERVER_XML"
  if [ ! -r "$f" ]; then record "WEB-16" "중" "$nm" "$R_NA" "$f" "(읽기 불가)" "server.xml 읽기 불가"; return; fi
  local body flat svr showval hideok=""; body="$(strip_xml_comments "$f")"
  # 다중라인 요소(예: <Valve ... showServerInfo\n="false"/>) 대응 — 평탄화 후 값 판정
  flat="$(printf '%s' "$body" | tr '\n' ' ' | tr -s ' \t' ' ')"
  svr="$(printf '%s' "$flat" | grep -ioE 'server[[:space:]]*=[[:space:]]*("|'\'')[^"'\'']+' | head -1)"
  showval="$(printf '%s' "$flat" | grep -ioE 'showServerInfo[[:space:]]*=[[:space:]]*("|'\'')?(true|false)' | grep -ioE '(true|false)$' | head -1)"
  [ "$(printf '%s' "$showval" | tr 'A-Z' 'a-z')" = "false" ] && hideok="yes"
  # raw: 원문 그대로 — server= 라인 + ErrorReportValve 요소 '전체'(다중라인 포함)
  local raw="" svrline valve
  svrline="$(printf '%s' "$body" | grep -iE 'server[[:space:]]*=[[:space:]]*("|'\'')' | head -1 | sed 's/^[[:space:]]*//' | tr -s ' \t' ' ')"
  valve="$(printf '%s' "$body" | awk '/ErrorReportValve/{p=1} p{print; if(/>/) exit}' | sed 's/^[[:space:]]*//')"
  [ -n "$svrline" ] && raw="${raw}# ${f}: ${svrline}"$'\n'
  [ -n "$valve" ] && raw="${raw}# ${f} (ErrorReportValve 요소)"$'\n'"${valve}"$'\n'
  [ -z "$raw" ] && raw="(server 속성/showServerInfo 미설정)"
  if [ -n "$svr" ] || [ -n "$hideok" ]; then record "WEB-16" "중" "$nm" "$R_PASS" "$f" "$raw" "서버 정보 노출 제한 설정 적용"
  else record "WEB-16" "중" "$nm" "$R_VULN" "$f" "$raw" "server 속성/showServerInfo=false 미설정(버전 노출 가능)"; fi
}

diag_web17() {
  local nm="웹 서비스 가상 디렉터리 삭제" f="$SERVER_XML"
  if [ ! -r "$f" ]; then record "WEB-17" "중" "$nm" "$R_NA" "$f" "(읽기 불가)" "server.xml 읽기 불가"; return; fi
  local ctx; ctx="$(strip_xml_comments "$f" | grep -iE '<Context[^>]*path[[:space:]]*=[[:space:]]*("|'\'')[^"'\'']+')"
  if [ -z "$ctx" ]; then record "WEB-17" "중" "$nm" "$R_PASS" "$f" "(server.xml 내 명시적 Context path 없음)" "불필요한 가상 디렉터리(Context path) 없음"
  else record "WEB-17" "중" "$nm" "$R_VULN" "$f" "$ctx" "가상 디렉터리(Context path) 존재 — 필요 여부 수동 확인"; fi
}

diag_web18() { record "WEB-18" "상" "웹 서비스 WebDAV 비활성화" "$R_NA" "-" "(Tomcat 점검 대상 아님 / 대상: Apache·Nginx·IIS·WebtoB)" "Tomcat 점검 대상 아님 — 웹서버 진단에서 점검"; }

diag_web19() {
  local nm="웹 서비스 SSI(Server Side Includes) 사용 제한" files=("${WEB_XML_LIST[@]}")
  local ssi; ssi="$(scan_list 'SSIServlet|SSIFilter|servlet-name>[[:space:]]*ssi' "${files[@]}")"
  if [ -z "$ssi" ]; then record "WEB-19" "중" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "(SSI 서블릿/필터 매핑 없음 — 주석 제외)" "SSI 매핑 없음(비활성)"
  else record "WEB-19" "중" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "$ssi" "SSI 서블릿/필터 활성화됨"; fi
}

diag_web20() { record "WEB-20" "상" "SSL/TLS 활성화" "$R_NA" "-" "(Tomcat 점검 대상 아님 / SSL은 앞단 Apache 종단)" "Tomcat 점검 대상 아님 — 웹서버 진단에서 점검"; }
diag_web21() { record "WEB-21" "중" "HTTP 리디렉션" "$R_NA" "-" "(Tomcat 점검 대상 아님 / 대상: Apache·Nginx·IIS·WebtoB)" "Tomcat 점검 대상 아님 — 웹서버 진단에서 점검"; }

diag_web22() {
  local nm="에러 페이지 관리" files=("${WEB_XML_LIST[@]}") raw="" hit="" ff body lines
  for ff in "${files[@]}"; do [ -r "$ff" ] || continue
    body="$(strip_xml_comments "$ff")"
    printf '%s' "$body" | grep -iq '<error-page>' || continue
    hit="yes"
    # 원문 증적: error-page 블록 라인을 grep 원문 그대로(앞 공백만 정리)
    lines="$(printf '%s' "$body" | grep -iE '<error-page>|</error-page>|<error-code>|<exception-type>|<location>' | sed 's/^[[:space:]]*//')"
    raw="${raw}# ${ff}"$'\n'"${lines}"$'\n'
  done
  if [ -n "$hit" ]; then record "WEB-22" "하" "$nm" "$R_PASS" "$(join_files "${files[@]}")" "$raw" "일원화된 error-page 설정 존재"
  else record "WEB-22" "하" "$nm" "$R_VULN" "$(join_files "${files[@]}")" "(error-page 미설정)" "error-page 미설정(기본 에러페이지 → 정보 노출 우려)"; fi
}

diag_web23() {
  local nm="LDAP 알고리즘 적절하게 구성" f="$SERVER_XML"
  if [ ! -r "$f" ]; then record "WEB-23" "중" "$nm" "$R_NA" "$f" "(읽기 불가)" "server.xml 읽기 불가"; return; fi
  local body; body="$(strip_xml_comments "$f")"
  local hasldap=""; printf '%s' "$body" | grep -iqE 'JNDIRealm|ldap' && hasldap="yes"
  # digest / CredentialHandler algorithm 라인·값 추출 (가이드: grep digest= server.xml)
  local dgline dg up
  dgline="$(printf '%s' "$body" | grep -iE 'digest[[:space:]]*=|CredentialHandler|algorithm[[:space:]]*=' | sed -E 's/^[ \t]+//')"
  dg="$(printf '%s' "$body" | grep -ioE '(digest|algorithm)[[:space:]]*=[[:space:]]*("|'\'')[^"'\'']+' | sed -E 's/^[^"'\'']*("|'\'')//' | head -1)"
  # digest 설정도 없고 LDAP 연동도 없으면 점검 대상 없음 → 양호
  if [ -z "$dg" ] && [ -z "$hasldap" ]; then
    record "WEB-23" "중" "$nm" "$R_PASS" "$f" "(digest/LDAP(JNDIRealm) 설정 없음)" "LDAP 연동·digest 미사용"; return
  fi
  local raw; raw="$(printf '%s' "$dgline" | sed "s|^|# ${f}: |")"; [ -z "$dgline" ] && raw="(digest 설정 라인 없음)"; up="$(printf '%s' "$dg"|tr 'a-z' 'A-Z')"
  case "$up" in
    SHA-256|SHA-384|SHA-512|SHA256|SHA384|SHA512|SHA-512/256|SHA3-256|SHA3-384|SHA3-512)
      record "WEB-23" "중" "$nm" "$R_PASS" "$f" "$raw" "digest=${dg} (SHA-256 이상)" ;;
    "")
      record "WEB-23" "중" "$nm" "$R_VULN" "$f" "$raw" "LDAP/Realm 사용하나 digest 미지정" ;;
    *)
      record "WEB-23" "중" "$nm" "$R_VULN" "$f" "$raw" "digest=${dg} (SHA-256 미만 — 취약)" ;;
  esac
}

diag_web24() {
  local nm="별도의 업로드 경로 사용 및 권한 설정" scan_files=()
  local f; for f in "${WEB_XML_LIST[@]}" "$CONTEXT_XML" ${APP_DB_FILES[@]+"${APP_DB_FILES[@]}"}; do [ -r "$f" ] && scan_files+=("$f"); done
  if [ "${#scan_files[@]}" -eq 0 ]; then record "WEB-24" "중" "$nm" "$R_NA" "web.xml / context.xml / 앱 설정" "(읽기 불가)" "점검 파일 읽기 불가"; return; fi

  # 업로드 기능 탐지 + 모든 업로드 경로 값 추출(빈 값은 제외)
  local found="" srcfile="" body line v
  local paths=()
  for f in "${scan_files[@]}"; do body="$(strip_xml_comments "$f")"
    if printf '%s' "$body" | grep -iqE '<servlet-class>[^<]*pload|<servlet-name>[^<]*pload|multipart-config|MultipartResolver|<param-name>[[:space:]]*uploadDir|upload\.[a-z.]*path|UploadConfig'; then
      found="yes"; [ -z "$srcfile" ] && srcfile="$f"
      # (a) uploadDir context-param 값
      while IFS= read -r v; do [ -n "$v" ] && paths+=("$v"); done < <(printf '%s' "$body" | tr -d '\n' | grep -ioE '<param-name>[[:space:]]*uploadDir[[:space:]]*</param-name>[[:space:]]*<param-value>[^<]+' | sed -E 's/.*<param-value>[[:space:]]*//')
      # (b) upload.*path = <비어있지 않은 값>  (예: upload.file.path / upload.qna.path)
      while IFS= read -r v; do v="$(printf '%s' "$v" | sed -E 's/^[^=]*=[[:space:]]*//')"; [ -n "$v" ] && paths+=("$v"); done < <(printf '%s' "$body" | grep -ioE 'upload\.[a-z.]*path[[:space:]]*=[[:space:]]*[^[:space:]]+')
    fi
  done

  # 업로드 설정 자체가 없음 → 미사용으로 판단(양호)
  if [ -z "$found" ]; then record "WEB-24" "중" "$nm" "$R_PASS" "$(join_files "${scan_files[@]}")" "(업로드 서블릿/설정 없음 — 주석 제외)" "업로드 서블릿/설정 없음 → 업로드 기능 미사용으로 판단"; return; fi

  # 설정은 있으나 경로 값이 전부 비어있음 → 관례적 내부 경로 존재 여부로 보조 판정
  if [ "${#paths[@]}" -eq 0 ]; then
    if [ -d "${APP_CONTEXT_DIR}/upload" ]; then
      record "WEB-24" "중" "$nm" "$R_VULN" "$srcfile" "업로드경로=${APP_CONTEXT_DIR}/upload (기본 내부 경로)" "업로드 경로 미지정 + 웹루트 내부 기본 경로 존재 — 별도 경로 분리 필요"
    else
      record "WEB-24" "중" "$nm" "$R_PASS" "$srcfile" "(로컬 업로드 경로 미설정)" "로컬 업로드 경로 미설정(외부 저장 추정 — 수동 확인 권장)"
    fi
    return
  fi

  # 추출된 각 경로를 평가: 웹루트 내부 또는 other 접근 → 취약
  local vuln="" detail="" raw="설정파일=${srcfile}"$'\n' p perm inside owner xf
  for p in "${paths[@]}"; do
    inside=""; case "$p" in "${APP_CONTEXT_DIR}"/*|"${WEBAPPS_DIR}"/*) inside="yes" ;; esac
    perm=""; owner=""
    if [ -e "$p" ]; then perm="$(perm_of "$p")"; owner="$(stat -c '%U:%G' "$p" 2>/dev/null)"; fi
    raw="${raw}업로드경로=${p}  권한=${perm:-N/A}  소유자=${owner:-N/A}"$'\n'
    if [ -n "$inside" ]; then vuln="yes"; detail="${detail} ${p}(웹루트내부)"
    elif [ -n "$perm" ] && others_has_access "$perm"; then vuln="yes"; detail="${detail} ${p}(other접근:${perm})"; fi
    # 업로드 경로 내 실행권한(x) 파일 존재 = 업로드 파일 실행 위험
    if [ -d "$p" ]; then
      xf="$(find "$p" -maxdepth 1 -type f -perm /111 2>/dev/null | head -3 | tr '\n' ' ')"
      [ -n "$xf" ] && { vuln="yes"; detail="${detail} ${p}(실행권한파일:${xf})"; }
    fi
  done
  if [ -n "$vuln" ]; then record "WEB-24" "중" "$nm" "$R_VULN" "$srcfile" "$raw" "업로드 경로 문제:${detail}"
  else record "WEB-24" "중" "$nm" "$R_PASS" "$srcfile" "$raw" "업로드 경로가 웹루트 외부 + other 접근/실행권한 제한"; fi
}

diag_web25() {
  local nm="주기적 보안 패치 및 벤더 권고사항 적용" ver=""
  if [ -x "${CATALINA_HOME}/bin/version.sh" ]; then ver="$("${CATALINA_HOME}/bin/version.sh" 2>/dev/null | grep -i 'server number' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"; fi
  if [ -z "$ver" ] && command -v unzip >/dev/null 2>&1 && [ -r "${CATALINA_HOME}/lib/catalina.jar" ]; then
    ver="$(unzip -p "${CATALINA_HOME}/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep -i 'server.number' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"; fi
  if [ -z "$ver" ]; then record "WEB-25" "상" "$nm" "$R_NA" "${CATALINA_HOME}/bin/version.sh" "(버전 확인 불가)" "Tomcat 버전 확인 불가 — 수동 확인"; return; fi
  local lowest; lowest="$(printf '%s\n%s\n' "$ver" "$MIN_TOMCAT_VERSION" | sort -V | head -1)"
  local raw="설치 버전=${ver}"$'\n'"기준 버전=${MIN_TOMCAT_VERSION}"
  if [ "$lowest" = "$MIN_TOMCAT_VERSION" ]; then record "WEB-25" "상" "$nm" "$R_PASS" "ServerInfo (version.sh)" "$raw" "설치 버전 ${ver} >= 기준 ${MIN_TOMCAT_VERSION}"
  else record "WEB-25" "상" "$nm" "$R_VULN" "ServerInfo (version.sh)" "$raw" "설치 버전 ${ver} < 기준 ${MIN_TOMCAT_VERSION} (패치 필요)"; fi
}

diag_web26() {
  local nm="로그 디렉터리 및 파일 권한 설정"
  if [ ! -d "$LOG_DIR" ]; then record "WEB-26" "중" "$nm" "$R_NA" "$LOG_DIR" "(로그 디렉터리 없음)" "로그 디렉터리 없음"; return; fi
  local bad="" raw="" dp lf fp fcount=0
  dp="$(perm_of "$LOG_DIR")"; raw="$(stat_line "$LOG_DIR")"$'\n'
  others_has_access "$dp" && bad="$bad dir(${dp})"
  while IFS= read -r lf; do [ -z "$lf" ] && continue
    fp="$(perm_of "$lf")"; raw="${raw}$(stat_line "$lf")"$'\n'
    others_has_access "$fp" && bad="$bad $(basename "$lf")(${fp})"
    fcount=$((fcount+1)); [ "$fcount" -ge 10 ] && break
  done < <(find "$LOG_DIR" -maxdepth 1 -type f 2>/dev/null)
  if [ -n "$bad" ]; then record "WEB-26" "중" "$nm" "$R_VULN" "$LOG_DIR" "$raw" "로그 디렉터리/파일에 other 접근 권한 존재:${bad}"
  else record "WEB-26" "중" "$nm" "$R_PASS" "$LOG_DIR" "$raw" "로그 디렉터리/파일에 other 접근 권한 없음(dir=${dp})"; fi
}

#############################################################################
# 실행
#############################################################################
show_preinfo
echo
# ── 권한 사전 점검: 관리자(root) 권한이 아니면 예외(중단) ──
#    600/640 설정파일·750 디렉터리를 읽어야 정확한 진단이 가능하므로 root 가 필요.
#    (비-root는 일부만 읽혀 오탐이 나므로 아예 중단한다)
if [ "$(id -u)" -ne 0 ]; then
  {
    echo ""
    echo "================================================================"
    echo "[진단 중단] 관리자 권한(root/sudo)이 아닙니다."
    echo "  현재 계정 : $(id -un) (uid=$(id -u))"
    echo "  사유      : 권한 제한된 설정파일(예: $SERVER_XML)을 읽어야 정확히 진단됩니다."
    echo "  조치      : sudo 로 재실행하세요.  예) sudo ./was_diag.sh -c was_diag.conf"
    echo "================================================================"
  } >&2
  exit 2
fi
for f in "$SERVER_XML" "$WEB_XML" "$CONTEXT_XML" "$TOMCAT_USERS_XML"; do
  [ -e "$f" ] || echo "[경고] 핵심 설정 파일 없음: $f" >&2
done
[ -d "$CATALINA_HOME" ] || echo "[경고] CATALINA_HOME 없음: $CATALINA_HOME" >&2

diag_web01; diag_web02; diag_web03; diag_web04; diag_web05; diag_web06
diag_web07; diag_web08; diag_web09; diag_web10; diag_web11; diag_web12
diag_web13; diag_web14; diag_web15; diag_web16; diag_web17; diag_web18
diag_web19; diag_web20; diag_web21; diag_web22; diag_web23; diag_web24
diag_web25; diag_web26

TOTAL=$((CNT_PASS+CNT_VULN+CNT_NA))

# ── 보고서 TXT ─────────────────────────────────────────────
{
  show_preinfo
  echo
  printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
  echo "================================================================"
  i=0
  while [ "$i" -lt "${#F_CODE[@]}" ]; do
    emit_screen "${F_CODE[$i]}" "${F_SEV[$i]}" "${F_NAME[$i]}" "${F_CAT[$i]}" "${F_STD[$i]}" "${F_RESULT[$i]}" "${F_RAW[$i]}" "${F_FILE[$i]}"
    i=$((i+1))
  done
  echo "※ '수동 확인' 표기 항목과 취약 항목은 담당자의 실제 설정 검토로 최종 확정 필요."
} > "$REPORT"

# ── 로우데이터 CSV ─────────────────────────────────────────
csv_field() {
  # CSV 1필드: 큰따옴표 이스케이프 + 여러 줄은 " | "로 연결(경로의 / 와 혼동 방지)
  local v; v="$(printf '%s' "$1" | sed 's/"/""/g' | awk '{a[NR]=$0} END{for(i=1;i<=NR;i++) printf "%s%s",(i>1?" | ":""),a[i]}')"
  printf '"%s"' "$v"
}
{
  printf '\xEF\xBB\xBF'   # UTF-8 BOM — Excel 한글 깨짐 방지
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_field 항목코드)" "$(csv_field 분류)" "$(csv_field 항목)" "$(csv_field 판단기준)" \
    "$(csv_field 결과)" "$(csv_field 점검내용)" "$(csv_field 진단대상)" "$(csv_field 진단대상IP)" \
    "$(csv_field 중요도)" "$(csv_field 점검파일)"
  i=0
  while [ "$i" -lt "${#F_CODE[@]}" ]; do
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_field "${F_CODE[$i]}")" "$(csv_field "${F_CAT[$i]}")" "$(csv_field "${F_NAME[$i]}")" \
      "$(csv_field "${F_STD[$i]}")" "$(csv_field "${F_RESULT[$i]}")" "$(csv_field "${F_RAW[$i]}")" \
      "$(csv_field "$TARGET_SYS")" "$(csv_field "$IP_ADDR")" "$(csv_field "${F_SEV[$i]}")" \
      "$(csv_field "${F_FILE[$i]}")"
    i=$((i+1))
  done
} > "$RAW_CSV"

# ── 콘솔 종합 ──────────────────────────────────────────────
echo "================================================================"
printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
echo " 보고서(TXT)     : $REPORT"
echo " 로우데이터(CSV) : $RAW_CSV"
echo "진단 스크립트 종료"
