#!/usr/bin/env bash
#############################################################################
# 웹서버(Apache) 자동 진단 스크립트
#   KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 - 웹 서비스(WEB-01~26)
#   대상: Apache HTTP Server 2.4 (Debian/Ubuntu apache2 레이아웃).
#
# 특징
#   - 읽기 전용(READ-ONLY): cat/grep/stat/ls/ps/systemctl(show) 만 사용. 설정 변경 없음.
#   - 판정값: 양호 / 취약 / N/A 3가지만.
#   - 출력: 항목별 구조화(콘솔 실시간) + 보고서(TXT) + 외부 진단용 로우데이터(CSV).
#   - 계정관리(WEB-01/02/03)·DB연결(13)·스크립트매핑(15)·LDAP(23)은 Apache 비대상 → N/A.
#
# 사용법
#   sudo ./web_diag.sh [-c web_diag.conf] [-o 출력디렉터리]
#############################################################################
set -u
LC_ALL=C.UTF-8 2>/dev/null || true
export TZ='Asia/Seoul'   # 진단 시각 KST 고정 (서버 TZ가 UTC여도 KST로 표기)

R_PASS="양호"; R_VULN="취약"; R_NA="N/A"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/web_diag.conf"
OVERRIDE_OUTPUT=""
while getopts "c:o:h" opt; do
  case "$opt" in
    c) CONF_FILE="$OPTARG" ;; o) OVERRIDE_OUTPUT="$OPTARG" ;;
    h) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 0 ;;
    *) echo "사용법: $0 [-c 설정파일] [-o 출력디렉터리]"; exit 1 ;;
  esac
done
[ -f "$CONF_FILE" ] || { echo "[ERROR] 설정 파일 없음: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF_FILE"
[ -n "$OVERRIDE_OUTPUT" ] && OUTPUT_DIR="$OVERRIDE_OUTPUT"

# ── 메타/환경 ───────────────────────────────────────────────
TS="$(date '+%Y-%m-%d %H:%M:%S')"; TS_FILE="$(date '+%Y%m%d_%H%M%S')"
HOSTN="$(hostname 2>/dev/null || echo unknown)"; LABEL="${TARGET_LABEL:-$HOSTN}"
OS_NAME="$( ( . /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME" ) || true )"
[ -z "$OS_NAME" ] && OS_NAME="$(uname -sr 2>/dev/null || echo unknown)"
IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -z "$IP_ADDR" ] && IP_ADDR="$HOSTN"
TARGET_SYS="Web(Apache)"   # 진단대상(자산 종류) — CSV/화면 공통 표기

mkdir -p "$OUTPUT_DIR" 2>/dev/null || { echo "[ERROR] 출력 디렉터리 생성 실패: $OUTPUT_DIR" >&2; exit 1; }
RAW_CSV="${OUTPUT_DIR}/web_diag_raw_${LABEL}_${TS_FILE}.csv"
HISTORY="${OUTPUT_DIR}/web_diag_report_${LABEL}_${TS_FILE}.txt"

# ── 적재된 모듈 목록 (IfModule 평가용) ─────────────────────
#   각 *.load 의 LoadModule 식별자(cgi_module)와 .c 파일명(mod_cgi.c) 둘 다 수집
LOADED_MODS=""
if [ -d "$MODS_ENABLED_DIR" ]; then
  while IFS= read -r ln; do
    set -- $ln  # LoadModule <ident> <path/mod_X.so>
    [ -n "${2:-}" ] && LOADED_MODS="$LOADED_MODS $2"
    [ -n "${3:-}" ] && LOADED_MODS="$LOADED_MODS $(basename "$3" | sed 's/\.so$/.c/')"
  done < <(grep -hiE '^[[:space:]]*LoadModule' "$MODS_ENABLED_DIR"/*.load 2>/dev/null)
fi

# 비활성 <IfModule>/<IfDefine> 블록을 제거(조건 평가). Define 추적으로 IfDefine 까지 처리.
# 파일을 직접 인자로 받아, 활성(IfModule/IfDefine) 라인마다 '출처 파일(풀패스)'을
# 줄 끝에 ‹...›로 덧붙여 출력한다. (검출 패턴은 줄 시작 기준이라 끝 표기는 로직에 무영향)
apache_filter() {
  awk -v mods="$LOADED_MODS" '
    BEGIN{ n=split(mods,M," "); for(i=1;i<=n;i++) L[M[i]]=1; depth=0 }
    FNR==1 { depth=0; sf=FILENAME }
    /^[[:space:]]*#/ { next }
    {
      l=$0
      if (match(l, /<[Ii][Ff][A-Za-z]+[[:space:]]+!?[^>]*>/)) {
        depth++
        if (l ~ /<[Ii][Ff][Mm]odule/) {
          neg=(l ~ /[Mm]odule[[:space:]]+!/); m=l; sub(/.*[Mm]odule[[:space:]]+!?/,"",m); sub(/>.*/,"",m); gsub(/[[:space:]]/,"",m)
          a=(m in L)?1:0; if(neg)a=1-a
        } else if (l ~ /<[Ii][Ff][Dd]efine/) {
          neg=(l ~ /[Dd]efine[[:space:]]+!/); d=l; sub(/.*[Dd]efine[[:space:]]+!?/,"",d); sub(/>.*/,"",d); gsub(/[[:space:]]/,"",d)
          a=(d in DEF)?1:0; if(neg)a=1-a
        } else a=1
        act[depth]=a; next
      }
      if (l ~ /<\/[Ii][Ff][A-Za-z]+>/) { if(depth>0) depth--; next }
      ok=1; for(k=1;k<=depth;k++) if(!act[k]) ok=0
      if(!ok) next
      if (l ~ /^[[:space:]]*Define[[:space:]]+/){ d2=l; sub(/^[[:space:]]*Define[[:space:]]+/,"",d2); sub(/[[:space:]].*/,"",d2); DEF[d2]=1 }
      print l "\t‹" sf "›"
    }' "$@"
}

# ── 유효 설정(주석 제거 + 비활성 블록 제거 + 파일별 출처 표기) ────
ACFG_FILES=()
_ACFG_SEEN=""
# 중복 수집 방지: security.conf 는 $SECURITY_CONF 와 conf-enabled/* 양쪽에서 잡혀 두 번 들어간다.
# 심볼릭 링크(sites-enabled→sites-available)까지 고려해 실경로(readlink -f) 기준으로 1회만 추가.
add_acfg() {
  local rp; rp="$(readlink -f "$1" 2>/dev/null || printf '%s' "$1")"
  case " $_ACFG_SEEN " in *" $rp "*) return ;; esac
  _ACFG_SEEN="$_ACFG_SEEN $rp"; ACFG_FILES+=("$1")
}
for f in "$APACHE_CONF" "$PORTS_CONF" "$SECURITY_CONF"; do [ -r "$f" ] && add_acfg "$f"; done
for d in "$CONF_ENABLED_DIR" "$SITES_DIR"; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do [ -r "$f" ] && add_acfg "$f"; done
done
if [ "${#ACFG_FILES[@]}" -gt 0 ]; then ACFG="$(apache_filter "${ACFG_FILES[@]}")"; else ACFG=""; fi

# ── 저장소 ──────────────────────────────────────────────────
F_CODE=(); F_SEV=(); F_NAME=(); F_CAT=(); F_FILE=(); F_RAW=(); F_RESULT=(); F_SUMMARY=(); F_STD=()
CNT_PASS=0; CNT_VULN=0; CNT_NA=0

# ── KISA 판단기준 문구 (Apache 대상 항목) ──────────────────
declare -A CRIT_PASS CRIT_VULN
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
CRIT_PASS[WEB-10]="불필요한 Proxy(정방향) 설정을 제한함"
CRIT_VULN[WEB-10]="불필요한 Proxy(정방향) 설정을 제한하지 않음"
CRIT_PASS[WEB-11]="웹 서버 경로가 기타 업무와 분리된 경로로 설정되고 불필요한 경로가 없음"
CRIT_VULN[WEB-11]="웹 서버 경로가 분리되지 않았거나 불필요한 경로가 존재함"
CRIT_PASS[WEB-12]="심볼릭 링크(FollowSymLinks) 사용을 허용하지 않음"
CRIT_VULN[WEB-12]="심볼릭 링크(FollowSymLinks) 사용을 허용함"
CRIT_PASS[WEB-14]="주요 설정 파일 및 SSL 키에 불필요한 접근 권한이 부여되지 않음"
CRIT_VULN[WEB-14]="주요 설정 파일 또는 SSL 키에 불필요한 접근 권한이 부여됨"
CRIT_PASS[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않음"
CRIT_VULN[WEB-16]="HTTP 응답 헤더에서 웹 서버 정보가 노출됨"
CRIT_PASS[WEB-17]="불필요한 가상 디렉터리(Alias)가 존재하지 않음"
CRIT_VULN[WEB-17]="불필요한 가상 디렉터리(Alias)가 존재함"
CRIT_PASS[WEB-18]="WebDAV 서비스를 비활성화하고 있음"
CRIT_VULN[WEB-18]="WebDAV 서비스를 활성화하고 있음"
CRIT_PASS[WEB-19]="웹 서비스 SSI 사용 설정이 비활성화되어 있음"
CRIT_VULN[WEB-19]="웹 서비스 SSI 사용 설정이 활성화되어 있음"
CRIT_PASS[WEB-20]="SSL/TLS 설정이 활성화되어 있음"
CRIT_VULN[WEB-20]="SSL/TLS 설정이 비활성화되어 있음"
CRIT_PASS[WEB-21]="HTTP 접근 시 HTTPS Redirection이 활성화됨"
CRIT_VULN[WEB-21]="HTTP 접근 시 HTTPS Redirection이 비활성화됨"
CRIT_PASS[WEB-22]="웹 서비스 에러 페이지가 별도로 지정됨"
CRIT_VULN[WEB-22]="에러 페이지가 별도로 지정되지 않았거나 에러 발생 시 중요 정보가 노출됨"
CRIT_PASS[WEB-24]="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않음"
CRIT_VULN[WEB-24]="별도의 업로드 경로를 사용하지 않거나 일반 사용자의 접근 권한이 부여됨"
CRIT_PASS[WEB-25]="최신 보안 패치가 적용되어 있으며 주기적인 패치 관리를 함"
CRIT_VULN[WEB-25]="최신 보안 패치가 적용되어 있지 않거나 주기적인 패치 관리를 하지 않음"
CRIT_PASS[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없음"
CRIT_VULN[WEB-26]="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있음"

# ── KISA 판단기준(원문) ─────────────────────────────────────
#  2026 주요정보통신기반시설 상세가이드 - 웹 서비스 판단 기준 '양호/취약' 원문 그대로.
#  (판단기준 필드용 — 가공/요약하지 않는다. 판단 '근거'는 CRIT_*로 별도 생성. was/web 공통)
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

# ── KISA 조치 방법(원문) WEB-01~26 ──────────────────────────
#  03_웹_서비스.pdf '조치 방법' 절 발췌. 항목코드별 권고 조치를 하드코딩(결과와 무관하게 항목 기준값).
declare -A REMED
REMED[WEB-01]="기본 관리자 계정명을 추측하기 어려운 계정명으로 설정"
REMED[WEB-02]="복잡도 기준에 맞는 추측하기 어려운 비밀번호 설정"
REMED[WEB-03]="비밀번호 파일 권한 600 이하로 설정"
REMED[WEB-04]="디렉터리 리스팅 기능 차단 설정"
REMED[WEB-05]="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"
REMED[WEB-06]="상위 디렉터리 접근 기능 제거 설정"
REMED[WEB-07]="불필요한 파일 및 디렉터리를 제거하도록 설정"
REMED[WEB-08]="파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정"
REMED[WEB-09]="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"
REMED[WEB-10]="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"
REMED[WEB-11]="웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"
REMED[WEB-12]="웹 서비스 링크 사용 제한 설정"
REMED[WEB-13]="DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정"
REMED[WEB-14]="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"
REMED[WEB-15]="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"
REMED[WEB-16]="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"
REMED[WEB-17]="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"
REMED[WEB-18]="WebDAV 서비스 비활성화 설정"
REMED[WEB-19]="웹 서비스 내 불필요한 SSI 사용 제한 설정"
REMED[WEB-20]="웹 서비스 내 SSL/TLS 활성화 설정"
REMED[WEB-21]="HTTP Redirection 활성화 설정"
REMED[WEB-22]="필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정"
REMED[WEB-23]="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"
REMED[WEB-24]="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"
REMED[WEB-25]="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정"
REMED[WEB-26]="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"

cat_of() {
  case "$1" in
    WEB-01|WEB-02|WEB-03) printf '계정 관리' ;;
    WEB-19|WEB-20|WEB-21|WEB-22|WEB-23) printf '보안 설정' ;;
    WEB-24|WEB-25|WEB-26) printf '패치 및 로그 관리' ;;
    *) printf '서비스 관리' ;;
  esac
}

# ── 헬퍼 ────────────────────────────────────────────────────
perm_of() { [ -e "$1" ] && stat -L -c '%a' "$1" 2>/dev/null || echo ""; }   # -L: 심볼릭 링크 타겟 권한
stat_line() { [ -e "$1" ] && stat -L -c '%A (%a) %U:%G  %n' "$1" 2>/dev/null; }
perm_subset() { [ -n "$1" ] && [ "$(( (8#$1) & ~(8#$2) ))" -eq 0 ]; }   # 파일 권한이 기준 권한의 '칸별 부분집합'이면 통과(owner/group/other 비트별 — 8진수 통째 비교 ❌)
others_has_access() { local p="$1"; [ -n "$p" ] && [ "$(( 8#$p % 8 ))" -ne 0 ]; }
others_has_write() { local p="$1"; [ -n "$p" ] && [ "$(( (8#$p % 8) & 2 ))" -ne 0 ]; }
join_files() { local o="" f; for f in "$@"; do o="${o:+$o / }$f"; done; printf '%s' "$o"; }
mod_enabled() { ls "$MODS_ENABLED_DIR"/ 2>/dev/null | grep -qiE "^${1}\.(load|conf)$"; }
acfg_grep() { printf '%s' "$ACFG" | grep -iE "$1"; }
# ACFG 라인 끝의 출처태그(\t‹파일›)를 표준 '# <파일>' 헤더로 재배치(연속 동일 출처는 1회만).
#   Apache 설정은 여러 파일에서 병합되므로 각 증적이 '어느 파일'에서 왔는지 헤더로 명시(DIAG_STYLE §3.2).
regroup_src() {
  printf '%s' "$1" | awk '
    {
      line=$0; src=""
      i=index(line, "\t‹")
      if (i>0) { src=substr(line, i+1); line=substr(line, 1, i-1); sub(/^‹/,"",src); sub(/›$/,"",src) }
      if (src!="" && src!=cur) { print "# " src; cur=src }
      print line
    }'
}
# ACFG에서 정규식 매칭 라인을 소속 블록 헤더(<Directory>/<Location>/<Files>)와 함께 출력.
#   Options 등 지시자는 어느 디렉터리에 적용되는지가 판정에 중요한데, 라인만 보면 동일해 보여 구분 불가
#   → 블록 헤더를 같이 출력(출처태그 ‹›는 유지 → record의 regroup_src가 '# 파일' 헤더로 변환).
acfg_ctx() {
  printf '%s' "$ACFG" | awk -v pat="$1" '
    /<[Dd]irectory|<[Ll]ocation|<[Ff]iles/ { hdr=$0; shown=0 }
    /<\/[Dd]irectory|<\/[Ll]ocation|<\/[Ff]iles/ { hdr=""; shown=0 }
    tolower($0) ~ tolower(pat) {
      if (hdr!="" && !shown) { print hdr; shown=1 }
      print $0
    }'
}

# 점검내용을 화면용으로 최대 8줄까지만 (나머지는 생략 — 상세는 CSV)
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
# emit_screen CODE SEV NAME CAT STD RESULT RAW FILE  ($4 CAT 미사용: 화면 제외, CSV에만)
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
  # ACFG 출처태그(\t‹파일›)를 '# <파일>' 헤더로 재배치(어느 파일의 설정인지 명시)
  raw="$(regroup_src "$raw")"
  # 점검내용이 '결과 없음(자연어)'일 때 감싼 괄호 제거 — 전체가 한 줄이고 (…)로 통째 감싸진 경우만.
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
  echo "점검 분류    : WEB (Apache)    [전체 분류: WAS / DB / WEB / INFRA]"
  echo "점검 대상    : ${APACHE_PREFIX}"
  echo "점검 시각    : ${TS}"
  echo "점검 방식    : 읽기 전용(설정 변경 없음)"
  echo "점검 파일    : apache2.conf, ports.conf, conf-enabled/*, sites-enabled/*, mods-enabled/*"
  echo "설정 파일    : ${CONF_FILE}"
  echo "================================================================"
}

# 비대상(N/A) 공통
na() { record "$1" "$2" "$3" "$R_NA" "-" "(Apache 점검 대상 아님 / 대상: $4)" "Apache 비대상 — 해당 WAS/서버 진단에서 점검"; }

#############################################################################
# 점검 함수
#############################################################################
diag_web01() { na "WEB-01" "상" "Default 관리자 계정명 변경" "Tomcat·JEUS"; }
diag_web02() { na "WEB-02" "상" "취약한 비밀번호 사용 제한" "Tomcat·IIS·JEUS"; }
diag_web03() { na "WEB-03" "상" "비밀번호 파일 권한 관리" "Tomcat·IIS·JEUS"; }

diag_web04() {
  local nm="웹 서비스 디렉터리 리스팅 방지 설정"
  # KISA: 모든 <Directory>의 Options에서 Indexes 제거 여부 점검 (디렉터리 리스팅 = Indexes 활성).
  #   증적도 Indexes 지시자 기준으로 표기(FollowSymLinks 등 무관 Options ❌)
  local en raw; en="$(printf '%s' "$ACFG" | grep -iE 'Options[^#]*[+[:space:]]Indexes' | grep -ivE '\-Indexes')"
  raw="$(acfg_ctx 'Options[^#]*Indexes')"; [ -z "$raw" ] && raw="(활성 <Directory>에 Indexes 옵션 없음 — 디렉터리 리스팅 비활성)"
  if [ -n "$en" ]; then record "WEB-04" "상" "$nm" "$R_VULN" "$APACHE_CONF / sites-enabled/*" "$raw" "Indexes 옵션 활성(디렉터리 리스팅 허용)"
  else record "WEB-04" "상" "$nm" "$R_PASS" "$APACHE_CONF / sites-enabled/*" "$raw" "Indexes 옵션 미설정/제거됨"; fi
}

diag_web05() {
  local nm="지정하지 않은 CGI/ISAPI 실행 제한"
  local mod="" sa exec raw
  mod_enabled cgi && mod="cgi"; mod_enabled cgid && mod="${mod} cgid"
  sa="$(printf '%s' "$ACFG" | grep -iE 'ScriptAlias')"
  exec="$(printf '%s' "$ACFG" | grep -iE 'Options[^#]*[+[:space:]]ExecCGI' | grep -ivE '\-ExecCGI')"
  raw="모듈(mods-enabled): ${mod:-없음}"$'\n'"ScriptAlias: ${sa:-없음}"$'\n'"ExecCGI: ${exec:-없음}"
  if [ -z "$mod" ] && [ -z "$sa" ] && [ -z "$exec" ]; then record "WEB-05" "상" "$nm" "$R_PASS" "mods-enabled / ${APACHE_CONF}" "$raw" "CGI 모듈·ScriptAlias·ExecCGI 미사용"
  else record "WEB-05" "상" "$nm" "$R_VULN" "mods-enabled / ${APACHE_CONF}" "$raw" "CGI 사용 — 실행 디렉터리 제한 여부 수동 확인"; fi
}

diag_web06() {
  local nm="웹 서비스 상위 디렉터리 접근 제한 설정"
  # KISA Apache 조치: <Directory>에 AllowOverride AuthConfig 설정 + .htaccess/htpasswd 사용자 인증 구성.
  #   양호 = AllowOverride AuthConfig(또는 All) + 실제 인증 구성(AuthUserFile 경로의 htpasswd 존재 또는 AuthType/Require).
  local ovr_auth aufile htexists authcfg raw
  ovr_auth="$(printf '%s' "$ACFG" | grep -iE 'AllowOverride[^#]*(AuthConfig|All)')"
  # AuthUserFile 경로 추출 → htpasswd 파일 실제 존재 확인
  aufile="$(printf '%s' "$ACFG" | grep -ioE 'AuthUserFile[[:space:]]+[^[:space:]]+' | awk '{print $2}' | head -1)"
  htexists=""; [ -n "$aufile" ] && [ -e "$aufile" ] && htexists="yes"
  if [ -z "$htexists" ]; then
    local f; f="$(find "$DOCROOT" "$APACHE_PREFIX" -maxdepth 4 -name '.htpasswd' 2>/dev/null | head -1)"
    [ -n "$f" ] && { htexists="yes"; aufile="$f"; }
  fi
  authcfg="$(printf '%s' "$ACFG" | grep -iE 'AuthType|Require[[:space:]]+valid-user')"
  raw="$(acfg_ctx 'AllowOverride')"$'\n'"AuthUserFile/.htpasswd: ${aufile:-없음} (존재:${htexists:-아니오})"$'\n'"인증지시자(AuthType/Require): ${authcfg:-없음}"
  if [ -n "$ovr_auth" ] && { [ -n "$htexists" ] || [ -n "$authcfg" ]; }; then
    record "WEB-06" "상" "$nm" "$R_PASS" "$APACHE_CONF / sites-enabled/*" "$raw" "AllowOverride AuthConfig + htpasswd/.htaccess 인증 구성(상위 디렉터리 접근에 사용자 인증 적용)"
  elif [ -n "$ovr_auth" ]; then
    record "WEB-06" "상" "$nm" "$R_VULN" "$APACHE_CONF / sites-enabled/*" "$raw" "AllowOverride AuthConfig는 설정됐으나 htpasswd/.htaccess 인증 미구성 — 인증 파일(htpasswd/.htaccess) 생성 필요"
  else
    record "WEB-06" "상" "$nm" "$R_VULN" "$APACHE_CONF / sites-enabled/*" "$raw" "AllowOverride에 AuthConfig 미설정(.htaccess 인증 비허용) — 상위 디렉터리 접근 인증 제한 미흡"
  fi
}

diag_web07() {
  local nm="웹 서비스 경로 내 불필요한 파일 제거" found="" raw="" d
  # Apache 2.4(Debian/Ubuntu)는 htdocs를 기본 제공하지 않고 DocumentRoot=/var/www/html 사용.
  #   기본 제공 불필요물 = ① 배포본 기본 안내 페이지, ② apache2-doc 매뉴얼(디렉터리 또는 /manual Alias).
  # ① 데비안/우분투 기본 안내 페이지
  if [ -r "${DOCROOT}/index.html" ] && grep -qiE 'Apache2 (Ubuntu|Debian) Default Page' "${DOCROOT}/index.html" 2>/dev/null; then
    found="$found 기본index.html"; raw="${raw}${DOCROOT}/index.html (배포본 기본 안내 페이지)"$'\n'; fi
  # ② apache2-doc 매뉴얼 디렉터리
  for d in /usr/share/doc/apache2-doc/manual "${DOCROOT}/manual"; do
    [ -e "$d" ] && { found="$found ${d}"; raw="${raw}${d} (apache2-doc 매뉴얼)"$'\n'; }
  done
  # ③ /manual Alias (apache2-doc.conf 활성 시)
  local manalias; manalias="$(printf '%s' "$ACFG" | grep -iE 'Alias[^#]*/manual|apache2-doc')"
  [ -n "$manalias" ] && { found="$found /manual(Alias)"; raw="${raw}${manalias}"$'\n'; }
  if [ -n "$found" ]; then record "WEB-07" "중" "$nm" "$R_VULN" "$DOCROOT / /usr/share/doc/apache2-doc" "$raw" "불필요 기본 파일/디렉터리 존재:${found}"
  else record "WEB-07" "중" "$nm" "$R_PASS" "$DOCROOT" "(배포본 기본 안내 페이지·apache2-doc 매뉴얼 없음 — Apache 2.4는 htdocs 미사용)" "기본 매뉴얼/샘플 없음"; fi
}

diag_web08() {
  local nm="웹 서비스 파일 업로드 및 다운로드 용량 제한"
  local lrb; lrb="$(printf '%s' "$ACFG" | grep -iE 'LimitRequestBody[[:space:]]+[0-9]+')"
  if [ -n "$lrb" ]; then record "WEB-08" "하" "$nm" "$R_PASS" "$APACHE_CONF / sites-enabled/*" "$lrb" "LimitRequestBody 설정 존재"
  else record "WEB-08" "하" "$nm" "$R_VULN" "$APACHE_CONF / sites-enabled/*" "(LimitRequestBody 미설정)" "업로드 용량 제한(LimitRequestBody) 미설정"; fi
}

diag_web09() {
  local nm="웹 서비스 프로세스 권한 제한"
  local runenv workers nonroot="" u
  runenv="$(grep -iE 'APACHE_RUN_USER' "$ENVVARS" 2>/dev/null | grep -vE '^[[:space:]]*#' | sed -E 's/.*=//' | tr -d ' "' | head -1)"
  workers="$(ps -eo user,comm 2>/dev/null | awk '$2 ~ /^(apache2|httpd)$/{print $1}' | sort -u)"
  for u in $workers; do [ "$u" != "root" ] && nonroot="$u"; done
  local raw="envvars APACHE_RUN_USER=${runenv:-?}"$'\n'"실행중 계정=[$(printf '%s' "$workers" | tr '\n' ' ')]"
  local effuser="${nonroot:-$runenv}"
  if [ -z "$effuser" ]; then record "WEB-09" "상" "$nm" "$R_NA" "envvars / process" "$raw" "실행 계정 확인 불가 — 수동 확인"; return; fi
  local grps; grps="$(id -nG "$effuser" 2>/dev/null)"; [ -n "$grps" ] && raw="${raw}"$'\n'"groups(${effuser})=[${grps}]"
  local isadmin="" a g pg
  for a in $ADMIN_RUN_USERS; do [ "$effuser" = "$a" ] && isadmin="root/관리자계정"; done
  if [ -z "$isadmin" ] && [ -n "$grps" ]; then for g in $grps; do for pg in $PRIVILEGED_GROUPS; do [ "$g" = "$pg" ] && isadmin="권한그룹:${g}"; done; done; fi
  if [ -n "$isadmin" ]; then record "WEB-09" "상" "$nm" "$R_VULN" "envvars / process" "$raw" "워커가 관리자 권한 계정(${effuser}, ${isadmin})으로 구동 — master는 root 정상이나 워커는 비관리자여야 함"
  else record "WEB-09" "상" "$nm" "$R_PASS" "envvars / process" "$raw" "워커가 비관리자 전용 계정(${effuser})으로 구동 (master root는 포트바인딩용 정상)"; fi
}

diag_web10() {
  local nm="불필요한 프록시 설정 제한"
  local fwd rev; fwd="$(printf '%s' "$ACFG" | grep -iE 'ProxyRequests[[:space:]]+On')"
  rev="$(printf '%s' "$ACFG" | grep -iE 'ProxyPass|ProxyRequests' | head -4)"
  if [ -n "$fwd" ]; then record "WEB-10" "상" "$nm" "$R_VULN" "sites-enabled/* / ${APACHE_CONF}" "$fwd" "ProxyRequests On(정방향 프록시 활성) — open proxy 위험"
  else record "WEB-10" "상" "$nm" "$R_PASS" "sites-enabled/* / ${APACHE_CONF}" "${rev:-(Proxy 설정 없음)}" "ProxyRequests On 미설정(정방향 프록시 비활성; 리버스 프록시는 정상)"; fi
}

diag_web11() {
  local nm="웹 서비스 경로 설정"
  # 활성화된 서비스/설정 파일(sites-enabled, conf-enabled, apache2.conf …)에서만 DocumentRoot 수집
  local drlines; drlines="$(printf '%s' "$ACFG" | grep -iE 'DocumentRoot[[:space:]]+' | head -10)"

  # 활성 vhost에 DocumentRoot가 없으면 로컬 문서 서빙이 없는 리버스 프록시 구성
  if [ -z "$drlines" ]; then
    record "WEB-11" "중" "$nm" "$R_PASS" "sites-enabled/* / ${APACHE_CONF}" \
      "(활성 vhost에 DocumentRoot 미설정 — 리버스 프록시 구성)" \
      "활성 서비스 파일에 DocumentRoot 없음(로컬 문서 서빙 없음)"
    return
  fi

  # DocumentRoot 값(경로)만 추출: 'DocumentRoot ' 이후 ~ 공백/출처태그(\t‹..›) 전까지, 따옴표 제거
  local paths; paths="$(printf '%s' "$drlines" | sed -E 's/.*[Dd]ocument[Rr]oot[[:space:]]+//; s/[[:space:]].*//; s/^"(.*)"$/\1/')"

  # 기타 업무/시스템 영역과 공유되는(전용 분리되지 않은) 위험 경로
  local shared="" p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in
      /|/usr|/usr/share|/etc|/etc/*|/var|/var/lib|/var/lib/*|/home|/home/*|/root|/root/*|/opt|/srv|/tmp|/boot|/bin|/sbin|/lib|/lib/*|/mnt|/media|/dev|/proc|/sys)
        shared="${shared}${shared:+, }${p}" ;;
    esac
  done <<EOF
$paths
EOF

  if [ -n "$shared" ]; then
    record "WEB-11" "중" "$nm" "$R_VULN" "sites-enabled/* / ${APACHE_CONF}" "$drlines" \
      "DocumentRoot가 기타 업무/시스템 영역과 공유되는 경로(${shared}) 참조 — 웹 전용 경로로 분리 필요"
  else
    record "WEB-11" "중" "$nm" "$R_PASS" "sites-enabled/* / ${APACHE_CONF}" "$drlines" \
      "DocumentRoot(${paths//$'\n'/, })가 웹 전용 경로로 분리됨(시스템/타 업무 영역과 미공유)"
  fi
}

diag_web12() {
  local nm="웹 서비스 링크 사용 금지"
  local en raw; en="$(printf '%s' "$ACFG" | grep -iE 'Options[^#]*[+[:space:]]FollowSymLinks' | grep -ivE '\-FollowSymLinks')"
  raw="$(acfg_ctx 'Options[^#]*(Follow|Symlinks)')"; [ -z "$raw" ] && raw="(FollowSymLinks 관련 Options 없음)"
  if [ -n "$en" ]; then record "WEB-12" "중" "$nm" "$R_VULN" "$APACHE_CONF / sites-enabled/*" "$raw" "FollowSymLinks 활성(심볼릭 링크 허용)"
  else record "WEB-12" "중" "$nm" "$R_PASS" "$APACHE_CONF / sites-enabled/*" "$raw" "FollowSymLinks 미설정/제거됨(-FollowSymLinks)"; fi
}

diag_web14() {
  local nm="웹 서비스 경로 내 파일의 접근 통제" bad="" raw="" ff p
  # 설정 파일·활성 vhost: 권한이 CONF_FILE_MAX_PERM(750)의 칸별 부분집합이어야 양호 (KISA 조치: chmod 750 → other 접근 0)
  for ff in "$APACHE_CONF" "$PORTS_CONF" "$SECURITY_CONF" "$ENVVARS" "$SITES_DIR"/*; do [ -e "$ff" ] || continue
    raw="${raw}$(stat_line "$ff")"$'\n'; p="$(perm_of "$ff")"
    perm_subset "$p" "$CONF_FILE_MAX_PERM" || bad="$bad $(basename "$ff")(권한과다:${p}>${CONF_FILE_MAX_PERM})"
  done
  # SSL 개인키: SSL_KEY_MAX_PERM(600)의 칸별 부분집합
  for ff in $SSL_KEY_FILES; do [ -e "$ff" ] || continue
    raw="${raw}$(stat_line "$ff")"$'\n'; p="$(perm_of "$ff")"
    perm_subset "$p" "$SSL_KEY_MAX_PERM" || bad="$bad $(basename "$ff")(키권한과다:${p}>${SSL_KEY_MAX_PERM})"
  done
  if [ -n "$bad" ]; then record "WEB-14" "상" "$nm" "$R_VULN" "conf/sites/SSL키" "$raw" "접근권한 과다(기준 부분집합 위반):${bad}"
  else record "WEB-14" "상" "$nm" "$R_PASS" "conf/sites/SSL키" "$raw" "설정·vhost 권한이 ${CONF_FILE_MAX_PERM} 부분집합 + SSL 키가 ${SSL_KEY_MAX_PERM} 부분집합(불필요한 other 접근 없음)"; fi
}

diag_web16() {
  local nm="웹 서비스 헤더 정보 노출 제한"
  local tok sig raw; tok="$(printf '%s' "$ACFG" | grep -ioE 'ServerTokens[[:space:]]+[A-Za-z]+' | head -1)"
  sig="$(printf '%s' "$ACFG" | grep -ioE 'ServerSignature[[:space:]]+[A-Za-z]+' | head -1)"
  raw="${tok:-(ServerTokens 미설정 — 기본 OS/Full)}"$'\n'"${sig:-(ServerSignature 미설정)}"
  local tokok=""; printf '%s' "$tok" | grep -qiE 'Prod' && tokok="yes"
  local sigok=""; printf '%s' "$sig" | grep -qiE 'Off' && sigok="yes"
  if [ -n "$tokok" ] && [ -n "$sigok" ]; then record "WEB-16" "중" "$nm" "$R_PASS" "$SECURITY_CONF" "$raw" "ServerTokens Prod + ServerSignature Off"
  else record "WEB-16" "중" "$nm" "$R_VULN" "$SECURITY_CONF" "$raw" "ServerTokens Prod/ServerSignature Off 미적용(버전·OS 노출 가능)"; fi
}

diag_web17() {
  local nm="웹 서비스 가상 디렉터리 삭제"
  local al; al="$(printf '%s' "$ACFG" | grep -iE '^[[:space:]]*Alias(Match)?[[:space:]]')"
  if [ -z "$al" ]; then record "WEB-17" "중" "$nm" "$R_PASS" "sites-enabled/* / ${APACHE_CONF}" "(Alias 지시자 없음)" "불필요한 가상 디렉터리(Alias) 없음"
  else record "WEB-17" "중" "$nm" "$R_VULN" "sites-enabled/* / ${APACHE_CONF}" "$al" "Alias 설정 존재 — 필요 여부 수동 확인"; fi
}

diag_web18() {
  local nm="웹 서비스 WebDAV 비활성화"
  local mod="" dav; mod_enabled dav && mod="dav"; mod_enabled dav_fs && mod="${mod} dav_fs"
  dav="$(printf '%s' "$ACFG" | grep -iE 'Dav[[:space:]]+On')"
  local raw="모듈(mods-enabled): ${mod:-없음}"$'\n'"Dav On: ${dav:-없음}"
  if [ -z "$mod" ] && [ -z "$dav" ]; then record "WEB-18" "상" "$nm" "$R_PASS" "mods-enabled / ${APACHE_CONF}" "$raw" "mod_dav 미사용 + Dav On 없음(WebDAV 비활성)"
  else record "WEB-18" "상" "$nm" "$R_VULN" "mods-enabled / ${APACHE_CONF}" "$raw" "WebDAV 활성화됨"; fi
}

diag_web19() {
  local nm="웹 서비스 SSI(Server Side Includes) 사용 제한"
  local mod="" inc; mod_enabled include && mod="include"
  inc="$(printf '%s' "$ACFG" | grep -iE 'Options[^#]*[+[:space:]]Includes' | grep -ivE '\-Includes|IncludesNOEXEC')"
  local raw="모듈(mods-enabled/include): ${mod:-없음}"$'\n'"Options Includes: ${inc:-없음}"
  if [ -z "$mod" ] && [ -z "$inc" ]; then record "WEB-19" "중" "$nm" "$R_PASS" "mods-enabled / ${APACHE_CONF}" "$raw" "mod_include 미사용 + Options Includes 없음(SSI 비활성)"
  else record "WEB-19" "중" "$nm" "$R_VULN" "mods-enabled / ${APACHE_CONF}" "$raw" "SSI(Includes) 활성화됨"; fi
}

diag_web20() {
  local nm="SSL/TLS 활성화"
  local mod="" eng vhost proto raw
  mod_enabled ssl && mod="ssl"
  eng="$(printf '%s' "$ACFG" | grep -iE 'SSLEngine[[:space:]]+on' | head -1)"
  vhost="$(printf '%s' "$ACFG" | grep -iE '<VirtualHost[^>]*:443' | head -1)"
  proto="$(printf '%s' "$ACFG" | grep -iE 'SSLProtocol' | head -1)"
  raw="모듈(ssl): ${mod:-없음}"$'\n'"${eng:-SSLEngine 미설정}"$'\n'"${vhost:-443 vhost 없음}"$'\n'"${proto:-SSLProtocol 미설정}"
  if [ -n "$mod" ] && { [ -n "$eng" ] || [ -n "$vhost" ]; }; then record "WEB-20" "상" "$nm" "$R_PASS" "mods-enabled / sites-enabled/*" "$raw" "SSL/TLS 활성(SSLEngine on + 443 vhost)"
  else record "WEB-20" "상" "$nm" "$R_VULN" "mods-enabled / sites-enabled/*" "$raw" "SSL/TLS 비활성(mod_ssl/SSLEngine/443 vhost 미흡)"; fi
}

diag_web21() {
  local nm="HTTP 리디렉션"
  local redir; redir="$(printf '%s' "$ACFG" | grep -iE 'Redirect[^#]*https|RewriteRule[^#]*https')"
  if [ -n "$redir" ]; then record "WEB-21" "중" "$nm" "$R_PASS" "sites-enabled/*" "$redir" "HTTP→HTTPS Redirection 활성"
  else record "WEB-21" "중" "$nm" "$R_VULN" "sites-enabled/*" "(https 리디렉션 설정 없음)" "HTTP→HTTPS Redirection 미설정"; fi
}

diag_web22() {
  local nm="에러 페이지 관리"
  local ed; ed="$(printf '%s' "$ACFG" | grep -iE 'ErrorDocument[[:space:]]+[0-9]+')"
  if [ -z "$ed" ]; then
    record "WEB-22" "하" "$nm" "$R_VULN" "$SECURITY_CONF / sites-enabled/*" "(ErrorDocument 미설정)" "에러 페이지 미지정(기본 페이지 → 정보 노출 우려)"
    return
  fi

  # ErrorDocument가 가리키는 대상이 실제 서빙 가능한지(로컬 파일 존재) 확인 — 디렉티브만 있고 파일이 없으면 기본 페이지로 폴백됨
  local missing="" line code tgt fsa
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    code="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ee]rror[Dd]ocument[[:space:]]+([0-9]+).*/\1/')"
    # 'ErrorDocument <code> <target>' 의 target 추출 (출처태그 \t‹..› 제거)
    tgt="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ee]rror[Dd]ocument[[:space:]]+[0-9]+[[:space:]]+//; s/\t.*//')"
    case "$tgt" in
      \"*|\'*|http://*|https://*) continue ;;   # 인라인 메시지/외부 URL — 로컬 파일 점검 대상 아님
      /*) : ;;
      *) continue ;;
    esac
    # Apache는 '/'로 시작하는 인자를 DocumentRoot 기준 URL로 해석 → 실제 파일 = DOCROOT+경로.
    # (절대 파일경로를 그대로 적은 잘못된 표기까지 잡기 위해 경로 자체도 보조 확인)
    fsa="${DOCROOT}${tgt}"
    if [ ! -f "$fsa" ] && [ ! -f "$tgt" ]; then
      missing="${missing}${missing:+; }${code}→${tgt}(검사:${fsa})"
    fi
  done <<EOF
$ed
EOF

  if [ -z "$missing" ]; then
    record "WEB-22" "하" "$nm" "$R_PASS" "$SECURITY_CONF / sites-enabled/*" "$ed" "ErrorDocument 지정 + 대상 파일 존재 확인"
  else
    record "WEB-22" "하" "$nm" "$R_VULN" "$SECURITY_CONF / sites-enabled/*" "$ed"$'\n'"대상 파일 없음: ${missing}" "ErrorDocument 지정됐으나 대상 파일 미존재 → 기본 페이지 폴백(정보 노출). 파일 배포 또는 경로 표기 교정 필요"
  fi
}

diag_web13() { na "WEB-13" "상" "웹 서비스 설정 파일 노출 제한" "Tomcat·IIS·JEUS"; }
diag_web15() { na "WEB-15" "상" "웹 서비스의 불필요한 스크립트 매핑 제거" "Tomcat·IIS·JEUS"; }
diag_web23() { na "WEB-23" "중" "LDAP 알고리즘 적절하게 구성" "Tomcat"; }

diag_web24() {
  local nm="별도의 업로드 경로 사용 및 권한 설정"
  # Apache는 리버스 프록시 — 업로드는 WAS가 처리. docroot 내 업로드 경로 노출/쓰기 여부만 점검.
  local updir="${DOCROOT}/uploads" raw perm denied
  if [ -d "$updir" ]; then
    perm="$(perm_of "$updir")"; denied="$(printf '%s' "$ACFG" | awk -v p="$updir" 'index($0,p){f=1} f{print} /<\/Directory>/{if(f)exit}' | grep -iE 'Require[[:space:]]+all[[:space:]]+denied|Deny[[:space:]]+from[[:space:]]+all')"
    raw="업로드 디렉터리=${updir}  권한=${perm}"$'\n'"접근설정: ${denied:-제한 명시 없음}"
    if [ -n "$denied" ] || ! others_has_write "$perm"; then record "WEB-24" "중" "$nm" "$R_PASS" "$DOCROOT / sites-enabled/*" "$raw" "업로드 경로 접근 제한(Require all denied 또는 other 쓰기 없음)"
    else record "WEB-24" "중" "$nm" "$R_VULN" "$DOCROOT / sites-enabled/*" "$raw" "업로드 경로에 일반 사용자 쓰기 권한/접근 허용"; fi
  else
    record "WEB-24" "중" "$nm" "$R_PASS" "$DOCROOT" "(docroot 내 업로드 경로 없음 — 업로드는 WAS가 처리하는 리버스 프록시 구성)" "로컬 업로드 경로 없음(리버스 프록시 — 업로드는 WAS 진단에서 점검)"
  fi
}

diag_web25() {
  local nm="주기적 보안 패치 및 벤더 권고사항 적용" ver=""
  ver="$( (apache2 -v 2>/dev/null || apache2ctl -v 2>/dev/null || httpd -v 2>/dev/null) | grep -ioE 'Apache/[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ -z "$ver" ]; then record "WEB-25" "상" "$nm" "$R_NA" "apache2 -v" "(버전 확인 불가)" "Apache 버전 확인 불가 — 수동 확인"; return; fi
  local lowest; lowest="$(printf '%s\n%s\n' "$ver" "$MIN_APACHE_VERSION" | sort -V | head -1)"
  local raw="설치 버전=${ver}"$'\n'"기준 버전=${MIN_APACHE_VERSION} (※ 점검 시점 최신/EOL 여부는 수동 확인)"
  if [ "$lowest" = "$MIN_APACHE_VERSION" ]; then record "WEB-25" "상" "$nm" "$R_PASS" "apache2 -v" "$raw" "설치 버전 ${ver} >= 기준 ${MIN_APACHE_VERSION}"
  else record "WEB-25" "상" "$nm" "$R_VULN" "apache2 -v" "$raw" "설치 버전 ${ver} < 기준 ${MIN_APACHE_VERSION} (패치 필요)"; fi
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
show_preinfo; echo
# ── 권한 사전 점검: 관리자(root) 권한이 아니면 예외(중단) ──
#    SSL 개인키(600)·로그(750 root:adm) 등 권한 제한 자원을 읽어야 정확하므로 root 필요.
#    (ubuntu 계정은 adm 그룹이라 로그는 읽혀도 SSL키는 못 읽어 부분 오탐 → 아예 중단)
if [ "$(id -u)" -ne 0 ]; then
  {
    echo ""
    echo "================================================================"
    echo "[진단 중단] 관리자 권한(root/sudo)이 아닙니다."
    echo "  현재 계정 : $(id -un) (uid=$(id -u))"
    echo "  사유      : 권한 제한된 자원(예: SSL 개인키, 로그 디렉터리)을 읽어야 정확히 진단됩니다."
    echo "  조치      : sudo 로 재실행하세요.  예) sudo ./web_diag.sh"
    echo "================================================================"
  } >&2
  exit 2
fi
[ "${#ACFG_FILES[@]}" -gt 0 ] || echo "[경고] 읽을 수 있는 Apache 설정 파일이 없음 — sudo 로 실행 권장" >&2

diag_web01; diag_web02; diag_web03; diag_web04; diag_web05; diag_web06
diag_web07; diag_web08; diag_web09; diag_web10; diag_web11; diag_web12
diag_web13; diag_web14; diag_web15; diag_web16; diag_web17; diag_web18
diag_web19; diag_web20; diag_web21; diag_web22; diag_web23; diag_web24
diag_web25; diag_web26

TOTAL=$((CNT_PASS+CNT_VULN+CNT_NA))

# ── 보고서 TXT ─────────────────────────────────────────────
{
  show_preinfo; echo
  printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
  echo "================================================================"
  i=0
  while [ "$i" -lt "${#F_CODE[@]}" ]; do
    emit_screen "${F_CODE[$i]}" "${F_SEV[$i]}" "${F_NAME[$i]}" "${F_CAT[$i]}" "${F_STD[$i]}" "${F_RESULT[$i]}" "${F_RAW[$i]}" "${F_FILE[$i]}"
    i=$((i+1))
  done
  echo "※ '수동 확인' 표기 항목과 취약 항목은 담당자의 실제 설정 검토로 최종 확정 필요."
} > "$HISTORY"

# ── 로우데이터 CSV ─────────────────────────────────────────
csv_field() {
  local v; v="$(printf '%s' "$1" | sed 's/"/""/g' | awk '{a[NR]=$0} END{for(i=1;i<=NR;i++) printf "%s%s",(i>1?" | ":""),a[i]}')"
  printf '"%s"' "$v"
}
{
  printf '\xEF\xBB\xBF'   # UTF-8 BOM — Excel 한글 깨짐 방지
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_field 항목코드)" "$(csv_field 분류)" "$(csv_field 항목)" "$(csv_field 판단기준)" \
    "$(csv_field 결과)" "$(csv_field 점검내용)" "$(csv_field 조치방법)" "$(csv_field 진단대상)" \
    "$(csv_field 진단대상IP)" "$(csv_field 중요도)" "$(csv_field 점검파일)"
  i=0
  while [ "$i" -lt "${#F_CODE[@]}" ]; do
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_field "${F_CODE[$i]}")" "$(csv_field "${F_CAT[$i]}")" "$(csv_field "${F_NAME[$i]}")" \
      "$(csv_field "${F_STD[$i]}")" "$(csv_field "${F_RESULT[$i]}")" "$(csv_field "${F_RAW[$i]}")" \
      "$(csv_field "${REMED[${F_CODE[$i]}]:-}")" "$(csv_field "$TARGET_SYS")" "$(csv_field "$IP_ADDR")" \
      "$(csv_field "${F_SEV[$i]}")" "$(csv_field "${F_FILE[$i]}")"
    i=$((i+1))
  done
} > "$RAW_CSV"

echo "================================================================"
printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$CNT_PASS" "$CNT_VULN" "$CNT_NA"
echo " 히스토리(TXT)   : $HISTORY"
echo " 로우데이터(CSV) : $RAW_CSV"
echo "진단 스크립트 종료"
