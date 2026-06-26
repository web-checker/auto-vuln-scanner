#!/usr/bin/env bash
# =============================================================
# cloud_diag.sh - SK쉴더스 2024 클라우드 보안가이드(AWS) 자동 진단
#   기준 PDF : 클라우드 보안 가이드_AWS.pdf (SK Shieldus, 2024) — ※ KISA 아님
#   범위     : 4개 영역 41개 항목(계정13·권한3·리소스10·운영15). EKS 미대상은 N/A.
#   동작     : 읽기전용(describe/list/get/lookup)만 사용. 설정 변경 없음.
#   출력     : 로우데이터 CSV(10컬럼) + 보고서 TXT (DIAG_STYLE / OUTPUT_REFORMAT 준수)
#   판단기준 : STD_PASS/STD_VULN = 위 PDF '양호기준/취약기준' 원문 그대로
#   실행     : bash cloud_diag.sh [-c cloud_diag.conf] [-p 프로파일] [-r 리전]
#                                 [-k 1,3] [-o ./result_cloud]
# =============================================================
set -uo pipefail
export TZ='Asia/Seoul'   # 점검시각/파일명 KST 고정(DIAG_STYLE §8)

# ===== 0. conf 로드 =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$SCRIPT_DIR/cloud_diag.conf"
CATS="1,2,3,4"; OUTDIR=""
CLI_PROFILE=""; CLI_REGION=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--conf)     CONF="$2"; shift 2 ;;
    -p|--profile)  CLI_PROFILE="$2"; shift 2 ;;
    -r|--region)   CLI_REGION="$2"; shift 2 ;;
    -k|--category) CATS="$2"; shift 2 ;;
    -o|--output)   OUTDIR="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
사용법: $0 [옵션]
  -c, --conf <file>     환경설정 파일 (기본: 스크립트 옆 cloud_diag.conf)
  -p, --profile <name>  AWS 프로파일 (conf보다 우선)
  -r, --region  <name>  리전 (conf보다 우선)
  -k, --category <n>    영역만 점검 1=계정 2=권한 3=리소스 4=운영 (콤마)
  -o, --output  <dir>   산출물(CSV/TXT) 저장 디렉터리
예) $0 -o ./result_cloud
    $0 -p audit -r ap-northeast-2 -k 1,3 -o ./result_cloud
EOF
      exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done
[ -f "$CONF" ] || { echo "설정 파일 없음: $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

# CLI 인자 > conf > CLI 기본설정 순으로 프로파일/리전 결정
[ -n "$CLI_PROFILE" ] && AWS_PROFILE_DEFAULT="$CLI_PROFILE"
[ -n "$CLI_REGION" ]  && REGION_DEFAULT="$CLI_REGION"
[ -n "${AWS_PROFILE_DEFAULT:-}" ] && export AWS_PROFILE="$AWS_PROFILE_DEFAULT"
[ -n "${REGION_DEFAULT:-}" ] && { export AWS_REGION="$REGION_DEFAULT"; export AWS_DEFAULT_REGION="$REGION_DEFAULT"; }

# ===== 2. 결과 누적 배열 (OUTPUT_REFORMAT §2 컬럼 구성) =====
declare -a F_CODE F_CAT F_NAME F_STD F_FIX F_RESULT F_RAW F_SEV F_FILE
PASS_CNT=0; FAIL_CNT=0; NA_CNT=0

# ===== 3. 분류/중요도/판단기준 원문 (PDF 그대로) =====
# 분류는 코드 접두로 결정
cat_of() {
  case "$1" in
    1.*) echo "계정 관리" ;;
    2.*) echo "권한 관리" ;;
    3.*) echo "가상 리소스 관리" ;;
    4.*) echo "운영 관리" ;;
    *)   echo "" ;;
  esac
}
declare -A SEV
SEV[1.1]=상 SEV[1.2]=상 SEV[1.3]=중 SEV[1.4]=중 SEV[1.5]=상 SEV[1.6]=상 SEV[1.7]=중
SEV[1.8]=상 SEV[1.9]=중 SEV[1.10]=중 SEV[1.11]=상 SEV[1.12]=중 SEV[1.13]=상
SEV[2.1]=상 SEV[2.2]=상 SEV[2.3]=상
SEV[3.1]=상 SEV[3.2]=상 SEV[3.3]=중 SEV[3.4]=중 SEV[3.5]=하 SEV[3.6]=중 SEV[3.7]=중
SEV[3.8]=중 SEV[3.9]=상 SEV[3.10]=중
SEV[4.1]=중 SEV[4.2]=중 SEV[4.3]=중 SEV[4.4]=중 SEV[4.5]=중 SEV[4.6]=중 SEV[4.7]=상
SEV[4.8]=중 SEV[4.9]=중 SEV[4.10]=중 SEV[4.11]=중 SEV[4.12]=중 SEV[4.13]=중
SEV[4.14]=중 SEV[4.15]=중

declare -A STD_PASS STD_VULN
STD_PASS[1.1]='관리자 권한을 보유한 다수 계정이 존재하지 않고 불필요한 계정이 존재하지 않을 경우'
STD_VULN[1.1]='관리자 권한을 보유한 다수 계정이 존재하거나 불필요한 계정이 존재할 경우'
STD_PASS[1.2]='IAM 사용자 계정을 1인 1계정으로 사용하고 있는 경우'
STD_VULN[1.2]='IAM 사용자 계정을 1인 1계정으로 사용하고 있지 않은 경우'
STD_PASS[1.3]='사용자 정보(이름, 이메일, 부서 등)가 IAM 사용자 태그에 설정되어 있을 경우'
STD_VULN[1.3]='사용자 정보(이름, 이메일, 부서 등)가 IAM 사용자 태그에 설정되어 있지 않을 경우'
STD_PASS[1.4]='IAM 그룹에 포함된 사용자 계정 중 불필요한 계정이 존재하지 않을 경우'
STD_VULN[1.4]='IAM 그룹에 포함된 사용자 계정 중 불필요한 계정이 존재할 경우'
STD_PASS[1.5]='Key Pair(PEM)를 통해 EC2 인스턴스에 접근할 경우'
STD_VULN[1.5]='Key Pair(PEM)가 아닌 일반 패스워드로 EC2 인스턴스에 접근할 경우'
STD_PASS[1.6]='Key Pair(PEM) File의 보관 위치가 쉽게 유추할 수 없는 공간에 보관되어 있을 경우'
STD_VULN[1.6]='Key Pair(PEM) File의 보관 위치가 다수 접근이 가능한 공용 공간(퍼블릭 S3, EC2 "Admin Console(/)" 디렉터리 등)에 보관되어 있을 경우'
STD_PASS[1.7]='Admin Console 계정을 서비스 용도로 사용하지 않는 경우'
STD_VULN[1.7]='Admin Console 계정을 서비스 용도로 사용하는 경우'
STD_PASS[1.8]='AWS Admin Console 계정에 Access Key가 존재하지 않고 IAM 사용자 계정에 대한 Access Key 사용 주기가 60일 이내일 경우'
STD_VULN[1.8]='AWS Admin Console 계정에 Access Key가 존재하거나 IAM 사용자 계정에 대한 Access Key 사용 주기가 60일 초과일 경우'
STD_PASS[1.9]='AWS 계정 및 IAM 사용자 계정 로그인 시 MFA가 활성화 되어 있을 경우'
STD_VULN[1.9]='AWS 계정 및 IAM 사용자 계정 로그인 시 MFA 가 비활성화 되어 있을 경우'
STD_PASS[1.10]='Admin Console 및 IAM 계정의 패스워드 복잡성 기준 준수 및 암호 만료/재사용 제한을 설정하고 있을 경우'
STD_VULN[1.10]='Admin Console 및 IAM 계정의 패스워드 복잡성 기준 준수 및 암호 만료/재사용 제한을 설정하고 있지 않을 경우'
STD_PASS[1.11]='EKS 리소스 접근을 위한 ConfigMap(RBAC) 내 인가된 사용자만 설정되어 있는 경우'
STD_VULN[1.11]='EKS 리소스 접근을 위한 ConfigMap(RBAC) 내 인가된 사용자만 설정되어 있지 않은 경우'
STD_PASS[1.12]='네임스페이스 또는 서비스 어카운트 설정 내 automountServiceAccountToken 값이 False 로 설정된 경우'
STD_VULN[1.12]='네임스페이스 또는 서비스 어카운트 설정 내 automountServiceAccountToken 값이 True 로 설정된 경우'
STD_PASS[1.13]='ClusterRole 에 system:anonymous | unauthenticated 그룹이 바인딩 되어있지 않는 경우'
STD_VULN[1.13]='ClusterRole 에 system:anonymous | unauthenticated 그룹이 바인딩 되어 있는 경우'
STD_PASS[2.1]='인스턴스 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있을 경우'
STD_VULN[2.1]='인스턴스 서비스 IAM 사용 권한이 각각 서비스 역할에 맞지 않게 설정되어 있을 경우'
STD_PASS[2.2]='네트워크 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있을 경우'
STD_VULN[2.2]='네트워크 서비스 IAM 사용 권한이 각각 서비스 역할에 맞지 않게 설정되어 있을 경우'
STD_PASS[2.3]='기타 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있을 경우'
STD_VULN[2.3]='기타 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있지 않을 경우'
STD_PASS[3.1]='보안 그룹 내 인/아웃바운드의 포트가 Any로 허용되어 있지 않을 경우'
STD_VULN[3.1]='보안 그룹 내 인/아웃바운드의 포트가 Any로 허용되어 있을 경우'
STD_PASS[3.2]='보안 그룹 인/아웃바운드 규칙 내 불필요한 정책(Source, Destination)이 존재하지 않는 경우'
STD_VULN[3.2]='보안 그룹 인/아웃바운드 규칙 내 불필요한 정책(Source, Destination)이 존재하는 경우'
STD_PASS[3.3]='네트워크 ACL 내 인/아웃바운드에 대한 모든 트래픽이 허용되어 있지 않을 경우'
STD_VULN[3.3]='네트워크 ACL 내 인/아웃바운드에 대한 모든 트래픽이 허용되어 있을 경우'
STD_PASS[3.4]='라우팅 테이블 내 ANY 정책이 설정되어 있지 않고 서비스 타깃 별로 설정되어 있을 경우'
STD_VULN[3.4]='라우팅 테이블 내 ANY 정책이 설정되어 있거나 서비스 타깃 별로 설정되어 있지 않을 경우'
STD_PASS[3.5]='인터넷 게이트웨이에 불필요하게 연결된 NAT 게이트웨이가 존재하지 않을 경우'
STD_VULN[3.5]='인터넷 게이트웨이에 불필요하게 연결된 NAT 게이트웨이가 존재하는 경우'
STD_PASS[3.6]='외부 통신이 필요한 리소스가 NAT 게이트웨이가 연결되어 있을 경우'
STD_VULN[3.6]='목적이 확인되지 않은 리소스가 NAT 게이트웨이에 연결되어 있을 경우'
STD_PASS[3.7]='퍼블릭 액세스 차단이 설정되어 있거나, 퍼블릭 액세스를 허용할 경우 ACL을 버킷 소유자에게만 설정하고 있을 경우'
STD_VULN[3.7]='퍼블릭 액세스 차단이 설정되어 있지 않고, ACL이 모든 사람, 외부계정 소유자로 설정하고 있을 경우'
STD_PASS[3.8]='RDS 서브넷 그룹 내 불필요한 가용영역이 존재하지 않는 경우'
STD_VULN[3.8]='RDS 서브넷 그룹 내 불필요한 가용영역이 존재하는 경우'
STD_PASS[3.9]='PSS Profile Baseline 및 PSA Audit 이상 설정을 적용해 사용하는 경우'
STD_VULN[3.9]='PSS 및 PSA 설정을 적용하여 사용하지 않거나 PSS Profile Privileged 및 PSA warn 설정을 적용해 사용하는 경우'
STD_PASS[3.10]='ELB 제어 정책을 준수하고 있는 경우'
STD_VULN[3.10]='ELB 제어 정책을 준수하고 있지 않는 경우'
STD_PASS[4.1]='EBS 및 볼륨 리소스에 암호화가 활성화되어 있을 경우'
STD_VULN[4.1]='EBS 및 볼륨 리소스에 암호화가 비활성화되어 있을 경우'
STD_PASS[4.2]='RDS 데이터베이스 암호화가 활성화되어 있을 경우'
STD_VULN[4.2]='RDS 데이터베이스 암호화가 비활성화되어 있을 경우'
STD_PASS[4.3]='Amazon S3 키(SSE-S3)로 서버 측 암호화 사용 또는 SSE-KMS로 서버 측 암호화가 설정되어 있을 경우'
STD_VULN[4.3]='Amazon S3 키(SSE-S3)로 서버 측 암호화 사용 또는 SSE-KMS 로 서버 측 암호화가 설정되어 있지 않을 경우'
STD_PASS[4.4]='클라우드 리소스 통신 구간 내 암호화 설정이 되어 있는 경우'
STD_VULN[4.4]='클라우드 리소스 통신 구간 내 암호화 설정이 되어 있지 않는 경우'
STD_PASS[4.5]='CloudTrail 관련 로그 파일에 SSE-KMS 암호화 설정이 되어있을 경우'
STD_VULN[4.5]='CloudTrail 관련 로그 파일에 SSE-KMS 암호화 설정이 되어있지 않을 경우'
STD_PASS[4.6]='로그 그룹 생성 시 "KMS key ARN" 을 설정하여 사용하고 있는 경우'
STD_VULN[4.6]='로그 그룹 생성 시 "KMS key ARN" 을 설정하여 사용하고 있지 않는 경우'
STD_PASS[4.7]='AWS 사용자 계정(Console, IAM)의 로깅이 설정되어 있는 경우'
STD_VULN[4.7]='AWS 사용자 계정(Console, IAM)의 로깅이 설정되어 있지 않은 경우'
STD_PASS[4.8]='CloudWatch 로그 스트림으로 보관하고 있는 경우'
STD_VULN[4.8]='CloudWatch 로그 스트림으로 보관하고 있지 않은 경우'
STD_PASS[4.9]='CloudWatch 로그 스트림으로 보관하고 있는 경우'
STD_VULN[4.9]='CloudWatch 로그 스트림으로 보관하고 있지 않은 경우'
STD_PASS[4.10]='로그를 보관하고 있는 버킷의 "서버 액세스 로깅"이 설정되어 있는 경우'
STD_VULN[4.10]='로그를 보관하고 있는 버킷의 "서버 액세스 로깅"이 설정되어 있지 않은 경우'
STD_PASS[4.11]='VPC 플로우 로그 설정이 존재하는 경우'
STD_VULN[4.11]='VPC 플로우 로그 설정이 존재하지 않을 경우'
STD_PASS[4.12]='AWS 서비스 로그를 기준(최소 1년 이상)에 맞게 보관하고 있는 경우'
STD_VULN[4.12]='AWS 서비스 로그를 기준(최소 1년 이상)에 맞게 보관하고 있지 않은 경우'
STD_PASS[4.13]='클라우드 리소스 백업 정책이 존재하는 경우'
STD_VULN[4.13]='클라우드 리소스 백업 정책이 존재하지 않는 경우'
STD_PASS[4.14]='EKS Cluster 제어 플레인 로깅을 설정하여 유형 별 로그를 기록하고 있는 경우'
STD_VULN[4.14]='EKS Cluster의 유형 별 로그를 기록하고 있지 않는 경우'
STD_PASS[4.15]='암호 암호화가 활성화 되어있는 경우'
STD_VULN[4.15]='암호 암호화가 활성화 되어있지 않는 경우'

# ----- 조치 방법(간단) : 대시보드 표시용. 콘솔(GUI)에서 누구나 이해하도록 평이하게 -----
#   ※ 콘솔에 그 이름으로 보이는 기능(MFA·Access Key·KMS·CloudTrail·퍼블릭 액세스 차단 등)은 유지,
#     코드/매니페스트 식별자(automountServiceAccountToken 등)는 풀어 씀.
declare -A FIX
FIX[1.1]='IAM 관리자 권한 보유 사용자 최소화 및 불필요한 사용자 삭제'
FIX[1.2]='담당자 1인당 IAM 사용자 1개 발급 및 공용 계정 제거'
FIX[1.3]='IAM 사용자별 이름·이메일·부서 등 식별 정보 태그 등록'
FIX[1.4]='IAM 그룹 내 미사용 사용자 식별 및 그룹에서 제외'
FIX[1.5]='EC2 인스턴스 키 페어(Key Pair) 등록을 통한 키 기반 접속 설정'
FIX[1.6]='키 페어(.pem) 파일을 외부 접근이 불가한 비공개 위치에 보관 (퍼블릭 S3 보관 금지)'
FIX[1.7]='루트(최고관리자) 계정 사용 제한 및 권한이 제한된 IAM 사용자 사용, 루트 액세스 키 삭제'
FIX[1.8]='루트 계정 액세스 키 삭제 및 IAM 사용자 액세스 키 60일 이내 주기적 교체'
FIX[1.9]='루트 계정 및 IAM 사용자 로그인 시 MFA(다중 인증) 활성화'
FIX[1.10]='계정 암호 정책에 복잡성·만료(90일)·재사용 제한 설정'
FIX[1.11]='EKS 클러스터 접근 권한 목록 내 인가된 사용자만 유지 및 불필요 사용자 제거'
FIX[1.12]='EKS 서비스 계정의 인증 토큰 자동 연결(자동 마운트) 비활성화 설정'
FIX[1.13]='EKS 익명(미인증) 사용자 접근 권한 제거'
FIX[2.1]='EC2 등 인스턴스 서비스 역할에 최소 권한 부여 및 과도한 권한 회수'
FIX[2.2]='네트워크 서비스 역할에 최소 권한 부여 및 과도한 권한 회수'
FIX[2.3]='기타 서비스 역할에 최소 권한 부여 및 과도한 권한 회수'
FIX[3.1]='보안 그룹 내 전체 포트(0~65535) 허용 규칙 제거'
FIX[3.2]='보안 그룹 내 전체 IP(0.0.0.0/0) 허용 규칙 제거 및 필요한 IP 대역만 허용'
FIX[3.3]='네트워크 ACL 내 전체 트래픽 허용 규칙 제거'
FIX[3.4]='라우팅 테이블 내 불필요한 전체 경로(0.0.0.0/0) 제거 및 목적지별 경로 설정'
FIX[3.5]='미사용(미연결) 인터넷 게이트웨이 삭제'
FIX[3.6]='용도 미확인 NAT 게이트웨이 연결 제거'
FIX[3.7]='S3 버킷 퍼블릭 액세스 차단 설정'
FIX[3.8]='RDS 서브넷 그룹 내 미사용 가용 영역 제거'
FIX[3.9]='EKS 파드 보안 수준 Baseline 이상 적용'
FIX[3.10]='로드밸런서(ELB) 보안 기준 준수 구성'
FIX[4.1]='EBS 볼륨 암호화 활성화'
FIX[4.2]='RDS 데이터베이스 암호화 활성화'
FIX[4.3]='S3 버킷 기본 암호화(서버 측 암호화) 설정'
FIX[4.4]='리소스 간 통신 구간 암호화(HTTPS/TLS) 설정'
FIX[4.5]='CloudTrail 로그 KMS 키 암호화 설정'
FIX[4.6]='CloudWatch 로그 그룹 KMS 암호화 키 지정'
FIX[4.7]='CloudTrail 활성화를 통한 계정·사용자 활동 로깅 설정'
FIX[4.8]='EC2 인스턴스 로그 CloudWatch 수집·보관 설정'
FIX[4.9]='RDS 로그 CloudWatch 내보내기 설정'
FIX[4.10]='S3 버킷 서버 액세스 로깅 설정'
FIX[4.11]='VPC 플로우 로그(트래픽 기록) 활성화'
FIX[4.12]='로그 보관 기간 최소 1년 이상 설정'
FIX[4.13]='AWS Backup 등을 통한 리소스 백업 정책 설정'
FIX[4.14]='EKS 클러스터 제어 플레인 로깅 활성화'
FIX[4.15]='EKS 클러스터 비밀정보(Secret) 암호화 활성화'

# ===== 4. 공통 헬퍼 =====
# CSV 필드: 따옴표 이스케이프 + 멀티라인은 ' | ' 조인 (DIAG_STYLE §7)
csv_field(){ local v; v="$(printf '%s' "$1" | sed 's/"/""/g' \
  | awk '{a[NR]=$0} END{for(i=1;i<=NR;i++) printf "%s%s",(i>1?" | ":""),a[i]}')"; printf '"%s"' "$v"; }

# 화면용 8줄 절단 (OUTPUT_REFORMAT §3)
truncate8(){
  printf '%s' "$1" | awk '
    { ln[NR]=$0 }
    END { n=NR; lim=(n>8?8:n)
      for(i=1;i<=lim;i++) print ln[i]
      if(n>8) printf "... (이하 %d줄 생략 — 상세는 로우데이터 CSV 참조)\n", n-8 }'
}
# emit_screen CODE SEV NAME STD RESULT RAW FILE  (분류/진단대상은 CSV에만)
emit_screen(){
  printf '[%s (%s) %s]\n' "$1" "$2" "$3"
  printf '점검 결과    : %s\n' "$5"
  printf '점검 파일 명 : %s\n' "$7"
  printf '점검 요약    :\n'
  if [ -n "$6" ]; then truncate8 "$6" | sed 's/^/    /'; else printf '    (없음)\n'; fi
  printf '판단 기준    :\n'; printf '%s\n' "$4" | sed 's/^/    /'
  printf -- '----------------------------------------------------------------\n'
}

# 읽기전용 AWS CLI 래퍼: describe/list/get/lookup/generate-credential-report 만 통과
aws_ro(){
  local action="$2"
  case "$action" in
    describe-*|list-*|get-*|lookup-*|generate-credential-report) : ;;
    *) echo "[차단] 읽기전용 아닌 호출: aws $1 $2" >&2; return 90 ;;
  esac
  aws "$@" 2>/dev/null
}

# 예외 리소스 판정
is_excepted(){ local list="$1" target="$2" x; for x in $list; do [ "$target" = "$x" ] && return 0; done; return 1; }
matches_except(){ local list="$1" target="$2" x; for x in $list; do case "$target" in *"$x"*) return 0;; esac; done; return 1; }

# 시나리오 화이트리스트(비우면 전체)
in_scenario(){ [ -z "${SCENARIO_USERS:-}" ] && return 0; local u; for u in $SCENARIO_USERS; do [ "$1" = "$u" ] && return 0; done; return 1; }

# 사용자의 '실효' 연결정책 전체(직접+인라인+그룹 상속) — 출처 라벨 포함
#   ※ list-attached-user-policies는 '직접 연결'만 반환하므로 그룹 상속 권한을 놓침.
#     INSTANCE-IAM 같은 그룹으로 받은 EC2/S3 FullAccess까지 잡으려면 그룹까지 전개해야 함.
user_effective_policies(){  # $1=username → "정책명 [출처]" 라인들
  local u="$1" p g
  for p in $(aws_ro iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyName' --output text); do
    echo "${p} [직접]"
  done
  for p in $(aws_ro iam list-user-policies --user-name "$u" --query 'PolicyNames[]' --output text); do
    echo "${p} [인라인]"
  done
  for g in $(aws_ro iam list-groups-for-user --user-name "$u" --query 'Groups[].GroupName' --output text); do
    for p in $(aws_ro iam list-attached-group-policies --group-name "$g" --query 'AttachedPolicies[].PolicyName' --output text); do
      echo "${p} [그룹:${g}]"
    done
    for p in $(aws_ro iam list-group-policies --group-name "$g" --query 'PolicyNames[]' --output text); do
      echo "${p} [그룹인라인:${g}]"
    done
  done
}

# 보안 그룹 규칙 상세(프로토콜/포트/CIDR) — 위반 규칙 마킹 + 상단 정렬 (3.1/3.2 증적)
#   위반(ANY 포트 0-65535 / ALL 프로토콜 -1 / 전체개방 0.0.0.0/0)을 표시하고 맨 위로 올려
#   안전 규칙에 묻히지 않게(8줄 잘림 대비). 전체 규칙은 그대로 로우데이터로 유지.
sg_rules(){
  local gid="$1"
  { aws_ro ec2 describe-security-groups --group-ids "$gid" \
      --query "SecurityGroups[].IpPermissions[].[IpProtocol,FromPort,ToPort,join(',',IpRanges[].CidrIp)]" \
      --output text 2>/dev/null | sed 's/^/in\t/'
    aws_ro ec2 describe-security-groups --group-ids "$gid" \
      --query "SecurityGroups[].IpPermissionsEgress[].[IpProtocol,FromPort,ToPort,join(',',IpRanges[].CidrIp)]" \
      --output text 2>/dev/null | sed 's/^/out\t/'
  } | awk -F'\t' '
    { dir=$1; proto=$2; fp=$3; tp=$4; cidr=$5; mark="";
      if(fp=="0" && tp=="65535") mark=mark" ← [ANY 포트]";
      if(proto=="-1")            mark=mark" ← [ALL 프로토콜]";
      if(index(cidr,"0.0.0.0/0")>0) mark=mark" ← [전체개방]";
      line=sprintf("  %s: %s %s %s %s%s", dir, proto, fp, tp, cidr, mark);
      if(mark!="") viol[++v]=line; else ok[++o]=line; }
    END { for(i=1;i<=v;i++) print viol[i]; for(i=1;i<=o;i++) print ok[i]; }'
}

# 판정 기록: record CODE NAME STATUS RAW FILE
#   STATUS = PASS|FAIL|NA, RAW = 증적(핵심필드 원문 라인), FILE = 사용한 AWS API
record(){
  local code="$1" name="$2" status="$3" raw="$4" file="$5"
  local sev cat std result fix
  sev="${SEV[$code]:-중}"; cat="$(cat_of "$code")"; fix="${FIX[$code]:-(조치 방법 미정의)}"
  # 결과 없음(자연어, 단일라인 괄호)일 때만 괄호 제거 — 다중라인/내부괄호는 보존
  case "$raw" in
    *$'\n'*) : ;;
    "("*")") raw="${raw#\(}"; raw="${raw%\)}" ;;
  esac
  # AWS CLI --output text의 다중값 탭 구분자를 ', '로 정리(셀/블록 가독성)
  raw="${raw//$'\t'/, }"
  std="양호 : ${STD_PASS[$code]:-(기준 미정의)}"$'\n'"취약 : ${STD_VULN[$code]:-(기준 미정의)}"
  case "$status" in
    PASS)   result="양호"; PASS_CNT=$((PASS_CNT+1)) ;;
    FAIL)   result="취약"; FAIL_CNT=$((FAIL_CNT+1)) ;;
    NA)     result="N/A";  NA_CNT=$((NA_CNT+1)) ;;
  esac
  # append 방식(set -u에서 빈 배열 길이 참조 회피)
  F_CODE+=("$code"); F_CAT+=("$cat"); F_NAME+=("$name"); F_STD+=("$std"); F_FIX+=("$fix")
  F_RESULT+=("$result"); F_RAW+=("$raw"); F_SEV+=("$sev"); F_FILE+=("$file")
  # 실시간 출력(화면=보고서 동일 양식)
  emit_screen "$code" "$sev" "$name" "$std" "$result" "$raw" "$file"
}

section(){ printf "\n■ %s\n" "$1"; }

# 자격증명 보고서 캐시(IAM 다수 항목 재사용)
CRED_REPORT_CSV=""
ensure_cred_report(){
  [ -n "$CRED_REPORT_CSV" ] && return 0
  aws iam generate-credential-report >/dev/null 2>&1
  for _ in 1 2 3; do
    CRED_REPORT_CSV=$(aws iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null)
    [ -n "$CRED_REPORT_CSV" ] && break
    sleep 2; aws iam generate-credential-report >/dev/null 2>&1
  done
}

# ===== 5. 전제 점검 =====
preflight(){
  command -v aws >/dev/null 2>&1 || { echo "AWS CLI 미설치" >&2; exit 1; }
  WHOAMI=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
  [ -n "$WHOAMI" ] || { echo "AWS 자격증명 확인 불가 (aws configure / 프로파일)" >&2; exit 1; }
  ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
  REGION_EFF="${AWS_REGION:-$(aws configure get region 2>/dev/null)}"
  IP_ADDR="$ACCOUNT_ID"   # 클라우드는 호스트 IP 없음 → 진단대상IP=Account ID
}

# =============================================================
# 6. 점검 함수 (로직 유지 · 증적=핵심필드 원문 라인)
# =============================================================

# ---- 1. 계정 관리 ----
check_account(){
  section "1. 계정 관리"
  ensure_cred_report
  local all_users scen_users="" u
  all_users=$(aws_ro iam list-users --query 'Users[].UserName' --output text)
  for u in $all_users; do in_scenario "$u" && scen_users="$scen_users $u"; done
  scen_users="${scen_users# }"

  # 1.1 사용자 계정 관리 : 관리자급(Administrator/FullAccess) 다수 여부
  # 실효 권한(직접+인라인+그룹 상속) 기준으로 관리자급 보유 계정 탐지
  local raw="" admin_cnt=0 eff
  for u in $scen_users; do
    eff="$(user_effective_policies "$u")"
    raw="${raw}${u}:"$'\n'"$(printf '%s' "${eff:-(연결정책 없음)}" | sed 's/^/  /')"$'\n'
    case "$eff" in *AdministratorAccess*|*FullAccess*) admin_cnt=$((admin_cnt+1));; esac
  done
  raw="${raw%$'\n'}"; [ -z "$raw" ] && raw="(점검 대상 IAM 사용자 없음)"
  if [ "$admin_cnt" -le 1 ]; then
    record 1.1 "사용자 계정 관리" PASS "$raw" "iam list-attached-user-policies, list-user-policies, list-groups-for-user, list-attached-group-policies"
  else
    record 1.1 "사용자 계정 관리" FAIL "$raw" "iam list-attached-user-policies, list-user-policies, list-groups-for-user, list-attached-group-policies"
  fi

  # 1.2 IAM 사용자 계정 단일화(1인 1계정): 공유 의심 명칭 탐지 (점검 대상=화이트리스트)
  local shared
  shared=$(echo "$scen_users" | tr ' ' '\n' | grep -iE 'shared|common|test|temp|guest' | tr '\n' ' ')
  raw="$(echo "$scen_users" | tr ' ' '\n' | grep -v '^$')"   # SCENARIO_USERS 적용(비우면 전체)
  [ -z "$raw" ] && raw="(점검 대상 IAM 사용자 없음)"
  if [ -z "${shared// }" ]; then
    record 1.2 "IAM 사용자 계정 단일화 관리" PASS "$raw" "iam list-users"
  else
    record 1.2 "IAM 사용자 계정 단일화 관리" FAIL "$raw"$'\n'"# 공유 의심: ${shared}" "iam list-users"
  fi

  # 1.3 IAM 사용자 계정 식별: 태그 설정 여부
  raw=""; local untagged="" tags
  for u in $scen_users; do
    tags=$(aws_ro iam list-user-tags --user-name "$u" --query 'Tags[].Key' --output text)
    raw="${raw}${u}: ${tags:-(태그 없음)}"$'\n'
    [ -z "$tags" ] && untagged="$untagged $u"
  done
  raw="${raw%$'\n'}"; [ -z "$raw" ] && raw="(점검 대상 IAM 사용자 없음)"
  if [ -z "${untagged// }" ]; then
    record 1.3 "IAM 사용자 계정 식별 관리" PASS "$raw" "iam list-user-tags"
  else
    record 1.3 "IAM 사용자 계정 식별 관리" FAIL "$raw" "iam list-user-tags"
  fi

  # 1.4 IAM 그룹 사용자 계정: 그룹별 멤버(점검 대상=화이트리스트) + 불필요(장기 미사용) 탐지
  #   PDF 점검방법 9) "그룹 내 불필요한 사용자 확인 및 제거" → 그룹+멤버가 증적.
  #   SCENARIO_USERS 적용: 대상 멤버만 표시·판정하고, 대상 멤버 없는 그룹은 범위 밖이라 제외(비우면 전체).
  raw=""; local groups g members m in_members stale_mem=""
  groups=$(aws_ro iam list-groups --query 'Groups[].GroupName' --output text)
  for g in $groups; do
    is_excepted "${EXCEPT_GROUP:-}" "$g" && continue
    members=$(aws_ro iam get-group --group-name "$g" --query 'Users[].UserName' --output text)
    in_members=""
    for m in $members; do in_scenario "$m" && in_members="$in_members $m"; done
    in_members="${in_members# }"
    [ -z "$in_members" ] && continue   # 점검 대상 멤버 없는 그룹은 범위 밖 → 제외
    raw="${raw}${g}: ${in_members// /, }"$'\n'
    for m in $in_members; do
      local last; last=$(echo "$CRED_REPORT_CSV" | awk -F, -v u="$m" '$1==u{print $5}')
      if [ -n "$last" ] && [ "$last" != "N/A" ]; then
        local le ne d; le=$(date -d "$last" +%s 2>/dev/null||echo 0); ne=$(date +%s); d=$(( (ne-le)/86400 ))
        [ "$le" -gt 0 ] && [ "$d" -gt "${STALE_DAYS:-90}" ] && stale_mem="$stale_mem ${g}/${m}(${d}d)"
      fi
    done
  done
  raw="${raw%$'\n'}"; [ -z "$raw" ] && raw="(점검 대상 멤버가 속한 IAM 그룹 없음)"
  if [ -z "${stale_mem// }" ]; then
    record 1.4 "IAM 그룹 사용자 계정 관리" PASS "$raw" "iam list-groups, iam get-group"
  else
    record 1.4 "IAM 그룹 사용자 계정 관리" FAIL "$raw"$'\n'"# 불필요 의심(${STALE_DAYS}일 초과 미사용) 멤버:${stale_mem}" "iam list-groups, iam get-group"
  fi

  # 1.5 Key Pair 접근: EC2 인스턴스에 Key Pair(KeyName)가 등록되어 있는지로 판정
  #   양호=Key Pair 접근 / 취약=KeyName 미등록(패스워드 접근 의심, SSM 전용 인스턴스는 예외 가능)
  local insts iid kname state no_key=""
  insts=$(aws_ro ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,KeyName,State.Name]' --output text)
  raw=""
  while read -r iid kname state; do
    [ -z "$iid" ] && continue
    [ "$state" = "terminated" ] && continue
    raw="${raw}${iid}: KeyName=${kname:-(없음)} State=${state}"$'\n'
    { [ -z "$kname" ] || [ "$kname" = "None" ]; } && no_key="$no_key $iid"
  done <<< "$insts"
  raw="${raw%$'\n'}"
  if [ -z "$raw" ]; then
    record 1.5 "Key Pair 접근 관리" NA "(실행 중인 EC2 인스턴스 없음 — 해당 없음)" "ec2 describe-instances"
  elif [ -z "${no_key// }" ]; then
    record 1.5 "Key Pair 접근 관리" PASS "$raw" "ec2 describe-instances"
  else
    record 1.5 "Key Pair 접근 관리" FAIL "$raw"$'\n'"# Key Pair 미등록(패스워드 접근 의심, SSM 전용 시 예외):${no_key}" "ec2 describe-instances"
  fi

  # 1.6 Key Pair 보관: S3 버킷에서 .pem/.ppk/.key 탐색 후 보관 위치(퍼블릭 여부)로 판정
  #   퍼블릭 버킷=취약, 프라이빗 버킷=양호, 미발견=N/A(수동). 버킷당 스캔 상한으로 비용 방어.
  local kbuckets kb keys k pab loc pub_hit="" priv_hit=""
  kbuckets=$(aws_ro s3api list-buckets --query 'Buckets[].Name' --output text)
  raw=""
  for kb in $kbuckets; do
    keys=$(aws_ro s3api list-objects-v2 --bucket "$kb" --max-items "${S3_KEYFILE_MAXKEYS:-2000}" \
            --query 'Contents[].Key' --output text 2>/dev/null | tr '\t' '\n' | grep -iE '\.(pem|ppk|key)$')
    [ -z "$keys" ] && continue
    pab=$(aws_ro s3api get-public-access-block --bucket "$kb" \
        --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text)
    loc="private"; { [ -z "$pab" ] || echo "$pab" | grep -qi false; } && loc="public"
    while read -r k; do [ -z "$k" ] && continue
      raw="${raw}s3://${kb}/${k}  [bucket=${loc}]"$'\n'
      [ "$loc" = "public" ] && pub_hit="$pub_hit s3://${kb}/${k}" || priv_hit="$priv_hit s3://${kb}/${k}"
    done <<< "$keys"
  done
  raw="${raw%$'\n'}"
  if [ -n "${pub_hit// }" ]; then
    record 1.6 "Key Pair 보관 관리" FAIL "$raw"$'\n'"# 퍼블릭 접근 가능 버킷에 Key Pair 보관:${pub_hit}" "s3api list-objects-v2, s3api get-public-access-block"
  elif [ -n "${priv_hit// }" ]; then
    record 1.6 "Key Pair 보관 관리" PASS "$raw"$'\n'"# 프라이빗 버킷 보관(쉽게 유추 불가 위치) — 객체 ACL은 수동 확인 권장" "s3api list-objects-v2, s3api get-public-access-block"
  else
    record 1.6 "Key Pair 보관 관리" NA "(스캔한 S3 버킷에서 .pem/.ppk/.key 미발견 — 보관 위치 수동 확인. 스캔 상한 ${S3_KEYFILE_MAXKEYS:-2000}키/버킷)" "s3api list-objects-v2"
  fi

  # 1.7 Admin Console 관리자 정책: 루트 Access Key 활성(서비스용 의심)
  local root_line root_k1 root_k2
  root_line=$(echo "$CRED_REPORT_CSV" | awk -F, '$1=="<root_account>"{print}')
  root_k1=$(echo "$root_line" | awk -F, '{print $9}'); root_k2=$(echo "$root_line" | awk -F, '{print $14}')
  raw="<root_account>: access_key_1_active=${root_k1:-N/A} access_key_2_active=${root_k2:-N/A}"
  if echo "${root_k1},${root_k2}" | grep -q "true"; then
    record 1.7 "Admin Console 관리자 정책 관리" FAIL "$raw" "iam get-credential-report"
  else
    record 1.7 "Admin Console 관리자 정책 관리" PASS "$raw" "iam get-credential-report"
  fi

  # 1.8 Access Key 활성화 및 사용주기(60일)
  raw=""; local bad_keys=""
  while IFS=, read -r user _arn _c _pe _pl _pc _pn _mfa k1act k1rot _a _b _cc k2act k2rot _rest; do
    [ "$user" = "user" ] && continue
    [ "$user" = "<root_account>" ] && continue
    in_scenario "$user" || continue
    raw="${raw}${user}: key1(active=${k1act},last_rotated=${k1rot}) key2(active=${k2act},last_rotated=${k2rot})"$'\n'
    local pair idx act rot
    for pair in "1:$k1act:$k1rot" "2:$k2act:$k2rot"; do
      IFS=: read -r idx act rot <<< "$pair"
      [ "$act" != "true" ] && continue
      if [ "$rot" != "N/A" ] && [ -n "$rot" ]; then
        local re ne d; re=$(date -d "$rot" +%s 2>/dev/null||echo 0); ne=$(date +%s); d=$(( (ne-re)/86400 ))
        [ "$re" -gt 0 ] && [ "$d" -gt "${KEY_MAX_DAYS:-60}" ] && bad_keys="$bad_keys ${user}#${idx}(${d}d)"
      fi
    done
  done <<< "$CRED_REPORT_CSV"
  raw="${raw%$'\n'}"
  raw="<root_account>: access_key_1_active=${root_k1:-N/A} access_key_2_active=${root_k2:-N/A}"$'\n'"${raw}"
  echo "${root_k1},${root_k2}" | grep -q "true" && bad_keys="$bad_keys root(Access Key 존재)"
  if [ -z "${bad_keys// }" ]; then
    record 1.8 "Admin Console 계정 Access Key 활성화 및 사용주기 관리" PASS "$raw" "iam get-credential-report"
  else
    record 1.8 "Admin Console 계정 Access Key 활성화 및 사용주기 관리" FAIL "$raw"$'\n'"# 기준 초과:${bad_keys}" "iam get-credential-report"
  fi

  # 1.9 MFA 설정
  raw=""; local no_mfa=""
  while IFS=, read -r user _arn _c pe _pl _pc _pn mfa _rest; do
    [ "$user" = "user" ] && continue
    if [ "$user" = "<root_account>" ]; then
      raw="<root_account>: mfa_active=${mfa}"$'\n'"${raw}"
      [ "$mfa" = "false" ] && no_mfa="$no_mfa root"
      continue
    fi
    in_scenario "$user" || continue
    raw="${raw}${user}: password_enabled=${pe} mfa_active=${mfa}"$'\n'
    [ "$pe" = "true" ] && [ "$mfa" = "false" ] && no_mfa="$no_mfa $user"
  done <<< "$CRED_REPORT_CSV"
  raw="${raw%$'\n'}"
  if [ -z "${no_mfa// }" ]; then
    record 1.9 "MFA (Multi-Factor Authentication) 설정" PASS "$raw" "iam get-credential-report"
  else
    record 1.9 "MFA (Multi-Factor Authentication) 설정" FAIL "$raw"$'\n'"# MFA 미설정:${no_mfa}" "iam get-credential-report"
  fi

  # 1.10 패스워드 정책
  local pol
  pol=$(aws_ro iam get-account-password-policy --output json)
  if [ -z "$pol" ]; then
    record 1.10 "AWS 계정 패스워드 정책 관리" FAIL "(계정 패스워드 정책 미설정)" "iam get-account-password-policy"
  else
    raw="$(echo "$pol" | grep -oE '"(MinimumPasswordLength|RequireSymbols|RequireNumbers|RequireUppercaseCharacters|RequireLowercaseCharacters|MaxPasswordAge|PasswordReusePrevention|ExpirePasswords)": *[^,}]*' | sed 's/^/# password-policy: /')"
    local minlen reuse maxage low up num sym problems=""
    minlen=$(echo "$pol" | grep -o '"MinimumPasswordLength": *[0-9]*' | grep -o '[0-9]*$')
    reuse=$(echo "$pol"  | grep -o '"PasswordReusePrevention": *[0-9]*' | grep -o '[0-9]*$')
    maxage=$(echo "$pol" | grep -o '"MaxPasswordAge": *[0-9]*' | grep -o '[0-9]*$')
    low=$(echo "$pol" | grep -o '"RequireLowercaseCharacters": *true')
    up=$(echo "$pol"  | grep -o '"RequireUppercaseCharacters": *true')
    num=$(echo "$pol" | grep -o '"RequireNumbers": *true')
    sym=$(echo "$pol" | grep -o '"RequireSymbols": *true')
    [ "${minlen:-0}" -lt "${PW_MIN_LEN:-8}" ] && problems="$problems 길이<${PW_MIN_LEN}"
    [ -z "$reuse" ] && problems="$problems 재사용제한없음"
    { [ -z "$maxage" ] || [ "${maxage:-999}" -gt "${PW_MAX_AGE:-90}" ]; } && problems="$problems 만료>${PW_MAX_AGE}일"
    [ -z "$low$up" ] && problems="$problems 대소문자미요구"
    [ -z "$num" ] && problems="$problems 숫자미요구"
    [ -z "$sym" ] && problems="$problems 특수문자미요구"
    if [ -z "${problems// }" ]; then
      record 1.10 "AWS 계정 패스워드 정책 관리" PASS "$raw" "iam get-account-password-policy"
    else
      record 1.10 "AWS 계정 패스워드 정책 관리" FAIL "$raw"$'\n'"# 미흡:${problems}" "iam get-account-password-policy"
    fi
  fi

  # 1.11~1.13 EKS : 클러스터 없으면 N/A
  local eks
  eks=$(aws_ro eks list-clusters --query 'clusters' --output text)
  if [ -z "$eks" ]; then
    record 1.11 "EKS 사용자 관리" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
    record 1.12 "EKS 서비스 어카운트 관리" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
    record 1.13 "EKS 불필요한 익명 접근 관리" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
  else
    raw="# eks list-clusters"$'\n'"$(echo "$eks" | tr '\t' '\n')"
    record 1.11 "EKS 사용자 관리" NA "$raw"$'\n'"# ConfigMap(aws-auth)/RBAC는 클러스터 내부 확인 필요(kubectl)" "eks list-clusters"
    record 1.12 "EKS 서비스 어카운트 관리" NA "$raw"$'\n'"# automountServiceAccountToken은 클러스터 내부 확인 필요(kubectl)" "eks list-clusters"
    record 1.13 "EKS 불필요한 익명 접근 관리" NA "$raw"$'\n'"# system:anonymous 바인딩은 클러스터 내부 확인 필요(kubectl)" "eks list-clusters"
  fi
}

# ---- 2. 권한 관리 ----
# "역할에 맞게" 적정성은 사람/AI 판정 영역 → 과다권한(Administrator/FullAccess)만 객관 취약,
# 그 외는 역할·연결정책 전수 수록 후 N/A(수동 확인).
check_iam_policy(){
  section "2. 권한 관리"
  local r rpath attached raw="" wild="" rraw="" uraw="" users u upols hidden=0
  # 사용자 정의 역할만 — AWS 자동생성/서비스 역할(path 또는 이름 패턴)은 숨김
  while IFS=$'\t' read -r r rpath; do
    [ -z "$r" ] && continue
    case "$rpath" in /aws-service-role/*|/service-role/*) hidden=$((hidden+1)); continue ;; esac
    matches_except "${AWS_ROLE_HIDE_PATTERNS:-}" "$r" && { hidden=$((hidden+1)); continue; }
    attached=$(aws_ro iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyName' --output text)
    rraw="${rraw}${r}: ${attached:-(연결정책 없음)}"$'\n'
    case " $attached " in *AdministratorAccess*|*FullAccess*) wild="$wild ${r}";; esac
  done < <(aws_ro iam list-roles --query 'Roles[].[RoleName,Path]' --output text)
  rraw="${rraw%$'\n'}"; [ -z "$rraw" ] && rraw="(사용자 정의 IAM 역할 없음)"
  [ "$hidden" -gt 0 ] && rraw="${rraw}"$'\n'"# (AWS 자동생성/서비스 역할 ${hidden}개 숨김 — 필요 시 conf AWS_ROLE_HIDE_PATTERNS 조정)"
  # 사용자 실효 권한(직접+인라인+그룹 상속, 출처 라벨) — 점검 대상=화이트리스트(SCENARIO_USERS)
  users=$(aws_ro iam list-users --query 'Users[].UserName' --output text)
  for u in $users; do
    in_scenario "$u" || continue   # 점검 대상 화이트리스트 적용(비우면 전체)
    upols="$(user_effective_policies "$u")"
    uraw="${uraw}${u}:"$'\n'"$(printf '%s' "${upols:-(연결정책 없음)}" | sed 's/^/  /')"$'\n'
  done
  uraw="${uraw%$'\n'}"; [ -z "$uraw" ] && uraw="(점검 대상 IAM 사용자 없음)"
  # 사용자(사용 계정) 정책을 앞에 — 화면 8줄에 먼저 보이도록. 역할은 뒤(전량은 CSV).
  raw="# IAM 사용자 연결정책"$'\n'"${uraw}"$'\n'"# IAM 역할(서비스 역할) 연결정책"$'\n'"${rraw}"
  local code name
  for code in 2.1 2.2 2.3; do
    case "$code" in
      2.1) name="인스턴스 서비스 정책 관리" ;;
      2.2) name="네트워크 서비스 정책 관리" ;;
      2.3) name="기타 서비스 정책 관리" ;;
    esac
    if [ -n "${wild// }" ]; then
      record "$code" "$name" FAIL "$raw"$'\n'"# 과다권한(Administrator/FullAccess) 역할:${wild}" "iam list-roles, iam list-attached-role-policies"
    else
      record "$code" "$name" NA "$raw"$'\n'"# 과다권한 역할 없음. 서비스별 역할 적정성은 수동/AI 확인 대상" "iam list-roles, iam list-attached-role-policies"
    fi
  done
}

# ---- 3. 가상 리소스 관리 ----
check_resource(){
  section "3. 가상 리소스 관리"
  local raw=""

  # 3.1 보안 그룹 ANY(포트 0-65535) 설정
  local sg_any
  sg_any=$(aws_ro ec2 describe-security-groups \
    --query "SecurityGroups[?length(IpPermissions[?FromPort==\`0\` && ToPort==\`65535\`])>\`0\` || length(IpPermissionsEgress[?FromPort==\`0\` && ToPort==\`65535\`])>\`0\`].[GroupId,GroupName]" \
    --output text)
  if [ -z "$sg_any" ]; then
    record 3.1 "보안 그룹 인/아웃바운드 ANY 설정 관리" PASS "(포트 Any(0-65535) 허용 규칙 없음)" "ec2 describe-security-groups"
  else
    local eff="" exc="" gid
    raw="$(echo "$sg_any" | sed 's/\t/  /g')"
    while read -r gid _; do [ -z "$gid" ] && continue
      raw="${raw}"$'\n'"# ${gid} 규칙"$'\n'"$(sg_rules "$gid")"
      if is_excepted "$EXCEPT_SG" "$gid"; then exc="$exc $gid"; else eff="$eff $gid"; fi
    done <<< "$sg_any"
    if [ -z "${eff// }" ]; then
      record 3.1 "보안 그룹 인/아웃바운드 ANY 설정 관리" FAIL "$raw"$'\n'"# [조치 예외사항 - 구성상 필요]:${exc}" "ec2 describe-security-groups"
    else
      record 3.1 "보안 그룹 인/아웃바운드 ANY 설정 관리" FAIL "$raw" "ec2 describe-security-groups"
    fi
  fi

  # 3.2 보안 그룹 불필요 정책(0.0.0.0/0 광범위 허용)
  local sg_open
  sg_open=$(aws_ro ec2 describe-security-groups \
    --query "SecurityGroups[?length(IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')])>\`0\`].[GroupId,GroupName]" \
    --output text)
  if [ -z "$sg_open" ]; then
    record 3.2 "보안 그룹 인/아웃바운드 불필요 정책 관리" PASS "(0.0.0.0/0 인바운드 개방 SG 없음)" "ec2 describe-security-groups"
  else
    raw="$(echo "$sg_open" | sed 's/\t/  /g')"
    local eff="" exc="" gid mgmt="" p
    while read -r gid _; do [ -z "$gid" ] && continue
      raw="${raw}"$'\n'"# ${gid} 규칙"$'\n'"$(sg_rules "$gid")"
      if is_excepted "$EXCEPT_SG" "$gid"; then exc="$exc $gid"; continue; fi
      eff="$eff $gid"
      p=$(aws_ro ec2 describe-security-groups --group-ids "$gid" \
        --query "SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp,'0.0.0.0/0') && (FromPort==\`22\` || FromPort==\`3389\`)].FromPort" --output text)
      [ -n "$p" ] && mgmt="$mgmt ${gid}(port:${p})"
    done <<< "$sg_open"
    [ -n "$mgmt" ] && raw="${raw}"$'\n'"# 관리포트(22/3389) 노출:${mgmt}"
    if [ -z "${eff// }" ]; then
      record 3.2 "보안 그룹 인/아웃바운드 불필요 정책 관리" FAIL "$raw"$'\n'"# [조치 예외사항 - 구성상 필요]:${exc}" "ec2 describe-security-groups"
    else
      record 3.2 "보안 그룹 인/아웃바운드 불필요 정책 관리" FAIL "$raw" "ec2 describe-security-groups"
    fi
  fi

  # 3.3 네트워크 ACL 모든 트래픽 허용(커스텀 NACL)
  local nacl
  nacl=$(aws_ro ec2 describe-network-acls \
    --query "NetworkAcls[?!IsDefault && length(Entries[?RuleAction=='allow' && CidrBlock=='0.0.0.0/0' && Protocol=='-1'])>\`0\`].NetworkAclId" \
    --output text)
  if [ -z "$nacl" ]; then
    record 3.3 "네트워크 ACL 인/아웃바운드 트래픽 정책 관리" PASS "(커스텀 NACL 전체허용 없음 — 기본 NACL 제외)" "ec2 describe-network-acls"
  else
    record 3.3 "네트워크 ACL 인/아웃바운드 트래픽 정책 관리" FAIL "$(echo "$nacl" | tr '\t' '\n' | sed 's/^/# 전체허용 NACL: /')" "ec2 describe-network-acls"
  fi

  # 3.4 라우팅 테이블 정책(사설 RT에 0.0.0.0/0→IGW)
  local rt
  rt=$(aws_ro ec2 describe-route-tables \
    --query "RouteTables[?length(Routes[?DestinationCidrBlock=='0.0.0.0/0' && starts_with(GatewayId,'igw-')])>\`0\`].[RouteTableId]" \
    --output text)
  if [ -z "$rt" ]; then
    record 3.4 "라우팅 테이블 정책 관리" PASS "(0.0.0.0/0→IGW 경로 없음)" "ec2 describe-route-tables"
  else
    raw="$(echo "$rt" | tr '\t' '\n' | sed 's/^/# 0.0.0.0\/0 to IGW: /')"
    record 3.4 "라우팅 테이블 정책 관리" NA "$raw"$'\n'"# 퍼블릭 서브넷의 IGW 기본경로는 정상 — 사설 서브넷 오연결 여부 수동 확인" "ec2 describe-route-tables"
  fi

  # 3.5 인터넷 게이트웨이 연결(미연결 고아 IGW)
  local igw
  igw=$(aws_ro ec2 describe-internet-gateways \
    --query "InternetGateways[?length(Attachments)==\`0\`].InternetGatewayId" --output text)
  if [ -z "$igw" ]; then
    record 3.5 "인터넷 게이트웨이 연결 관리" PASS "(미연결(고아) IGW 없음)" "ec2 describe-internet-gateways"
  else
    record 3.5 "인터넷 게이트웨이 연결 관리" FAIL "$(echo "$igw" | tr '\t' '\n' | sed 's/^/# 미연결 IGW: /')" "ec2 describe-internet-gateways"
  fi

  # 3.6 NAT 게이트웨이 연결(라우팅 미참조)
  local nat_ids n ref nat_unused=""
  nat_ids=$(aws_ro ec2 describe-nat-gateways --filter "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text)
  raw=""
  for n in $nat_ids; do
    ref=$(aws_ro ec2 describe-route-tables --query "RouteTables[?length(Routes[?NatGatewayId=='${n}'])>\`0\`].RouteTableId" --output text)
    raw="${raw}${n}: route_ref=${ref:-(없음)}"$'\n'
    [ -z "$ref" ] && nat_unused="$nat_unused $n"
  done
  raw="${raw%$'\n'}"
  if [ -z "$nat_ids" ]; then
    record 3.6 "NAT 게이트웨이 연결 관리" PASS "(활성 NAT 게이트웨이 없음)" "ec2 describe-nat-gateways"
  elif [ -z "${nat_unused// }" ]; then
    record 3.6 "NAT 게이트웨이 연결 관리" PASS "$raw" "ec2 describe-nat-gateways, ec2 describe-route-tables"
  else
    record 3.6 "NAT 게이트웨이 연결 관리" FAIL "$raw"$'\n'"# 라우팅 미참조 NAT:${nat_unused}" "ec2 describe-nat-gateways, ec2 describe-route-tables"
  fi

  # 3.7 S3 버킷/객체 접근(퍼블릭 액세스 차단)
  local buckets b pab pub_bkt=""
  buckets=$(aws_ro s3api list-buckets --query 'Buckets[].Name' --output text)
  raw=""
  for b in $buckets; do
    pab=$(aws_ro s3api get-public-access-block --bucket "$b" \
      --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text)
    raw="${raw}${b}: PublicAccessBlock=[${pab:-미설정}]"$'\n'
    { [ -z "$pab" ] || echo "$pab" | grep -qi "false"; } && pub_bkt="$pub_bkt $b"
  done
  raw="${raw%$'\n'}"
  if [ -z "$buckets" ]; then
    record 3.7 "S3 버킷/객체 접근 관리" PASS "(S3 버킷 없음)" "s3api list-buckets"
  elif [ -z "${pub_bkt// }" ]; then
    record 3.7 "S3 버킷/객체 접근 관리" PASS "$raw" "s3api get-public-access-block"
  else
    local eff="" exc=""
    for b in $pub_bkt; do if is_excepted "$EXCEPT_BUCKET" "$b"; then exc="$exc $b"; else eff="$eff $b"; fi; done
    if [ -z "${eff// }" ]; then
      record 3.7 "S3 버킷/객체 접근 관리" FAIL "$raw"$'\n'"# [조치 예외사항 - 구성상 필요]:${exc}" "s3api get-public-access-block"
    else
      record 3.7 "S3 버킷/객체 접근 관리" FAIL "$raw"$'\n'"# 퍼블릭 차단 미흡:${eff}" "s3api get-public-access-block"
    fi
  fi

  # 3.8 RDS 서브넷 가용 영역(불필요 AZ)
  local rds_list grp azc
  rds_list=$(aws_ro rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output text)
  if [ -z "$rds_list" ]; then
    record 3.8 "RDS 서브넷 가용 영역 관리" PASS "(RDS 인스턴스 없음)" "rds describe-db-instances"
  else
    raw=""
    for grp in $(aws_ro rds describe-db-subnet-groups --query 'DBSubnetGroups[].DBSubnetGroupName' --output text); do
      azc=$(aws_ro rds describe-db-subnet-groups --db-subnet-group-name "$grp" \
        --query 'DBSubnetGroups[].Subnets[].SubnetAvailabilityZone.Name' --output text | tr '\t' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
      raw="${raw}${grp}: AZ=[${azc}]"$'\n'
    done
    raw="${raw%$'\n'}"
    record 3.8 "RDS 서브넷 가용 영역 관리" NA "$raw"$'\n'"# 서브넷 그룹 AZ 구성 — '불필요' 여부는 DB 배치 대비 수동 확인" "rds describe-db-subnet-groups"
  fi

  # 3.9 EKS Pod 보안 정책 : 클러스터 없으면 N/A
  local eks
  eks=$(aws_ro eks list-clusters --query 'clusters' --output text)
  if [ -z "$eks" ]; then
    record 3.9 "EKS Pod 보안 정책 관리" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
  else
    record 3.9 "EKS Pod 보안 정책 관리" NA "$(echo "$eks" | tr '\t' '\n')"$'\n'"# PSS/PSA(Baseline/Audit) 적용은 클러스터 내부 확인 필요(kubectl)" "eks list-clusters"
  fi

  # 3.10 ELB 연결 관리 : 제어 정책 준수는 수동
  local lb
  lb=$(aws_ro elbv2 describe-load-balancers --query 'LoadBalancers[].[LoadBalancerName,Scheme,Type]' --output text)
  if [ -z "$lb" ]; then
    record 3.10 "ELB(Elastic Load Balancing) 연결 관리" PASS "(로드밸런서 없음 — 해당 없음)" "elbv2 describe-load-balancers"
  else
    record 3.10 "ELB(Elastic Load Balancing) 연결 관리" NA "$(echo "$lb" | sed 's/\t/  /g')"$'\n'"# ELB 제어 정책(리스너/대상 등) 준수는 수동 확인" "elbv2 describe-load-balancers"
  fi
}

# ---- 4. 운영 관리 ----
check_operation(){
  section "4. 운영 관리"
  local raw="" buckets b arn
  buckets=$(aws_ro s3api list-buckets --query 'Buckets[].Name' --output text)
  local rds_list
  rds_list=$(aws_ro rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output text)

  # 4.1 EBS 볼륨 암호화
  raw="$(aws_ro ec2 describe-volumes --query 'Volumes[].[VolumeId,Encrypted]' --output text | sed 's/\t/  Encrypted=/')"
  local ebs_unenc
  ebs_unenc=$(aws_ro ec2 describe-volumes --query "Volumes[?Encrypted==\`false\`].VolumeId" --output text)
  [ -z "$raw" ] && raw="(EBS 볼륨 없음)"
  if [ -z "$ebs_unenc" ]; then
    record 4.1 "EBS 및 볼륨 암호화 설정" PASS "$raw" "ec2 describe-volumes"
  else
    record 4.1 "EBS 및 볼륨 암호화 설정" FAIL "$raw"$'\n'"# 미암호화:${ebs_unenc}" "ec2 describe-volumes"
  fi

  # 4.2 RDS 암호화
  if [ -z "$rds_list" ]; then
    record 4.2 "RDS 암호화 설정" PASS "(RDS 인스턴스 없음 — 해당 없음)" "rds describe-db-instances"
  else
    raw="$(aws_ro rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,StorageEncrypted]' --output text | sed 's/\t/  StorageEncrypted=/')"
    local rds_unenc
    rds_unenc=$(aws_ro rds describe-db-instances --query "DBInstances[?StorageEncrypted==\`false\`].DBInstanceIdentifier" --output text)
    if [ -z "$rds_unenc" ]; then
      record 4.2 "RDS 암호화 설정" PASS "$raw" "rds describe-db-instances"
    else
      record 4.2 "RDS 암호화 설정" FAIL "$raw"$'\n'"# 미암호화:${rds_unenc}" "rds describe-db-instances"
    fi
  fi

  # 4.3 S3 암호화(SSE-S3/SSE-KMS)
  raw=""; local enc s3_unenc=""
  for b in $buckets; do
    enc=$(aws_ro s3api get-bucket-encryption --bucket "$b" \
      --query 'ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)
    raw="${raw}${b}: SSEAlgorithm=${enc:-(미설정)}"$'\n'
    [ -z "$enc" ] && s3_unenc="$s3_unenc $b"
  done
  raw="${raw%$'\n'}"
  if [ -z "$buckets" ]; then
    record 4.3 "S3 암호화 설정" PASS "(S3 버킷 없음)" "s3api list-buckets"
  elif [ -z "${s3_unenc// }" ]; then
    record 4.3 "S3 암호화 설정" PASS "$raw" "s3api get-bucket-encryption"
  else
    record 4.3 "S3 암호화 설정" FAIL "$raw"$'\n'"# 암호화 미설정:${s3_unenc}" "s3api get-bucket-encryption"
  fi

  # 4.4 통신구간 암호화 : TLS/리스너 정책은 API 단편만 관측 → N/A(수동)
  local lb_arns listeners=""
  lb_arns="$(aws_ro elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text | tr '\t' '\n')"
  for arn in $lb_arns; do
    [ -z "$arn" ] && continue
    listeners="${listeners}$(aws_ro elbv2 describe-listeners --load-balancer-arn "$arn" --query 'Listeners[].[Protocol,Port]' --output text | sed 's/\t/:/')"$'\n'
  done
  listeners="$(echo "$listeners" | grep -v '^$' | sed 's/^/# listener: /')"
  [ -z "$listeners" ] && listeners="(로드밸런서/리스너 없음 — 리소스 간 TLS 적용 여부 수동 확인)"
  record 4.4 "통신구간 암호화 설정" NA "$listeners" "elbv2 describe-listeners"

  # 4.5 CloudTrail 암호화(SSE-KMS)
  local trails ct_nokms
  trails=$(aws_ro cloudtrail describe-trails --query 'trailList[].[Name,KmsKeyId]' --output text)
  if [ -z "$trails" ]; then
    record 4.5 "CloudTrail 암호화 설정" FAIL "(CloudTrail 미구성)" "cloudtrail describe-trails"
  else
    raw="$(echo "$trails" | sed 's/\t/  KmsKeyId=/')"
    ct_nokms=$(aws_ro cloudtrail describe-trails --query "trailList[?KmsKeyId==null].Name" --output text)
    if [ -z "$ct_nokms" ]; then
      record 4.5 "CloudTrail 암호화 설정" PASS "$raw" "cloudtrail describe-trails"
    else
      record 4.5 "CloudTrail 암호화 설정" FAIL "$raw"$'\n'"# KMS 미적용:${ct_nokms}" "cloudtrail describe-trails"
    fi
  fi

  # 4.6 CloudWatch 로그그룹 암호화(KMS)
  local lg_all lg_nokms
  lg_all=$(aws_ro logs describe-log-groups --query 'logGroups[].[logGroupName,kmsKeyId]' --output text)
  lg_nokms=$(aws_ro logs describe-log-groups --query "logGroups[?kmsKeyId==null].logGroupName" --output text)
  if [ -z "$lg_all" ]; then
    record 4.6 "CloudWatch 암호화 설정" PASS "(로그 그룹 없음)" "logs describe-log-groups"
  else
    raw="$(echo "$lg_all" | sed 's/\t/  kmsKeyId=/')"
    if [ -z "$lg_nokms" ]; then
      record 4.6 "CloudWatch 암호화 설정" PASS "$raw" "logs describe-log-groups"
    else
      record 4.6 "CloudWatch 암호화 설정" FAIL "$raw"$'\n'"# KMS 미적용:${lg_nokms}" "logs describe-log-groups"
    fi
  fi

  # 4.7 AWS 사용자 계정 로깅(멀티리전 CloudTrail + 로깅 활성)
  local multiregion t st active="" raw7=""
  multiregion=$(aws_ro cloudtrail describe-trails --query "trailList[?IsMultiRegionTrail==\`true\`].Name" --output text)
  if [ -n "$multiregion" ]; then
    for t in $multiregion; do
      st=$(aws cloudtrail get-trail-status --name "$t" --query 'IsLogging' --output text 2>/dev/null)
      raw7="${raw7}${t}: IsMultiRegionTrail=true IsLogging=${st}"$'\n'
      [ "$st" = "True" ] && active="$active $t"
    done
    raw7="${raw7%$'\n'}"
    if [ -n "${active// }" ]; then
      record 4.7 "AWS 사용자 계정 로깅 설정" PASS "$raw7" "cloudtrail describe-trails, cloudtrail get-trail-status"
    else
      record 4.7 "AWS 사용자 계정 로깅 설정" FAIL "$raw7"$'\n'"# 멀티리전 Trail 존재하나 로깅 비활성" "cloudtrail get-trail-status"
    fi
  else
    record 4.7 "AWS 사용자 계정 로깅 설정" FAIL "(멀티리전 CloudTrail 미설정)" "cloudtrail describe-trails"
  fi

  # 4.8 인스턴스 로깅: 실행 인스턴스가 CloudWatch 로그 스트림으로 적재되는지 추정
  #   (로그 스트림명에 instance-id 포함 여부로 매칭. 정의적 판정은 아니라 미매칭은 N/A·수동)
  local run_insts iid grp allstreams="" matched="" unmatched=""
  run_insts=$(aws_ro ec2 describe-instances --query "Reservations[].Instances[?State.Name=='running'].InstanceId" --output text)
  if [ -z "$run_insts" ]; then
    record 4.8 "인스턴스 로깅 설정" NA "(실행 중인 EC2 인스턴스 없음 — 해당 없음)" "ec2 describe-instances"
  else
    for grp in $(echo "$lg_all" | awk '{print $1}'); do
      allstreams="${allstreams} $(aws_ro logs describe-log-streams --log-group-name "$grp" --query 'logStreams[].logStreamName' --output text 2>/dev/null)"
    done
    raw=""
    for iid in $run_insts; do
      if echo "$allstreams" | grep -q "$iid"; then
        matched="$matched $iid"; raw="${raw}${iid}: CloudWatch 로그 스트림 존재"$'\n'
      else
        unmatched="$unmatched $iid"; raw="${raw}${iid}: 매칭 로그 스트림 없음"$'\n'
      fi
    done
    raw="${raw%$'\n'}"
    if [ -z "${unmatched// }" ]; then
      record 4.8 "인스턴스 로깅 설정" PASS "$raw" "ec2 describe-instances, logs describe-log-streams"
    else
      record 4.8 "인스턴스 로깅 설정" NA "$raw"$'\n'"# 미매칭=스트림명이 instance-id가 아닐 수 있음(에이전트 구성 수동 확인):${unmatched}" "logs describe-log-streams"
    fi
  fi

  # 4.9 RDS 로깅(CloudWatch export)
  if [ -z "$rds_list" ]; then
    record 4.9 "RDS 로깅 설정" PASS "(RDS 없음 — 해당 없음)" "rds describe-db-instances"
  else
    raw="$(aws_ro rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,EnabledCloudwatchLogsExports]' --output text | sed 's/\t/  CloudwatchLogsExports=/')"
    local rds_nolog
    rds_nolog=$(aws_ro rds describe-db-instances --query "DBInstances[?EnabledCloudwatchLogsExports==null].DBInstanceIdentifier" --output text)
    if [ -z "$rds_nolog" ]; then
      record 4.9 "RDS 로깅 설정" PASS "$raw" "rds describe-db-instances"
    else
      record 4.9 "RDS 로깅 설정" FAIL "$raw"$'\n'"# CloudWatch export 미설정:${rds_nolog}" "rds describe-db-instances"
    fi
  fi

  # 4.10 S3 버킷 로깅(서버 액세스 로깅)
  raw=""; local lg s3_nolog=""
  for b in $buckets; do
    lg=$(aws_ro s3api get-bucket-logging --bucket "$b" --query 'LoggingEnabled.TargetBucket' --output text)
    raw="${raw}${b}: ServerAccessLogging.TargetBucket=${lg:-None}"$'\n'
    { [ -z "$lg" ] || [ "$lg" = "None" ]; } && s3_nolog="$s3_nolog $b"
  done
  raw="${raw%$'\n'}"
  if [ -z "$buckets" ]; then
    record 4.10 "S3 버킷 로깅 설정" PASS "(S3 버킷 없음)" "s3api list-buckets"
  elif [ -z "${s3_nolog// }" ]; then
    record 4.10 "S3 버킷 로깅 설정" PASS "$raw" "s3api get-bucket-logging"
  else
    local eff="" exc=""
    for b in $s3_nolog; do if is_excepted "$EXCEPT_BUCKET" "$b"; then exc="$exc $b"; else eff="$eff $b"; fi; done
    if [ -z "${eff// }" ]; then
      record 4.10 "S3 버킷 로깅 설정" FAIL "$raw"$'\n'"# [조치 예외사항 - 구성상 필요]:${exc}" "s3api get-bucket-logging"
    else
      record 4.10 "S3 버킷 로깅 설정" FAIL "$raw"$'\n'"# 액세스 로깅 미설정:${eff}" "s3api get-bucket-logging"
    fi
  fi

  # 4.11 VPC 플로우 로깅
  raw=""; local vpcs v fl vpc_noflow=""
  vpcs=$(aws_ro ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text)
  for v in $vpcs; do
    fl=$(aws_ro ec2 describe-flow-logs --filter "Name=resource-id,Values=$v" --query 'FlowLogs[].FlowLogId' --output text)
    raw="${raw}${v}: FlowLogId=${fl:-(없음)}"$'\n'
    [ -z "$fl" ] && vpc_noflow="$vpc_noflow $v"
  done
  raw="${raw%$'\n'}"; [ -z "$raw" ] && raw="(VPC 없음)"
  if [ -z "${vpc_noflow// }" ]; then
    record 4.11 "VPC 플로우 로깅 설정" PASS "$raw" "ec2 describe-flow-logs"
  else
    record 4.11 "VPC 플로우 로깅 설정" FAIL "$raw"$'\n'"# 플로우 로그 미설정:${vpc_noflow}" "ec2 describe-flow-logs"
  fi

  # 4.12 로그 보관 기간(최소 1년)
  raw=""; local under1y="" name ret
  while read -r name ret; do
    [ -z "$name" ] && continue
    matches_except "$EXCEPT_LOG" "$name" && continue
    raw="${raw}${name}: retentionInDays=${ret}"$'\n'
    if [ "$ret" = "None" ] || [ -z "$ret" ]; then :   # 무제한 = 1년 이상 충족
    elif [ "$ret" -lt "${LOG_MIN_DAYS:-365}" ] 2>/dev/null; then under1y="$under1y ${name}(${ret}d)"; fi
  done < <(aws_ro logs describe-log-groups --query 'logGroups[].[logGroupName,retentionInDays]' --output text)
  raw="${raw%$'\n'}"
  if [ -z "$lg_all" ]; then
    record 4.12 "로그 보관 기간 설정" PASS "(로그 그룹 없음 — 보관기준 해당 없음)" "logs describe-log-groups"
  elif [ -z "${under1y// }" ]; then
    record 4.12 "로그 보관 기간 설정" PASS "$raw" "logs describe-log-groups"
  else
    record 4.12 "로그 보관 기간 설정" FAIL "$raw"$'\n'"# 1년 미만 보존:${under1y}" "logs describe-log-groups"
  fi

  # 4.13 백업 사용 여부
  local plans rds_bk
  plans=$(aws_ro backup list-backup-plans --query 'BackupPlansList[].[BackupPlanName,BackupPlanId]' --output text)
  rds_bk=""
  [ -n "$rds_list" ] && rds_bk=$(aws_ro rds describe-db-instances --query "DBInstances[?BackupRetentionPeriod>\`0\`].[DBInstanceIdentifier,BackupRetentionPeriod]" --output text)
  raw=""
  [ -n "$plans" ] && raw="# AWS Backup Plans"$'\n'"$(echo "$plans" | sed 's/\t/  id=/')"
  [ -n "$rds_bk" ] && raw="${raw}"$'\n'"# RDS 자동백업(보존일)"$'\n'"$(echo "$rds_bk" | sed 's/\t/  retention=/')"
  raw="$(echo "$raw" | grep -v '^$')"
  if [ -n "$plans" ] || [ -n "$rds_bk" ]; then
    record 4.13 "백업 사용 여부" PASS "$raw" "backup list-backup-plans, rds describe-db-instances"
  else
    record 4.13 "백업 사용 여부" FAIL "(AWS Backup 계획/RDS 자동백업 미발견)" "backup list-backup-plans, rds describe-db-instances"
  fi

  # 4.14~4.15 EKS : 클러스터 없으면 N/A
  local eks c enabled kms clog_off="" cenc_off="" raw14="" raw15=""
  eks=$(aws_ro eks list-clusters --query 'clusters' --output text)
  if [ -z "$eks" ]; then
    record 4.14 "EKS Cluster 제어 플레인 로깅 설정" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
    record 4.15 "EKS Cluster 암호화 설정" NA "(EKS 클러스터 없음 — 진단 대상 아님)" "eks list-clusters"
  else
    for c in $eks; do
      enabled=$(aws_ro eks describe-cluster --name "$c" --query "cluster.logging.clusterLogging[?enabled==\`true\`].types" --output text)
      raw14="${raw14}${c}: enabledLogTypes=[${enabled:-없음}]"$'\n'
      [ -z "$enabled" ] && clog_off="$clog_off $c"
      kms=$(aws_ro eks describe-cluster --name "$c" --query 'cluster.encryptionConfig' --output text)
      raw15="${raw15}${c}: encryptionConfig=[${kms:-없음}]"$'\n'
      { [ -z "$kms" ] || [ "$kms" = "None" ]; } && cenc_off="$cenc_off $c"
    done
    raw14="${raw14%$'\n'}"; raw15="${raw15%$'\n'}"
    if [ -z "${clog_off// }" ]; then record 4.14 "EKS Cluster 제어 플레인 로깅 설정" PASS "$raw14" "eks describe-cluster"
    else record 4.14 "EKS Cluster 제어 플레인 로깅 설정" FAIL "$raw14"$'\n'"# 로깅 미설정:${clog_off}" "eks describe-cluster"; fi
    if [ -z "${cenc_off// }" ]; then record 4.15 "EKS Cluster 암호화 설정" PASS "$raw15" "eks describe-cluster"
    else record 4.15 "EKS Cluster 암호화 설정" FAIL "$raw15"$'\n'"# 암호화 미설정:${cenc_off}" "eks describe-cluster"; fi
  fi
}

# =============================================================
# 7. 메인
# =============================================================
echo "================================================================"
echo " SK쉴더스 AWS 클라우드 보안 자동 진단 (2024 가이드)"
echo " 읽기전용 · 판단기준=PDF 양호/취약 원문 · EKS는 N/A"
echo "================================================================"
preflight
NOW="$(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "진단 주체 : ${WHOAMI}"
echo "대상 계정 : ${ACCOUNT_ID}   리전 : ${REGION_EFF:-(미지정)}   진단대상 : ${TARGET_SYS}"
echo "점검 시각 : ${NOW}   설정파일 : ${CONF}"

run_has(){ echo ",$CATS," | grep -q ",$1,"; }
run_has 1 && check_account
run_has 2 && check_iam_policy
run_has 3 && check_resource
run_has 4 && check_operation

TOTAL=$((PASS_CNT+FAIL_CNT+NA_CNT))

# ---- 산출물 저장 (CSV 11컬럼 + 보고서 TXT) ----
HISTORY=""; RAW_CSV=""
if [ -n "$OUTDIR" ]; then
  mkdir -p "$OUTDIR"
  TS="$(date +%Y%m%d_%H%M%S)"
  LABEL="${ACCOUNT_ID:-unknown}"
  RAW_CSV="$OUTDIR/cloud_diag_raw_${LABEL}_${TS}.csv"
  HISTORY="$OUTDIR/cloud_diag_history_${LABEL}_${TS}.txt"

  # CSV: UTF-8 BOM + 13컬럼 (조치방법 삽입 + 진단대상 시트용 호스트명/버전정보 — 첫 행에만)
  #  클라우드는 호스트/OS 없음 → 호스트명 공란, 버전정보는 'AWS'(진단대상=계정).
  { printf '\xEF\xBB\xBF'
    echo "항목코드,분류,항목,판단기준,결과,점검내용,조치방법,진단대상,진단대상IP,중요도,점검파일,호스트명,버전정보"
    _n=0
    for i in "${!F_CODE[@]}"; do
      if [ "$_n" -eq 0 ]; then _h=""; _v="AWS"; else _h=""; _v=""; fi; _n=$((_n+1))
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_field "${F_CODE[$i]}")" "$(csv_field "${F_CAT[$i]}")" "$(csv_field "${F_NAME[$i]}")" \
        "$(csv_field "${F_STD[$i]}")" "$(csv_field "${F_RESULT[$i]}")" "$(csv_field "${F_RAW[$i]}")" \
        "$(csv_field "${F_FIX[$i]}")" \
        "$(csv_field "$TARGET_SYS")" "$(csv_field "$IP_ADDR")" "$(csv_field "${F_SEV[$i]}")" \
        "$(csv_field "${F_FILE[$i]}")" "$(csv_field "$_h")" "$(csv_field "$_v")"
    done
  } > "$RAW_CSV"

  # 보고서 TXT: 사전정보 헤더 + emit_screen 블록 (화면과 동일 양식)
  { echo "================ AWS 클라우드 보안 자동 진단 보고서 ================"
    echo "기준      : SK쉴더스 2024 클라우드 보안가이드(AWS)"
    echo "진단대상  : ${TARGET_SYS}   (Account ${ACCOUNT_ID} / Region ${REGION_EFF:-미지정})"
    echo "진단 주체 : ${WHOAMI}"
    echo "점검 시각 : ${NOW} (KST)"
    echo "설정 파일 : ${CONF}"
    echo "요약      : 총 ${TOTAL}  양호 ${PASS_CNT}  취약 ${FAIL_CNT}  N/A ${NA_CNT}"
    echo "=================================================================="
    echo
    for i in "${!F_CODE[@]}"; do
      emit_screen "${F_CODE[$i]}" "${F_SEV[$i]}" "${F_NAME[$i]}" "${F_STD[$i]}" "${F_RESULT[$i]}" "${F_RAW[$i]}" "${F_FILE[$i]}"
    done
  } > "$HISTORY"
fi

# ---- 종합 요약 (다른 진단 스크립트와 동일 양식) ----
echo "================================================================"
printf "[종합] 총 %d개 | 양호 %d | 취약 %d | N/A %d\n" "$TOTAL" "$PASS_CNT" "$FAIL_CNT" "$NA_CNT"
if [ -n "$OUTDIR" ]; then
  echo " 로우데이터(CSV) : $RAW_CSV"
  echo " 히스토리(TXT)   : $HISTORY"
fi
echo "진단 스크립트 종료"

[ "$FAIL_CNT" -gt 0 ] && exit 1 || exit 0
