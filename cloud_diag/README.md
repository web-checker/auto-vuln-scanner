# cloud_diag — AWS 클라우드 보안 자동 진단

**기준:** SK쉴더스 2024 클라우드 보안가이드(AWS) — `클라우드 보안 가이드_AWS.pdf` (※ KISA 아님)
**범위:** 4개 영역 41개 항목(계정13·권한3·리소스10·운영15). EKS 항목은 클러스터 미존재 시 N/A.
**동작:** 읽기전용(`describe`/`list`/`get`/`lookup`) AWS CLI 호출만 사용. 설정 변경 없음.

출력 양식은 `../DIAG_STYLE.md` · `../OUTPUT_REFORMAT_GUIDE.md` 를 따른다(10컬럼 CSV + emit_screen 보고서).

---

## 파일 구성

```
cloud_diag/
  cloud_diag.sh        # 진단 본체 (읽기전용)
  cloud_diag.conf      # 환경 의존값(프로파일·리전·시나리오·예외·임계값)
  result_cloud/        # 산출물(raw CSV + report TXT)
  README.md
```

## 사전 요구사항

- AWS CLI v2 설치 및 자격증명 구성(`aws configure` 또는 프로파일/Instance Profile).
- 권한: 읽기전용 점검에 필요한 `ReadOnlyAccess`(또는 `SecurityAudit`) 수준 권장.
  - 특히 `iam:GenerateCredentialReport`, `iam:GetCredentialReport` 필요(계정 영역).

## 실행

```bash
# 전체 점검 + 산출물 저장
bash cloud_diag.sh -o ./result_cloud

# 프로파일/리전 지정, 특정 영역(1=계정 3=리소스)만
bash cloud_diag.sh -p audit -r ap-northeast-2 -k 1,3 -o ./result_cloud
```

| 옵션 | 설명 |
|---|---|
| `-c, --conf <file>` | 설정 파일(기본: 스크립트 옆 `cloud_diag.conf`) |
| `-p, --profile <name>` | AWS 프로파일(conf보다 우선) |
| `-r, --region <name>` | 리전(conf보다 우선) |
| `-k, --category <n>` | 영역만 점검 `1`계정 `2`권한 `3`리소스 `4`운영 (콤마) |
| `-o, --output <dir>` | 산출물 저장 디렉터리 |

종료코드: 취약(FAIL) 1건 이상이면 `1`, 아니면 `0` (CI 연동용).

## 설정(`cloud_diag.conf`)

`DIAG_STYLE §6` 규칙(선언=사용)을 따른다. 환경 의존값만 분리:

- `SCENARIO_USERS` — 점검 대상 IAM 사용자 화이트리스트. **비우면 전체 사용자**(범용 기본값).
- `EXCEPT_SG` / `EXCEPT_BUCKET` — 취약으로 잡되 `[조치 예외사항]`으로 표기할 리소스.
- `EXCEPT_LOG` — 로그 보관 점검(4.12)에서 제외할 로그 그룹 패턴(부분일치).
- 임계값: `PW_MIN_LEN`(8) · `PW_MAX_AGE`(90) · `KEY_MAX_DAYS`(60) · `STALE_DAYS`(90) · `LOG_MIN_DAYS`(365).

## 산출물

`result_cloud/` 에 2종:

- **로우데이터** `cloud_diag_raw_<account>_<ts>.csv` — UTF-8 BOM, 11컬럼
  `항목코드,분류,항목,판단기준,결과,점검내용,조치방법,진단대상,진단대상IP,중요도,점검파일`
  - `판단기준` = PDF `양호 : … | 취약 : …` 원문
  - `조치방법` = 항목별 한 줄 조치(대시보드 표시용, `FIX[code]` 배열). 양호 상태를 달성하는 조치
  - `점검내용` = 점검에 사용한 AWS CLI 핵심필드 **원문 라인**(가공 문장 ❌)
  - `진단대상` = `Cloud(AWS)`, `진단대상IP` = Account ID(클라우드는 호스트 IP 없음)
  - `점검파일` = 증적 수집에 쓴 AWS API(예 `iam list-users`) — 파일 대신 API 표기
- **보고서** `cloud_diag_report_<account>_<ts>.txt` — 사전정보 헤더 + 항목별 `emit_screen` 블록(화면과 동일 양식, 점검요약 8줄 절단).

## 판정 모델 (KISA 파일기반과 다른 점)

이 진단은 KISA 주요정보통신기반시설(파일/권한 기반)이 아니라 **AWS API 기반**이라 다음을 적용했다:

- **판단기준 원문** = 위 SK쉴더스 PDF의 `양호기준`/`취약기준`(STD_PASS/STD_VULN).
- **분류** = PDF 대분류(계정 관리 / 권한 관리 / 가상 리소스 관리 / 운영 관리).
- **증적** = `grep 라인`·`stat 권한` 대신 **CLI describe/list/get 출력의 핵심필드 원문 라인**.
- **API로 판정 불가한 항목은 N/A(수동/AI 확인)** — "무조건 양호" 스텁 금지(DIAG_STYLE §4):
  - 1.5/1.6 Key Pair 접근수단·보관위치, 2.x 서비스 역할 적정성, 3.4/3.8/3.10 의도성 판단,
    4.4 통신구간 TLS, 4.8 인스턴스 로깅(에이전트 영역) 등.
  - 단, 명백한 객관 위반(과다권한 역할, 미연결 IGW 등)은 자동 **취약**.
- **EKS(1.11~1.13/3.9/4.14/4.15)** = 클러스터 내부(kubectl/RBAC)는 API 밖이라, 클러스터 존재 시
  관측 가능한 메타만 수록 후 N/A. 클러스터 없으면 진단 대상 아님 N/A.

> ⚠️ 검증 필요: 본 스크립트의 자동 판정은 가이드 '점검·조치 사례'와의 대조를 거쳐야 한다.
> 실제 계정에 배포·실행한 산출물로 항목별 판정 방향을 PDF와 재확인할 것.

## 배포·실행·회수 (예: bastion)

```bash
ssh bastion 'rm -rf ~/cloud_diag.sh ~/cloud_diag.conf ~/result_cloud'
scp cloud_diag.sh cloud_diag.conf bastion:~/
ssh bastion 'cd ~ && bash cloud_diag.sh -o ~/result_cloud'
scp 'bastion:~/result_cloud/*' result_cloud/
```
