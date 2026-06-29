# security-diag — 주요정보통신기반시설 자동 보안진단

[![repo: auto-vuln-scanner](https://img.shields.io/badge/repo-auto--vuln--scanner-2ea44f?style=flat-square)](https://github.com/web-checker/auto-vuln-scanner)
[![mode: READ-ONLY](https://img.shields.io/badge/mode-READ--ONLY-blue?style=flat-square)](#개요)
[![shell: bash + PowerShell](https://img.shields.io/badge/shell-bash%20%2B%20PowerShell-89e051?style=flat-square)](#진단-영역--대상-호스트)
[![purpose: educational](https://img.shields.io/badge/purpose-educational-lightgrey?style=flat-square)](#라이선스--용도)

KISA 2026 「주요정보통신기반시설 기술적 취약점 분석·평가」 기준의 **읽기전용(READ-ONLY)** 자동 진단 스크립트 모음입니다. 대상 호스트에 배포해 실행하면 항목별 `양호 / 취약 / N/A` 판정과 **로우데이터(CSV) + 히스토리(TXT)** 를 생성합니다. 설정은 변경하지 않으며 `cat/grep/stat/ls/ps/systemctl(조회)/aws describe·list·get` 등 조회 명령만 사용합니다.

> 최종 목표는 각 호스트 로우데이터(CSV) → LLM 판정 → 대시보드 + 엑셀 보고서 파이프라인입니다. LLM 판정 단계는 별도 저장소 [`ai-vuln-scanner`](https://github.com/web-checker/ai-vuln-scanner)에서 담당합니다([관련 저장소](#관련-저장소) 참고).

---

## 목차

- [진단 영역 ↔ 대상 호스트](#진단-영역--대상-호스트)
- [배포·실행·회수 (리눅스 계열)](#배포실행회수-리눅스-계열)
- [cloud_diag (AWS) 보충](#cloud_diag-aws-보충)
- [산출물 형식](#산출물-형식)
- [CRLF 주의](#crlf-주의)
- [관련 저장소](#관련-저장소)
- [기여](#기여)
- [라이선스 / 용도](#라이선스--용도)

---

## 진단 영역 ↔ 대상 호스트

| 영역(suite) | 스크립트 | 기준 | 대상 호스트 | 비고 |
|---|---|---|---|---|
| **linux-diag** | `linux_diag.sh` | KISA UNIX `U-01~67` | bastion · webserver · was | 호스트별 `linux_diag_<host>.conf` (sudo) |
| **web-diag** | `web_diag.sh` | KISA 웹 `WEB-01~26` | webserver | Apache HTTP 2.4 (sudo) |
| **was-diag** | `was_diag.sh` | KISA 웹 `WEB-01~26` | was | Apache Tomcat 9 (sudo) |
| **cloud_diag** | `cloud_diag.sh` | SK쉴더스 2024 AWS 가이드 (4영역 41항목) | AWS 계정 | AWS CLI v2, 자격증명/콘솔 필요 |
| **DB_diag** | `dbms_diag.ps1` | KISA DBMS `D-01~26` | db (Windows) | PowerShell / RDP |
| **win_diag** | `win_diag.ps1` | KISA Windows `W-01~64` | (Windows) | PowerShell / RDP |

호스트 별칭은 `~/.ssh/config` 에 정의합니다(bastion·webserver·was·db-tunnel). was는 bastion `ProxyJump`를 경유합니다(사설망).

---

## 배포·실행·회수 (리눅스 계열)

SSH로 **고정 디렉토리 `~/diag_run/`** 에 영역별 하위 폴더로 배포하고, 실행 후 산출물을 로컬로 회수합니다. 재배포 시 과거 기록(`~/diag_run`·구 배포물)은 삭제하고 새로 만듭니다.

```bash
# 예: webserver — linux_diag + web_diag
ssh webserver 'sudo rm -rf ~/diag_run ~/linux_diag ~/web_diag* ~/*_result; \
               mkdir -p ~/diag_run/linux_diag/result ~/diag_run/web_diag/result'
scp linux-diag/linux_diag.sh linux-diag/linux_diag_webserver.conf webserver:diag_run/linux_diag/
scp web-diag/web_diag.sh web-diag/web_diag.conf                    webserver:diag_run/web_diag/

# CRLF 정규화(레포 체크아웃이 CRLF면 리눅스 bash가 깨짐 — 아래 .gitattributes 참고)
ssh webserver 'find ~/diag_run -type f \( -name "*.sh" -o -name "*.conf" \) -exec sed -i "s/\r$//" {} +'

ssh webserver 'cd ~/diag_run/linux_diag && sudo bash linux_diag.sh -c linux_diag_webserver.conf -o result'
ssh webserver 'cd ~/diag_run/web_diag   && sudo bash web_diag.sh   -c web_diag.conf            -o result; \
               sudo chown -R ubuntu:ubuntu ~/diag_run'
scp 'webserver:diag_run/linux_diag/result/*' linux-diag/result_web/
scp 'webserver:diag_run/web_diag/result/*'   web-diag/result_web/
```

공통 옵션은 `-c <설정파일>` · `-o <출력디렉터리>` 입니다(linux/web/was). cloud_diag는 추가로 `-p <profile>` `-r <region>` `-k <영역>` 을 받습니다. sudo는 root 소유 설정 파일 조회용이며, 산출물은 회수 전 로그인 유저로 `chown` 합니다.

### 산출물 보관(로컬)

회수 결과는 각 영역 폴더의 result 디렉토리에 둡니다 — `linux-diag/result_{bastion,was,web}/`, `web-diag/result_web/`, `was-diag/result_was/`, `cloud_diag/cloud_diag_result/`.

> 주의 — **결과물은 비공개**입니다: 실 호스트 IP·설정을 포함하므로 `.gitignore`(`result_*/`, `*_result/`)로 **레포에 올리지 않습니다.**

---

## cloud_diag (AWS) 보충

- **기준**: SK쉴더스 2024 클라우드 보안가이드(AWS) — 계정13·권한3·리소스10·운영15 (41항목). EKS는 클러스터가 없으면 N/A로 판정합니다.
- **동작**: `describe`/`list`/`get`/`lookup` 등 읽기전용 AWS CLI만 사용하며, 설정은 변경하지 않습니다.
- **사전 요건**: AWS CLI v2 + 자격증명(프로파일/Instance Profile). `ReadOnlyAccess` 또는 `SecurityAudit`를 권장합니다(계정 영역은 `iam:GenerateCredentialReport`/`GetCredentialReport` 필요).
- **실행**: `bash cloud_diag.sh -p <profile> -r <region> -k 1,3 -o ./cloud_diag_result`
- **설정(`cloud_diag.conf`)**: `SCENARIO_USERS`(점검 IAM 사용자, 비우면 전체) · `EXCEPT_*`(예외 표기) · 임계값 `PW_MIN_LEN`/`PW_MAX_AGE`/`KEY_MAX_DAYS`/`STALE_DAYS`/`LOG_MIN_DAYS`.
- **판정 모델**: KISA 파일/권한 기반이 아닌 **AWS API 기반**입니다. 증적은 CLI 출력의 핵심필드 원문이며, API로 판정 불가한 항목(키페어 보관위치, 역할 적정성, TLS 등)은 "무조건 양호"로 두지 않고 **N/A(수동/AI 확인)** 로 표기합니다.

---

## 산출물 형식

- **로우데이터** `*_raw_<label>_<ts>.csv` — UTF-8(BOM), 11컬럼
  `항목코드,분류,항목,판단기준,결과,점검내용,조치방법,진단대상,진단대상IP,중요도,점검파일`
  - `판단기준` = 기준 문서의 `양호/취약` 원문, `점검내용` = 점검에 쓴 명령 출력 **원문 라인**(가공하지 않음)
- **히스토리** `*_history_<label>_<ts>.txt` — 사전정보 헤더 + 항목별 화면 양식 블록.

종료코드는 취약(FAIL) 1건 이상이면 `1`, 아니면 `0` 입니다(CI 연동용).

---

## CRLF 주의

Windows에서 체크아웃하면 `*.sh`/`*.conf`가 CRLF로 변환돼 리눅스 bash 실행이 깨집니다. 레포에 다음 `.gitattributes`를 두면 LF로 고정됩니다.

```gitattributes
*.sh   text eol=lf
*.conf text eol=lf
```

배포 직후 `sed -i 's/\r$//'`로 정규화하는 방법도 가능합니다(위 예시 참고).

---

## 관련 저장소

본 프로젝트(web-checker)는 여러 저장소로 구성됩니다(다중 저장소는 서로 README를 링크합니다).

| 저장소 | 역할 |
| --- | --- |
| [web-checker/auto-vuln-scanner](https://github.com/web-checker/auto-vuln-scanner) | 본 저장소 — KISA 자동 진단 스크립트 모음(로우데이터 CSV 생성) |
| [web-checker/ai-vuln-scanner](https://github.com/web-checker/ai-vuln-scanner) | AI 교차 진단 대시보드(로우데이터 → LLM 판정 → 보고서) |
| [web-checker/checkbang](https://github.com/web-checker/checkbang) | 교육용 취약 버전 도서 쇼핑몰 |
| [web-checker/checkbang-secure](https://github.com/web-checker/checkbang-secure) | 보안 버전 도서 쇼핑몰 |

---

## 기여

- 브랜치/커밋 규칙은 프로젝트 가이드라인의 **Git 워크플로우**(feature 브랜치 작업, `main` 직접 푸시 금지, 제목/본문 분리 커밋)를 따릅니다.
  ```sh
  git checkout -b feature/<작업명>
  ```
- 스크립트는 **읽기전용 원칙**을 지킵니다 — 설정 변경 명령을 추가하지 않습니다.
- 산출물(`result_*/`, `*_result/`)은 실 호스트 정보를 포함하므로 커밋하지 않습니다.

---

## 라이선스 / 용도

본 프로젝트는 **교육 및 인가된 보안 진단 실습** 목적입니다. 진단은 반드시 인가된 대상에만 수행합니다.
