# security-diag — 주요정보통신기반시설 자동 보안진단

KISA 2026 「주요정보통신기반시설 기술적 취약점 분석·평가」 기준의 **읽기전용(READ-ONLY)** 자동 진단 스크립트 모음.
대상 호스트에 배포해 실행하면 항목별 `양호 / 취약 / N/A` 판정과 **로우데이터(CSV) + 히스토리(TXT)** 를 생성한다.
설정은 변경하지 않으며 `cat/grep/stat/ls/ps/systemctl(조회)/aws describe·list·get` 등 조회 명령만 사용한다.

> 최종 목표: 각 호스트 로우데이터(CSV) → LLM 판정 → 대시보드 + 엑셀 보고서 파이프라인.

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

호스트 별칭은 `~/.ssh/config` 에 정의(bastion·webserver·was·db-tunnel). was는 bastion `ProxyJump` 경유(사설망).

---

## 배포·실행·회수 (리눅스 계열)

SSH로 **고정 디렉토리 `~/diag_run/`** 에 영역별 하위 폴더로 배포하고, 실행 후 산출물을 로컬로 회수한다.
재배포 시 과거 기록(`~/diag_run`·구 배포물)은 삭제하고 새로 만든다.

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

공통 옵션: `-c <설정파일>` · `-o <출력디렉터리>` (linux/web/was), cloud_diag는 추가로 `-p <profile>` `-r <region>` `-k <영역>`.
sudo는 root 소유 설정 파일 조회용. 산출물은 회수 전 로그인 유저로 `chown`.

### 산출물 보관(로컬)

회수 결과는 각 영역 폴더의 result 디렉토리에 둔다 — `linux-diag/result_{bastion,was,web}/`,
`web-diag/result_web/`, `was-diag/result_was/`, `cloud_diag/cloud_diag_result/`.

> ⚠️ **결과물은 비공개**: 실 호스트 IP·설정을 포함하므로 `.gitignore`(`result_*/`, `*_result/`)로 **레포에 올리지 않는다.**

---

## cloud_diag (AWS) 보충

- **기준:** SK쉴더스 2024 클라우드 보안가이드(AWS) — 계정13·권한3·리소스10·운영15 (41항목). EKS는 클러스터 없으면 N/A.
- **동작:** `describe`/`list`/`get`/`lookup` 등 읽기전용 AWS CLI만. 설정 변경 없음.
- **사전:** AWS CLI v2 + 자격증명(프로파일/Instance Profile). `ReadOnlyAccess` 또는 `SecurityAudit` 권장
  (계정 영역은 `iam:GenerateCredentialReport`/`GetCredentialReport` 필요).
- **실행:** `bash cloud_diag.sh -p <profile> -r <region> -k 1,3 -o ./cloud_diag_result`
- **설정(`cloud_diag.conf`):** `SCENARIO_USERS`(점검 IAM 사용자, 비우면 전체) · `EXCEPT_*`(예외 표기) ·
  임계값 `PW_MIN_LEN`/`PW_MAX_AGE`/`KEY_MAX_DAYS`/`STALE_DAYS`/`LOG_MIN_DAYS`.
- **판정 모델:** KISA 파일/권한 기반이 아닌 **AWS API 기반** — 증적은 CLI 출력의 핵심필드 원문, API로
  판정 불가한 항목(키페어 보관위치, 역할 적정성, TLS 등)은 "무조건 양호" 금지하고 **N/A(수동/AI 확인)**.

---

## 산출물 형식

- **로우데이터** `*_raw_<label>_<ts>.csv` — UTF-8(BOM), 11컬럼
  `항목코드,분류,항목,판단기준,결과,점검내용,조치방법,진단대상,진단대상IP,중요도,점검파일`
  - `판단기준` = 기준 문서의 `양호/취약` 원문, `점검내용` = 점검에 쓴 명령 출력 **원문 라인**(가공 ❌)
- **히스토리** `*_history_<label>_<ts>.txt` — 사전정보 헤더 + 항목별 화면 양식 블록.

종료코드: 취약(FAIL) 1건 이상 `1`, 아니면 `0` (CI 연동용).

---

## CRLF 주의 (.gitattributes 권장)

Windows에서 체크아웃하면 `*.sh`/`*.conf`가 CRLF로 변환돼 리눅스 bash 실행이 깨진다.
레포에 다음을 두면 LF로 고정된다:

```gitattributes
*.sh   text eol=lf
*.conf text eol=lf
```

배포 직후 `sed -i 's/\r$//'`로 정규화하는 방법도 가능(위 예시 참고).
