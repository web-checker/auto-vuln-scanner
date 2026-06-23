# auto-vuln-scanner

KISA **주요정보통신기반시설 기술적 취약점 분석·평가** 기준 5개 분야 **자동진단 스크립트 모음**.
대상 호스트에서 **읽기 전용(READ-ONLY)** 으로 실행하면, 표준 형식의 로우데이터(CSV)와
사람이 읽는 보고서(TXT)를 생성한다.

> 생성된 CSV를 LLM으로 교차판정·보고서화하려면
> [ai-vuln-scanner](https://github.com/web-checker/ai-vuln-scanner) 참고.

## 분야 / 항목

| 분야 | 스크립트 | 항목 코드 | 실행 |
|------|----------|-----------|------|
| Unix / Linux 서버 | `linux-diag/linux_diag.sh` | U-01 ~ U-67 | bash (sudo) |
| WAS (Apache Tomcat) | `was-diag/was_diag.sh` | WEB-01 ~ WEB-26 | bash |
| Apache 웹서버 | `web-diag/web_diag.sh` | WEB-01 ~ WEB-26 | bash |
| Windows 서버 | `win_diag/win_diag.ps1` | W-01 ~ W-64 | PowerShell |
| DBMS | `DB_diag/dbms_diag.ps1` | D-01 ~ D-26 | PowerShell |

## 핵심 원칙

- **읽기 전용** — `cat / grep / stat / ls / ps / find / systemctl(상태조회)` 등만 사용. 설정·파일을 변경하지 않음.
- **판정값 3가지** — `양호` / `취약` / `N/A`. 자동화 한계 항목은 근거와 함께 **수동 확인** 표기.
- **KISA 지정 control 정확 검증** — 인접 proxy로 대체하지 않고, 항목이 요구하는 정확한 대상만 점검.

## 출력 형식

- **로우데이터** `*_raw_<대상>_<시각>.csv` — 10열, UTF-8 BOM, 항목별 **전체 증적**.
- **보고서** `*_report_<대상>_<시각>.txt` — 8줄 요약, 판단기준은 **KISA 원문 그대로**.
- 결과물은 각 분야의 `result_*/`·`*_result/`에 생성되며, 실 호스트 정보(IP·설정)를 담아
  **`.gitignore`로 레포에서 제외**한다(스크립트만 버전관리).

## 사용법

스크립트·설정(`*.conf`)을 대상 호스트에 올린 뒤 **로컬에서 실행**한다.

```bash
# Linux 예시 — conf로 환경(경로·계정 등) 지정, 출력 디렉터리 선택
cd linux-diag
sudo ./linux_diag.sh -c linux_diag_was.conf -o result_was

# WAS(Tomcat) / Apache — 각 분야 디렉터리에서 conf 설정 후 실행
cd was-diag && ./was_diag.sh
```

```powershell
# Windows / DBMS — PowerShell(관리자)
cd win_diag ;  .\win_diag.ps1
cd DB_diag  ;  .\dbms_diag.ps1
```

환경 의존 값(경로·계정·호스트명 등)은 전부 분야별 `*.conf`에서 입력한다.
Linux는 호스트별 conf(`linux_diag_bastion.conf` / `_was.conf` / `_webserver.conf`)를 제공한다.

## 문서

- `DIAG_STYLE.md` — 출력 스타일·판정 표기 규약
- `OUTPUT_REFORMAT_GUIDE.md` — 출력 포맷 마이그레이션 가이드(신규 스크립트 작성 시 기준)
- 각 분야 디렉터리의 `README.md`(예: `was-diag/README.md` — 점검 범위·한계 상세)
