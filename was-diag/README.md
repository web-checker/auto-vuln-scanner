# WAS(Tomcat) 자동 진단 스크립트

KISA **2026 주요정보통신기반시설 기술적 취약점 분석·평가 — 웹 서비스(WEB-01~26)** 기준으로
WAS(Apache Tomcat 9)의 설정을 **읽기 전용**으로 점검한다.

> 웹서버(Apache/Nginx/IIS/WebtoB) 진단은 별도 스크립트로 분리. 본 스크립트는 **WAS = Tomcat** 전용.

## 구성 파일

| 파일 | 설명 |
|------|------|
| `was_diag.sh` | 진단 본체 (bash, 읽기 전용) |
| `was_diag.conf` | 환경 설정 — 핵심 자료 위치·관리자 계정명 등 입력 |
| `README.md` | 본 문서 |

## 점검 범위 (중요)

본 스크립트는 KISA 가이드에 명시된 대로 **Tomcat 컨테이너 설정(`conf/`)만** 점검한다:
`conf/server.xml`, `conf/web.xml`, `conf/context.xml`, `conf/tomcat-users.xml`.

**앱 레벨 설정은 범위 외**다 — 배포된 WAR 내부의 `WEB-INF/web.xml`, Spring 설정(`WEB-INF/classes/config/spring/*.xml`), `app.properties` 등은 점검하지 않는다. 따라서:

- 예) **WEB-13(DB 연결정보) "양호"** 는 *컨테이너(server.xml/context.xml)에 노출된 JNDI Resource가 없다*는 의미일 뿐, **앱이 Spring DataSource·app.properties에 보관한 DB 자격증명의 안전성을 보증하지 않는다.**
- WEB-04/08/15/19도 앱 `WEB-INF/web.xml`의 override/추가 설정은 보지 않는다.
- 앱 레벨 점검이 필요하면 별도의 **웹 애플리케이션 진단**으로 수행한다.

또한 KISA가 "**불필요한** X 제거"라고 한 항목(WEB-10/13/15/17)의 *불필요 여부*는 앱 사용 맥락이 필요해 자동 판정 불가 → 존재 사실·접근통제만 점검하고 필요 여부는 **수동 확인** 대상으로 남긴다.

## 핵심 원칙

- **읽기 전용**: `cat / grep / stat / ls / ps / systemctl show` 만 사용. 어떤 설정·파일도 변경하지 않음.
- **판정값은 3가지뿐**: `양호` / `취약` / `N/A`.
- **출력 2종**:
  - 외부 진단용 **로우데이터** `was_diag_raw_<대상>_<시각>.csv`
  - 사람이 읽는 **보고서** `was_diag_report_<대상>_<시각>.txt`
- 경로·계정 등 환경 의존 값은 전부 `was_diag.conf` 에서 입력.

## 사용법

WAS(Private) 서버에 스크립트·설정을 올린 뒤 **WAS 로컬에서 실행**한다.

```bash
# 1) WAS 서버로 전송 (로컬 PC, PowerShell 예시)
scp deploy/was-diag/was_diag.sh  deploy/was-diag/was_diag.conf  was:/home/ubuntu/

# 2) WAS 접속 후 실행 (conf 파일이 root:600 인 경우가 많아 sudo 권장 — 읽기 목적)
ssh was
chmod +x ~/was_diag.sh
sudo ~/was_diag.sh -c ~/was_diag.conf

# 결과 회수 (로컬 PC)
scp 'was:~/was_diag_result/*' ./
```

### 옵션

```
sudo ./was_diag.sh [-c 설정파일] [-o 출력디렉터리]
  -c   설정 파일 경로 (기본: 스크립트와 같은 폴더의 was_diag.conf)
  -o   결과 저장 디렉터리 (기본: 설정의 OUTPUT_DIR)
```

> `sudo` 권장 이유: `tomcat-users.xml`·`server.xml` 등이 `600/640`이면 일반 사용자가 내용을
> 못 읽어 해당 항목이 `N/A`(읽기 불가)로 빠진다. 권한 자체(stat)는 sudo 없이도 확인되므로
> WEB-03/14/26 권한 점검은 sudo 없이도 동작한다.

## 설정값(`was_diag.conf`) 요약

| 키 | 용도 | 관련 항목 |
|----|------|-----------|
| `CATALINA_HOME` / `CONF_DIR` / `WEBAPPS_DIR` / `LOG_DIR` | 핵심 자료 위치 | 전체 |
| `SERVER_XML` `WEB_XML` `CONTEXT_XML` `TOMCAT_USERS_XML` | 점검 대상 설정 파일 | 전체 |
| `ADMIN_USER_NAMES` / `DEFAULT_ADMIN_NAMES` | 정상/기본 관리자 계정명 | WEB-01 |
| `WEAK_PASSWORDS` | 취약 비밀번호 - 사전 단어(부분일치) | WEB-02 |
| `WEAK_PASSWORD_REGEX` | 취약 비밀번호 - **정규표현식(ERE/PCRE) 패턴 배열** | WEB-02 |
| `TOMCAT_SERVICE` / `EXPECTED_RUN_USERS` / `ADMIN_RUN_USERS` | 구동 계정 판정 | WEB-09 |
| `UPLOAD_DIR` | 업로드 경로(웹루트 내부 여부) | WEB-24 |
| `MIN_TOMCAT_VERSION` | 패치 기준 버전 | WEB-25 |
| `*_MAX_PERM` | 권한 기준값(8진수) | WEB-03/13/14/26 |
| `OUTPUT_DIR` / `TARGET_LABEL` | 결과 출력 | 출력 |

## 점검 항목 & 판정 방식 (Tomcat 기준)

| 코드 | 항목 | 자동 점검 방식 |
|------|------|----------------|
| WEB-01 | Default 관리자 계정명 | `tomcat-users.xml` 활성 manager-* 역할 계정명이 기본명인지 |
| WEB-02 | 취약한 비밀번호 | 평문 PW를 ①사전단어 ②정규식 패턴 ③ID포함 으로 검사 + Realm digest 적용 여부 |
| WEB-03 | 비밀번호 파일 권한 | `tomcat-users.xml` 권한 ≤ 600 |
| WEB-04 | 디렉터리 리스팅 | `web.xml` DefaultServlet `listings` = false |
| WEB-05 | CGI 실행 제한 | `web.xml` CGIServlet 매핑 활성 여부(주석 제외) |
| WEB-06 | 상위 디렉터리 접근 | `allowLinking=true` 미설정 |
| WEB-07 | 불필요 파일 | `docs/examples/manager/host-manager` 등 존재 여부 |
| WEB-08 | 업/다운로드 용량 | `maxPostSize`/`multipart-config` 제한 존재 |
| WEB-09 | 프로세스 권한 | 구동 계정이 root 등 관리자 권한인지 |
| WEB-10 | 불필요 프록시 | Connector `proxyName/proxyPort` 존재 여부 |
| WEB-11 | 경로 설정 | `appBase` 확인(표준 레이아웃, 수동 확인 권장) |
| WEB-12 | 링크 사용 금지 | `allowLinking`/Resources 링크 허용 여부 |
| WEB-13 | 설정 파일 노출 | DB 연결 리소스 + 설정파일 권한 |
| WEB-14 | 경로 내 파일 접근통제 | 설정파일 other 접근 권한 |
| WEB-15 | 불필요 스크립트 매핑 | cgi/ssi 서블릿 매핑(주석 제외) |
| WEB-16 | 헤더 정보 노출 | Connector `server` 속성 / `showServerInfo=false` |
| WEB-17 | 가상 디렉터리 | `server.xml` 내 `<Context path=...>` |
| **WEB-18** | **WebDAV 비활성화** | **N/A — Tomcat 점검 대상 아님(웹서버 항목)** |
| WEB-19 | SSI 사용 제한 | SSI 서블릿/필터 매핑(주석 제외) |
| **WEB-20** | **SSL/TLS 활성화** | **N/A — Tomcat 점검 대상 아님(앞단 Apache 종단)** |
| **WEB-21** | **HTTP 리디렉션** | **N/A — Tomcat 점검 대상 아님** |
| WEB-22 | 에러 페이지 관리 | `web.xml` `<error-page>` 설정 |
| WEB-23 | LDAP 알고리즘 | JNDIRealm digest ≥ SHA-256 (미사용 시 양호) |
| WEB-24 | 별도 업로드 경로 | 업로드 경로가 웹루트 외부 + other 접근 제한 |
| WEB-25 | 보안 패치 | 설치 버전 ≥ `MIN_TOMCAT_VERSION` |
| WEB-26 | 로그 권한 | 로그 디렉터리/파일 other 접근 권한 |

> **WEB-18/20/21**은 KISA 가이드 대상표상 Tomcat이 포함되지 않아 자동으로 `N/A` 처리한다.
> 이 항목들은 웹서버(Apache 등) 진단 스크립트에서 점검한다.

## 결과 해석 주의

- `수동 확인 권장`/`수동 확인 필요`로 표기된 항목(WEB-02 평문·WEB-09 미구동·WEB-10·WEB-11·WEB-17·WEB-25 등)은
  자동 판정의 한계가 있으니 담당자가 실제 설정을 확인해 최종 확정한다.
- 설정 파일을 못 읽으면(`권한/부재`) 해당 항목은 `N/A`로 표기되므로, 누락 없는 점검을 위해 `sudo` 실행을 권장한다.

## CSV 컬럼

```
항목코드, 분류, 중요도, 점검항목, 대상, 결과, 상세, 근거, 진단대상, 점검시각
```
