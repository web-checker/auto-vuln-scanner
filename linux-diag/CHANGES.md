# linux_diag 변경 내역 (2026-06-18)

KISA UNIX(U-01~U-67) 리눅스 자동 진단 스크립트(`linux_diag.sh` + conf) 최신화 변경점.
기존 단일본(`linux-diag_fixed` 작업본)을 `linux-diag/`로 승격하고, 호스트별 conf로 분리했다.

---

## 1. 스크립트/판정 로직 변경

### ① 권한 판정: `perm_le` → `perm_subset` (정확화, 버그 수정)
- **이전:** `perm_le`가 8진수 권한을 **통째 정수 하나로 비교**(`8#640=416 ≤ 8#600=384?`). owner/group/other 칸 정보가 뭉개져, 칸별로 위험한 권한을 놓침.
  - 예: `044`(group/other 읽기)=36 ≤ 400 → **양호로 오판**, `606`(other 쓰기)·`060`(group 쓰기)도 통과.
- **현재:** `perm_subset` = 파일 권한이 기준 권한의 **칸별 부분집합**인지 비트 판정 `((8#p) & ~(8#max)) == 0`.
  - `040`/`044`/`606`/`060` 등 전부 정확히 취약으로 잡음. 정상 권한(passwd 644의 other 읽기 등)은 그대로 양호.
- **영향 항목:** `chk_file_perm`(U-16·18·19·20·21·22·29·63) + U-37(cron) + U-67(log).

### ② `chk_file_perm` 메시지: 소유자/권한 실패사유 분리
- **이전:** `소유자 부적정(root:shadow) 또는 권한 ...초과` — 소유자가 root인데도 "소유자 부적정"으로 **오표기**.
- **현재:** 실패한 조건만 표기 → `권한 과다(640 — 기준 400 부분집합 아님)`. 소유자/권한 각각 정확히 구분.

### ③ 타임스탬프 UTC → KST
- 상단에 `export TZ='Asia/Seoul'` 추가. 서버 TZ가 UTC여도 **점검시각·결과 파일명이 KST**로 기록.

### ④ 결과 양식: `점검 상태`를 항목명 바로 밑으로
- `emit_block`에서 `점검 상태`를 `[항목]` 헤더 직후(점검 파일 명 위)로 이동 — was_diag와 통일.

### ⑤-1 U-02(비밀번호 관리정책) 점검 내용 = 참조 파일별 출처 표기 + 완전성
- **이전:** 라벨이 실제 파일과 불일치(`system-auth pam_pwquality:` ← Ubuntu엔 system-auth 없음, 실제는 common-password / `pwquality minlen:` ← 출처 불명). 보여주는 값도 max_days·pam·minlen 3개뿐.
- **현재:** 참조 4개 파일을 **파일경로(#) 헤더와 함께 실제 설정 라인**으로 표기 →
  `# /etc/login.defs`(PASS_MAX/MIN_DAYS) · `# /etc/security/pwquality.conf`(minlen·dcredit/ucredit/lcredit/ocredit·minclass·maxrepeat·enforce_for_root) · `# <활성 PAM 파일>`(pam_pwquality/pam_unix/pam_pwhistory — RHEL system-auth/Ubuntu common-password 자동 탐지) · `# /etc/security/pwhistory.conf`(remember).
- conf에 `PWHISTORY_CONF` 추가(4개 conf 전부). 어느 파일에서 온 값인지 명확 + 복잡도/재사용 등 정책 전반을 한 번에 확인 가능.

### ⑤-2 파일에 적힌 값은 grep 원문 라인으로 표기 (신뢰성)
- **원칙:** 파일에 실제 적혀 있는 설정값은 **grep으로 꺼낸 원문 라인(파일:내용)** 을 그대로 보여준다. 추출값을 문장으로 풀어쓰면 근거가 약함. **값이 없을 때만** 서술형 "(…없음)" 사용.
- **적용:** U-12(TMOUT) · U-13(암호화 알고리즘) · U-30(UMASK).
  - 이전: `TMOUT(세션 타임아웃): 600` / `암호화 알고리즘: YESCRYPT` / `UMASK(파일): 022` (문장형, 출처 불명)
  - 현재: `/etc/login.defs:UMASK 022`, `ENCRYPT_METHOD SHA512`, `/etc/pam.d/common-password:… pam_unix.so obscure yescrypt` 등 **실제 라인 + 파일경로**.
- (런타임 서비스 상태 등 파일값이 아닌 항목 — 예 U-01 Telnet 활성/비활성 — 은 상태 표기 유지)

### ⑤-3 bastion 초안 리뷰 반영 (파일값=실측 원문, U-33 판정 도입)
- **U-14**(root PATH): 기존 grep이 `/etc/profile` 의 `pathmunge()` 함수 본문 `PATH=$1:$PATH` 를 오매칭 → `runuser -l root`로 **root 실제 로그인 PATH** 평가·표기.
- **U-17**(시작 스크립트): 카운트 요약 → 파일별 `stat`(권한 표현) 라인.
- **U-33**(숨김 파일): "항상 양호" 스텁 → **시스템 전체(/) 검색**(의사FS만 제외), **필터 없이 숨김 파일/디렉터리 전부 `stat`로 나열 + 총 개수**, 상태 **N/A(수동 확인 대상)** — 비정상/불필요 항목은 사람이 판별(U-23 SUID와 동일 패턴). ※ U-32(홈 디렉터리 존재)와 혼동 금지 — U-33은 전 경로 대상. (검토 과정에서 `/etc/.inetd.conf.swp`·`.systemd.conf.swp` 같은 vim 편집 잔재가 드러나 제거됨 — 화이트리스트 필터는 "기본 생성 파일만 거른다"는 게 사실상 의미 없어 폐기, 전수 나열로 전환.)
- **U-62**(경고 메시지): "설정됨" 서술 → 배너 파일 실제 첫 줄 + `sshd_config` Banner 지시자 라인.
- **U-23**(SUID/SGID): 5개 표본 → U-33과 동일 패턴으로 **SUID·SGID 파일 전부 `stat`(권한 표현)로 나열 + 개수**, N/A(수동 확인). 열거형 항목(U-23/U-33) 일관화.

### ⑤ 점검 파일 명 구분자 ` / ` → ` | `
- 한 항목에 점검 대상이 여러 개일 때 구분선을 `|`로 변경(경로 안의 `/`, `find /` 명령, 주석, raw 내용은 보존).
- 예: `… system-auth | /etc/login.defs`, `커널 | conf:LATEST_KERNEL_VERSION`. (U-02·04·13·20·28·30·64·66)

---

## 2. conf 변경

### ⑥ conf 일관화 — 죽은 변수 14개 제거
스크립트가 실제로 쓰지 않던 선언 제거(conf↔script 일치):
`SECURETTY · SUDOERS_DIR · CRON_ALLOW · AT_ALLOW · CRONTAB_DIR · NTP_CONF · CHRONY_CONF · PASS_MIN_DAYS_MIN · PERM_NFS_MAX · SU_WHEEL_GROUP · DOS_SERVICES · R_SERVICES · TFTP_TALK_SERVICES · MIN_KERNEL_NOTE`
(서비스 목록은 스크립트가 더 완전한 리스트를 하드코딩 중이라 변수 미사용 → 제거)
또한 권한 기준 주석 `"이하"가 양호` → `칸별 부분집합` 의미로 정정.

### ⑦ 호스트별 conf 3종 신설
| 파일 | 대상 | 커널(U-64) |
|---|---|---|
| `linux_diag_bastion.conf` | bastion (AL2023) | `6.1.170-213.321.amzn2023.x86_64` |
| `linux_diag_webserver.conf` | webserver (Ubuntu 26.04) | `7.0.0-1006-aws` |
| `linux_diag_was.conf` | was (Ubuntu 24.04) | `6.17.0-1017-aws` |

- 각 호스트의 실제 `uname -r`·`/etc/passwd`(uid<1000) 계정을 반영(`LATEST_KERNEL_VERSION`, `SYSTEM_ACCOUNTS`).
- 경로·임계값·권한기준은 공통. 공용 `linux_diag.conf`는 템플릿으로 잔존.
- 실행: `sudo ./linux_diag.sh -c ./linux_diag_<host>.conf`

---

## 3. 재배포 결과 (2026-06-18, 호스트별 conf 적용)

| 호스트 | OS | 양호 | 취약 | N/A | (참고)초기* |
|---|---|---|---|---|---|
| bastion | AL2023 | 62 | 1 | 4 | 58/2/7 |
| webserver | Ubuntu 26.04 | 53 | 10 | 4 | 51/9/7 |
| was | Ubuntu 24.04 | 53 | 10 | 4 | 51/9/7 |

\* 초기 = 변경 전 기록(참고치). 취약이 일부 늘어난 건 회귀가 아니라 `perm_subset`가 **칸별로 정확히** 잡아내게 된 결과.

### 취약 항목
- **bastion (1):** U-28(접속 IP/포트 제한) — 호스트 방화벽·hosts.deny 없이 AWS 보안그룹 의존 → 별도 확인 필요.
- **webserver / was (각 10):** U-02 비밀번호 정책 · U-03 계정잠금 · U-06 su 제한 · U-07 불필요 계정 · U-09 불필요 GID · U-12 세션타임아웃 · U-18 shadow 권한 · U-21 rsyslog.conf 권한 · U-37 cron 권한 · U-67 로그 권한.

---

## 4. 참고 / 주의

- **U-18 shadow:** Ubuntu 기본 `640 root:shadow`는 KISA 기준(소유자 root + ≤400)상 취약. AL2023은 `000`이라 양호. (per-host conf로도 기준은 400 유지 — 완화하지 않음)
- **U-64 패치:** `LATEST_KERNEL_VERSION`은 각 호스트 현재 커널로 설정됨. 벤더가 신규 보안 패치를 릴리스하면 conf 값을 갱신해야 정확.
- **U-28:** AWS 보안그룹은 OS에서 안 보이므로 스크립트가 자동 판정 불가 → "별도 통제 수동 확인" 주석과 함께 취약 표기(설계상 의도).
- 각 호스트 상주본(`~/linux_diag`)은 이번에 **호스트별 conf로 정식 재배포** 완료. 로컬 `result_bastion/result_web/result_was`도 최신 결과로 갱신.
