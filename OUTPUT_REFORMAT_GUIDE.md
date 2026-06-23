# 진단 스크립트 출력 양식 재구성 가이드

was_diag.sh 에 적용한 **출력/저장 양식 변경**을 나머지 스크립트(web / linux / win / DB)에
동일하게 적용하기 위한 작업 지침. **레퍼런스 구현 = `was-diag/was_diag.sh`** (그대로 복사·번역).

> ⚠️ 대원칙: **진단 로직(점검 함수)·스크립트 구조는 건드리지 않는다.** 바꾸는 것은
> **출력 화면 내용 + 저장(CSV/보고서) 내용**뿐. (= 출력부 / 데이터 컬럼 구성만 변경)

---

## 0. 적용 대상 ↔ 기준 PDF ↔ 진단대상 값

| 스크립트 | 언어 | 항목코드 | 기준 PDF(`주요정보통신기반시설_챕터별_분할_PDF/`) | `진단대상` 값(예시) |
|---|---|---|---|---|
| `was-diag/was_diag.sh`  | bash | WEB-01~26 | `03_웹_서비스.pdf` (Tomcat 대상) | `WAS(Tomcat)` ✅완료 |
| `web-diag/web_diag.sh`  | bash | WEB-01~26 | `03_웹_서비스.pdf` (Apache 대상) | `Web(Apache)` ✅완료 |
| `linux-diag/linux_diag.sh` | bash | U-01~67 | `01_Unix_서버.pdf` | `Linux(${ID})` 호스트별(ubuntu/amzn) ✅완료 |
| `win_diag/win_diag.ps1` | PowerShell | W-01~64 | `02_Windows_서버.pdf` | `Windows Server` ✅완료(배포=RDP 수동) |
| `DB_diag/dbms_diag.ps1` | PowerShell | D-01~26 | `08_DBMS.pdf` | `DBMS(Oracle)` ✅완료(배포=RDP 수동) |

`진단대상IP` = 점검 대상 호스트 IP (bash: `hostname -I` 첫 토큰 / PS: 대상 IP 변수).

---

## 1. 핵심 변경 5가지 (요약)

| # | 항목 | Before | After |
|---|---|---|---|
| 1 | **판단기준 원문** | 없음(가공 요약만) | PDF의 **양호/취약 원문** 양쪽 다 탑재 (`STD_PASS`/`STD_VULN`) |
| 2 | **분류(대분류)** | `계정관리` 등 압축표기 | PDF 표기 그대로 `계정 관리`, `서비스 관리`, `보안 설정`, `패치 및 로그 관리` |
| 3 | **CSV 점검내용** | 일부 가공 | 살펴본 파일/명령 **출력 전체** 삽입(없으면 자연어) |
| 4 | **화면 점검요약** | 1줄 요약문 | 점검내용을 **8줄까지** + `… 이하 N줄 생략` |
| 5 | **컬럼 구성** | 코드·분류·중요도·항목·파일·대상·결과·내용·요약·진단대상·시각 | 아래 §2 / §3 스펙 |

> **보고서(판단근거 형식)는 이번 범위 밖.** 판단근거 데이터(`F_SUMMARY` 등)는 *계산·저장만 유지*하고
> 출력하지 않는다 — 다음 단계에서 별도 보고서 양식 추가 시 바로 사용.

> 📌 **권한 판정 = 기준 권한 '초과 여부'(`perm_subset`).** PDF '조치 방법'의 권한값을 기준(conf `*_MAX_PERM`)으로 두고,
> **무조건 일치가 아니라 기준 이하(부분집합)면 양호, 어느 칸이든 초과면 취약**. 예) WEB-14 Apache 조치=`chmod 750` →
> `perm_subset "$p" "750"`. 640·600은 750의 부분집합이라 양호, 644(other r)·770(group w)은 초과라 취약.
> `perm_le`(8진수 통째 비교)·`others_has_write`(world-write만)는 칸을 뭉개거나 느슨 → ❌.
> **전수 점검(2026-06-19): `perm_le`는 web-diag에만 있던 잔재→제거. was/web/linux 모두 `perm_subset` 일원화. WEB-14는 was·web 양쪽 `perm_subset $CONF_FILE_MAX_PERM(750)` 적용.** (win/DB는 ACL 모델 — 마이그레이션 시 별도)

> 📌 **판정 방향·점검 대상도 PDF '점검 및 조치 사례'와 일치시킬 것**(권한뿐 아니라 로직 전체). 출력 양식을 손보며 각 항목이
> PDF 점검 사례가 보라는 *바로 그 지시자/파일*을 보는지 검증. 예(web-diag, 2026-06-19):
> - **WEB-04**: 증적이 Indexes 지시자 기준이어야 함(FollowSymLinks 등 무관 Options ❌). 점검 범위는 활성 설정(sites-enabled) 기준.
> - **WEB-06**: KISA Apache 조치=`AllowOverride AuthConfig` + `.htaccess/htpasswd` 인증 구성 → 양호=AuthConfig+htpasswd 둘 다.
>   (기존 `AllowOverride None`=양호 로직은 KISA 조치와 정반대였음 → 정정.)
> - **WEB-07**: Apache 2.4(Debian/Ubuntu)는 htdocs 미제공·DocumentRoot=/var/www/html → 점검 목록을 기본 안내페이지 + apache2-doc 매뉴얼(`/usr/share/doc/apache2-doc/manual`·`/manual` Alias)로 교정(구버전 `htdocs/manual`·IIS 잔재 `iissamples` 제거).
> - **WEB-17**(Alias 존재→취약)은 의도된 동작(필요 여부 수동 확인) — 유지.
>
> ✅ **web-diag 전수 대조 완료(2026-06-19): WEB-04/06/07/12/14 정정, 나머지 21항목 PDF 정합 확인.**
> 🔧 **win-diag 전수 대조(2026-06-20): 64항목 PDF 대조 — 임계값(W-04≤5·W-08≥60·W-36≤30분·W-42≥10240·W-59≥3) 및 양호 증적 정합. 정정 3건 — W-09 비밀번호 기억(history) 판정 추가(KISA 조치=4개, conf 12→4), W-11 SeInteractiveLogonRight를 SID 해석 후 자동판정(Administrators/IUSR_만=양호, 외 그룹=취약 — 타깃은 Backup Operators 존재로 취약), W-37 예약작업 전수 나열(화면 8줄/CSV 전체) + W-49/W-11 SID→이름 해석. 재실행(160745): W-11 자동판정→이번 상태는 Administrators만이라 양호(64/53/0/11). 추가 증적 보강 W-37·W-40·W-62·W-58 — '개수만' 출력을 전수 나열로(화면 8줄/CSV 전체): 예약작업·감사 하위범주·Run/RunOnce 항목·사용자 홈 ACL.**
> ✅ **was-diag 전수 대조 완료(2026-06-19): 26항목 PDF Tomcat 사례 정합(레퍼런스+오류.txt 반영본). WEB-15만 보강 — '불필요' 매핑은 자동 판정 불가(`UnuseServlet`처럼 앱 정의 서블릿은 필수와 구조 동일)이므로, 객관적 제거 대상(cgi/ssi)만 자동 취약 + 활성 servlet-mapping 전수 나열로 수동 확인 노출(DIAG_STYLE §4 열거형).**
> 🔧 **linux/was 증적 보강(2026-06-20)**: ①사전목록 판정 항목(U-07/09/11)은 전체 계정/그룹/셸 수록(AI 판정). ②U-24는 로그인 가능 계정별 홈 환경변수 파일 나열+소유자 검증. ③U-37은 cron/at '설정 파일'(crontab, cron.allow/deny, at.*, cron.d/*)을 stat 라인으로 표시 + 소유자 root·권한 ≤640 판정(주기 실행 디렉터리 cron.hourly 등은 755가 정상이라 640 적용 부적합 → 표시·판정에서 제외). ④서비스 점검 전 항목 `대상 서비스(목록) 구동: 활성/비활성`(svc_stat) 통일 — 활성 시 chk_svc_off는 구동중 목록 동반, NFS(U-40)는 서비스 활성 먼저→공유 디렉터리/내용 점검. ⑤다중라인 XML 요소(was WEB-16 ErrorReportValve)는 평탄화로 값 판정 + 요소 '전체'(여러 줄) 출력해 잘림 방지.
> ⚖️ **다중값 판정은 'head -1' 금지, 전체 평가**: 한 항목이 여러 파일·여러 값을 가질 때 첫 값만 보면 오판. 예) U-30 UMASK는 profile/login.defs/bashrc의 **모든 umask 값**을 평가 — 022 미만이 있으면 그 파일이 UPG 가드(`id -gn==id -un`/`UID -gt`, 사설그룹 한정)를 가지면 조건부(안전), 가드 없으면 '무조건 느슨 → 취약'. (RHEL/AL `/etc/bashrc`의 `umask 002`는 표준 UPG라 안전.)
> ✅ **DB-diag 전수 대조 완료(2026-06-20): D-01~26 PDF 정합 — 임계값(conf 기반)·ORACLE_MAINTAINED 제외·21c desupport·MSSQL전용(D-16/23/24) N/A 모두 적절. STD 정확(D-21 'WITH_GRANT_OPTION이 ROLE에 의하여 설정' = PDF 원문). 증적 풍부(프로파일·계정·서비스·파라미터 전수). 정정 0건 — 5종 중 최고 완성도. 증적 보강(2026-06-20): 양호 근거를 '없음/프로파일명'에서 모집단·실값으로 전수화 — D-03/05/09 프로파일별 정책값, D-08 활성계정별 해시버전, D-01 기본비번 계정+상태, D-04 DBA/SYSDBA 보유자, D-20 전체 Object 소유자, D-11 %ANY TABLE% 보유자, D-17 감사테이블 grantee, D-21 GRANT OPTION 보유자, D-18 PUBLIC Role 수.**
> ✅ **linux-diag 전수 대조 완료(2026-06-20): U-01~67 PDF 점검·조치 사례 정합. 권한 임계값 10개(U-16/18/19/20/21/22/29/37/63/67) 전부 STD와 일치, 판정 방향 정상, 자동판정 불가 항목(U-23 SUID·U-33 숨김·U-45 메일버전 등) N/A+열거 적절. U-40만 보강(접근통제뿐 아니라 exports 권한 ≤644도 점검 — PERM_EXPORTS_MAX 추가). 잔여 경미사항(비수정): U-37 cron.allow 사용자제한 미점검·U-24 소유자 미검증·U-06 root단독시스템 예외 미반영.**

---

## 2. CSV(로우데이터) — 10컬럼 고정

```
항목코드, 분류, 항목, 판단기준, 결과, 점검내용, 진단대상, 진단대상IP, 중요도, 점검파일
```

- **판단기준** = `양호 : <원문> | 취약 : <원문>` (다중라인 → CSV는 ` | `로 조인됨)
- **결과** = 양호 / 취약 / N/A
- **점검내용** = 점검에 사용한 명령/파일 출력 **전부**. 결과 없으면 `(…없음)` 자연어
  - ⚠️ **재포맷 금지**: 파일 내용을 새 구조로 변형하지 말 것. 예) error-page를 `400 -> /path`로 가공 ❌ → `<error-code>400</error-code>` 등 **grep 원문 라인 그대로** ✅.
  - 단, **stat 표현**(`-rw-r----- (640) …`)·**런타임 상태**(`pid=… user=…`)는 DIAG_STYLE §5·§6이 허용하므로 유지.
  - 🔎 **맥락 보존**: 지시자가 *어느 블록*에 속하는지가 판정에 중요하면(예 Apache `Options`가 어느 `<Directory>` 소속인지) **소속 블록 헤더를 함께 출력**. 라인만 떼면 동일해 보여(`Options -FollowSymLinks` ×2) 판단 불가 → web-diag `acfg_ctx`로 `<Directory>` 헤더 동반. 출처 파일은 `# <파일>` 헤더(web-diag `regroup_src`: ACFG `‹파일›` 태그 → 표준 헤더 변환).
  - 🔐 **민감정보 미수록**: 로우데이터에 **비밀번호 해시·평문 암호·개인키 내용**을 절대 넣지 말 것(CSV/보고서는 오프라인 크래킹·유출 대상). 예) U-04는 `/etc/shadow` *내용 대신* 존재·권한(stat)만, `/etc/passwd`는 *계정명만*(암호값 마스킹). SSL/SSH 개인키도 권한(stat)만 보고 내용 미수록.
  - 👥 **사전목록 판정 ↔ 전체 모집단 수록**: 자동 판정이 conf의 사전목록(예 `UNNECESSARY_ACCOUNTS`)으로 양호/취약을 내더라도, 로우데이터엔 **전체 모집단**(전체 계정/그룹/셸 등)을 수록할 것 — 사전목록 밖의 불필요 항목은 AI/담당자가 전체를 보고 판단해야 하므로. 예) U-07 전체계정·U-09 전체그룹·U-10 전체 UID·U-11 전체 계정:셸·U-24/U-31 각 홈 stat·U-27 각 rhosts/hosts.equiv stat·U-32 각 계정→홈 존재. **find 기반(U-25 world-writable 등)은 head 캡 없이 전수 + 총개수**(의사FS /proc·/sys·/dev·/run prune). 위반 요약("문제: 없음")만 출력 ❌.
  - 🧩 **서비스 의존 점검은 '활성 여부 먼저'**: 데몬 구동에 좌우되는 항목은 ①서비스 활성 점검 → ②활성 시 설정/디렉터리 권한·내용 점검 순. 예) U-40 NFS는 nfs-server 활성 확인 후 exports 내용+공유 디렉터리 권한 출력(비활성이면 '미사용' 양호).
  - 🎯 **이상치 탐지 = 전수 열거 + 속성 기반 IOC**(basename 화이트리스트 ❌): '검색·제거'형은 정상 나열로 양호를 내면 소수 이상치를 누락한다(예 U-33이 홈의 755 실행 숨김파일 `.jiyun`을 놓침). 그렇다고 **이름 화이트리스트는 허점**(같은 이름을 다른 경로/속성으로 위장 시 통과, `/etc/skel/.viminfo` 등) → 쓰지 말 것. 대신 **전수로 모두 표기**(거르지 않음) + **속성 기반 강한 IOC로 판정**. 예) **U-33** = 홈/임시/skel 숨김 항목 전수 + '실행권한 보유 숨김 파일'(정상 dotfile은 비실행)을 취약 신호로. **U-23** = SUID/SGID 전수 + '임시·홈 경로(/tmp,/dev/shm,/home,/root)의 SUID'·'SUID 셸(bash 등)'을 취약 신호로(정상 SUID는 /usr/bin 등 시스템 경로). U-25 world-writable도 head 캡 없이 전수. **판정 규칙**: 명백한 IOC 적중 → **취약**(확실한 신호는 묻지 않음). IOC 없음 → **N/A(수동/AI 확인 대상)** — '양호' 금지(정상 위치·이름 위장 백도어를 못 거르므로 'IOC 없음'을 '검증됨'으로 단정하면 거짓 안심). 전수 목록은 양쪽 다 제공해 비실행/비IOC 이상치를 사람·AI가 판별.
- **진단대상** = 자산 종류 상수(§0), **진단대상IP** = 호스트 IP
- 제거된 것: 중복 `대상` 컬럼, `점검시각`, `점검요약`(CSV엔 점검내용만)

bash CSV 출력부 (was_diag.sh 참고):
```bash
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
  "$(csv_field 항목코드)" "$(csv_field 분류)" "$(csv_field 항목)" "$(csv_field 판단기준)" \
  "$(csv_field 결과)" "$(csv_field 점검내용)" "$(csv_field 진단대상)" "$(csv_field 진단대상IP)" \
  "$(csv_field 중요도)" "$(csv_field 점검파일)"
# 행:
  "$(csv_field "${F_CODE[$i]}")" "$(csv_field "${F_CAT[$i]}")" "$(csv_field "${F_NAME[$i]}")" \
  "$(csv_field "${F_STD[$i]}")" "$(csv_field "${F_RESULT[$i]}")" "$(csv_field "${F_RAW[$i]}")" \
  "$(csv_field "$TARGET_SYS")" "$(csv_field "$IP_ADDR")" "$(csv_field "${F_SEV[$i]}")" \
  "$(csv_field "${F_FILE[$i]}")"
```

---

## 3. 화면 + 보고서(TXT) 블록 — `emit_screen` + `truncate8`

블록 필드(이 5개만): `[코드 (중요도) 항목명]` 헤더(=항목코드·중요도·항목) +
점검 결과 / 점검 파일 명 / 점검 요약(8줄) / 판단 기준(양호·취약). **분류·진단대상·진단대상IP는 화면 미표기**(CSV에만).

```
[WEB-26 (중) 로그 디렉터리 및 파일 권한 설정]
점검 결과    : 양호
점검 파일 명 : /opt/tomcat9/logs
점검 요약    :
    drwxr-x--- (750) tomcat:tomcat  /opt/tomcat9/logs
    ... (8줄까지)
    ... (이하 3줄 생략 — 상세는 로우데이터 CSV 참조)
판단 기준    :
    양호 : 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우
    취약 : 로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우
----------------------------------------------------------------
```

bash 구현(그대로 복사):
```bash
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
```
- 실시간 출력(record 내부)과 보고서 TXT 루프 **둘 다 `emit_screen` 사용** → 화면=보고서 동일 양식.
- `진단대상`·`진단대상IP`는 CSV 컬럼으로만 남고 화면 블록에선 뺀다(§2 CSV는 10컬럼 그대로).

---

## 4. 판단기준(STD) 배열 만들기

PDF에서 각 항목의 `양호 : … 취약 : …` **원문을 그대로** 추출해 배열로 박는다.

추출 (Git Bash, poppler `pdftotext` 사용):
```bash
pdftotext -enc UTF-8 "…/01_Unix_서버.pdf" u.txt
grep -n "양호 : .*취약 :" u.txt        # 항목별 판단기준 라인 확인 (긴 항목은 다음 줄까지 이어짐)
```
bash 배열:
```bash
declare -A STD_PASS STD_VULN
STD_PASS[U-01]="<PDF 양호 원문>"
STD_VULN[U-01]="<PDF 취약 원문>"
# … 전 항목
```
record()에서 조립·저장:
```bash
# 점검내용이 '결과 없음(자연어)'일 때 감싼 괄호 제거 — 전체가 한 줄이고 (…)로 통째 감싸진 경우만.
#   (권한 '(750)' 등 라인 내부 괄호·다중라인 증적은 보존)  ※ $'\n' 사용(명령치환 $(printf '\n')은 빈문자 됨!)
case "$raw" in
  *$'\n'*) : ;;
  "("*")") raw="${raw#\(}"; raw="${raw%\)}" ;;
esac
std="양호 : ${STD_PASS[$code]:-(기준 미정의)}"$'\n'"취약 : ${STD_VULN[$code]:-(기준 미정의)}"
F_STD[i]="$std"
emit_screen "$code" "$sev" "$name" "$cat" "$std" "$result" "$raw" "$file"
```
> ⚠️ pdftotext가 한 항목을 2줄로 끊는 경우 있음 — 끊긴 뒷부분까지 이어 붙여 **원문 완전체**로 넣을 것.
> 기존 가공 요약(`CRIT_PASS/VULN`)은 **판단근거용으로 유지**(삭제 금지) — STD와 별개.

---

## 5. PowerShell(win / DB) 적용 노트

- `STD_PASS`/`STD_VULN` → `$StdPass = @{}`, `$StdVuln = @{}` 해시테이블.
- 판단기준 조립: `"양호 : $($StdPass[$code])`n취약 : $($StdVuln[$code])"`.
- `truncate8` 대응:
  ```powershell
  function Truncate8($text){
    $lines = $text -split "`r?`n"
    if($lines.Count -le 8){ $text }
    else { ($lines[0..7] -join "`n") + "`n... (이하 $($lines.Count-8)줄 생략 — 상세는 로우데이터 CSV 참조)" }
  }
  ```
- CSV: 같은 10컬럼·같은 순서. 인코딩 `Out-File -Encoding utf8`(BOM 포함) 유지.
- 진단대상/진단대상IP 변수만 PS식으로(대상 IP 산출은 기존 방식 유지).

---

## 6. 커밋 전 체크리스트

- [ ] CSV 헤더가 정확히 **10컬럼**(§2 순서)인가
- [ ] 판단기준이 PDF **양호/취약 원문 그대로**(가공·축약 ❌)인가, 양쪽 다 들어갔는가
- [ ] 분류가 PDF 대분류 **띄어쓰기까지** 일치하는가
- [ ] 점검내용(CSV)에 살펴본 파일/명령 **출력 전체**가 들어가는가(없으면 자연어)
- [ ] 결과 없음 자연어가 **괄호 없이** 출력되는가(단일라인 `(…)`만 벗김 — 권한 `(750)` 보존)
- [ ] 화면 점검요약이 **8줄 + 이하 N줄 생략**으로 잘리는가
- [ ] 진단대상=자산종류 상수, 진단대상IP=호스트 IP 인가
- [ ] 진단 로직(점검 함수)은 **그대로**인가 (출력부만 변경 — 단, 판정이 PDF 조치와 어긋나면 기준 보정)
- [ ] 권한 판정이 **`perm_subset`**(칸별 부분집합)인가, 기준값이 PDF **조치 권한**과 일치하는가 (`perm_le`·world-write only ❌)
- [ ] BOM·KST·읽기전용·set -u(PS는 UTF-8 BOM) 유지했는가
- [ ] 배포→실행→결과회수로 실제 산출물 검증했는가

---

### 배포·실행·회수 (was 예시)
```bash
ssh was 'sudo rm -rf ~/<area>_diag.sh ~/<area>_diag.conf ~/<area>_diag_result'   # 기존 제거
scp <area>_diag.sh <area>_diag.conf was:~/                                        # 배포
ssh was 'chmod +x ~/<area>_diag.sh && cd ~ && sudo ./<area>_diag.sh -c <area>_diag.conf'  # 실행(root 필요)
scp 'was:~/<area>_diag_result/*' result_<target>/                                 # 회수
```
(win/DB는 RDP/WinRM 등 해당 호스트 접속 방식에 맞춰 동일 흐름.)
