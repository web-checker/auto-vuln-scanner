#!/usr/bin/env bash
#############################################################################
# 진단 스크립트 배포·실행·회수 오케스트레이터 (리눅스 호스트)
#   - 대상: bastion / webserver / was  (cloud 는 콘솔 전용이라 제외)
#   - 원격 홈에 ~/linux_diag, ~/was_diag, ~/web_diag 로 평탄 배포(중첩 ~/diag_run/* 없음)
#   - 읽기전용 진단 실행 후, 산출물(raw CSV + history TXT)을
#     각 suite 폴더(result_<host>)에 "산개" 저장한다. (중앙 수집 폴더 없음)
#   - git 에는 스크립트만 추적되고 산출물(result_*/)은 .gitignore 로 비공개.
#
#   사전: ~/.ssh/config 에 bastion/webserver/was 호스트 alias 정의되어 있어야 함.
#   사용법:  bash deploy.sh
#############################################################################
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH="ssh -o ConnectTimeout=25 -o BatchMode=yes"
SCP="scp -o ConnectTimeout=25 -o BatchMode=yes"
cd "$REPO" || exit 1

# ── 산출물 회수 대상(각 suite 폴더로 산개) ──────────────────
R_LX_BASTION="$REPO/linux-diag/result_bastion"
R_LX_WEB="$REPO/linux-diag/result_web"
R_LX_WAS="$REPO/linux-diag/result_was"
R_WEB="$REPO/web-diag/result_web"
R_WAS="$REPO/was-diag/result_was"

echo "###### 로컬 회수 폴더 초기화(각 suite) ######"
for d in "$R_LX_BASTION" "$R_LX_WEB" "$R_LX_WAS" "$R_WEB" "$R_WAS"; do
  rm -rf "$d"; mkdir -p "$d"
done

# =========================================================================
echo; echo "==================== bastion : linux_diag ===================="
$SSH bastion 'sudo rm -rf ~/diag_run ~/linux_diag ~/cloud_diag* ~/*_result ~/result_* 2>/dev/null; mkdir -p ~/linux_diag/result && echo CLEAN-OK'
$SCP linux-diag/linux_diag.sh           bastion:linux_diag/linux_diag.sh
$SCP linux-diag/linux_diag_bastion.conf bastion:linux_diag/linux_diag_bastion.conf
$SSH bastion 'cd ~/linux_diag && sudo bash linux_diag.sh -c linux_diag_bastion.conf -o result; echo "linux rc=$?"; sudo chown -R ec2-user:ec2-user ~/linux_diag'
$SCP 'bastion:linux_diag/result/*' "$R_LX_BASTION/"

# =========================================================================
echo; echo "==================== webserver : linux_diag + web_diag ===================="
$SSH webserver 'sudo rm -rf ~/diag_run ~/linux_diag ~/web_diag ~/web_diag.sh ~/web_diag.conf ~/web_diag_result ~/*_result 2>/dev/null; mkdir -p ~/linux_diag/result ~/web_diag/result && echo CLEAN-OK'
$SCP linux-diag/linux_diag.sh             webserver:linux_diag/linux_diag.sh
$SCP linux-diag/linux_diag_webserver.conf webserver:linux_diag/linux_diag_webserver.conf
$SCP web-diag/web_diag.sh web-diag/web_diag.conf webserver:web_diag/
$SSH webserver 'cd ~/linux_diag && sudo bash linux_diag.sh -c linux_diag_webserver.conf -o result; echo "linux rc=$?"'
$SSH webserver 'cd ~/web_diag   && sudo bash web_diag.sh   -c web_diag.conf            -o result; echo "web rc=$?"; sudo chown -R ubuntu:ubuntu ~/linux_diag ~/web_diag'
$SCP 'webserver:linux_diag/result/*' "$R_LX_WEB/"
$SCP 'webserver:web_diag/result/*'   "$R_WEB/"

# =========================================================================
echo; echo "==================== was : linux_diag + was_diag ===================="
$SSH was 'sudo rm -rf ~/diag_run ~/linux_diag ~/was_diag ~/was_diag.sh ~/was_diag.conf ~/was_diag_result ~/*_result 2>/dev/null; mkdir -p ~/linux_diag/result ~/was_diag/result && echo CLEAN-OK'
$SCP linux-diag/linux_diag.sh        was:linux_diag/linux_diag.sh
$SCP linux-diag/linux_diag_was.conf  was:linux_diag/linux_diag_was.conf
$SCP was-diag/was_diag.sh was-diag/was_diag.conf was:was_diag/
$SSH was 'cd ~/linux_diag && sudo bash linux_diag.sh -c linux_diag_was.conf -o result; echo "linux rc=$?"'
$SSH was 'cd ~/was_diag   && sudo bash was_diag.sh   -c was_diag.conf        -o result; echo "was rc=$?"; sudo chown -R ubuntu:ubuntu ~/linux_diag ~/was_diag'
$SCP 'was:linux_diag/result/*' "$R_LX_WAS/"
$SCP 'was:was_diag/result/*'   "$R_WAS/"

# =========================================================================
echo; echo "###### 산개 저장된 산출물 ######"
for d in "$R_LX_BASTION" "$R_LX_WEB" "$R_LX_WAS" "$R_WEB" "$R_WAS"; do
  echo "[$(basename "$d")]"; ls -1 "$d" 2>/dev/null | sed 's/^/   /'
done
