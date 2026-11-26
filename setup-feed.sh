#!/bin/sh
# setup-feed.sh - 在 OpenWrt / ImmortalWrt SDK 根目录执行，把本仓库的三个包
# 确定性地接入构建树，避免官方 feed 的同名包（openconnect / gnutls）抢先被选中。
#
# 用法（在 SDK 根目录）：
#   sh /path/to/zte-packages/setup-feed.sh
# 或显式指定仓库路径：
#   sh /path/to/zte-packages/setup-feed.sh /path/to/zte-packages
#
# 做四件事（可重复执行，幂等）：
#   1. 在 feeds.conf 顶部注册 src-link zte（已存在则改写路径，不重复添加）；
#   2. 清掉已装的同名包符号链接（关键：install_src 见 installed 标志会直接跳过）；
#   3. update + 用 -p zte 显式安装 openconnect / libgnutls；
#   4. 整目录替换 core 包 package/libs/openssl（先 rm -rf 再 cp，避免嵌套成 openssl/openssl）。
# 最后做 PASS/FAIL 验证：符号链接指向本仓库、版本/补丁/后端选项正确。

set -e

ZTE_REPO=$(cd "$(dirname "$0")" && pwd)
[ -n "$1" ] && ZTE_REPO=$(cd "$1" && pwd)

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f ./scripts/feeds ] || fail "请在 SDK 根目录执行（当前目录没有 scripts/feeds）"
for d in openssl openconnect gnutls; do
	[ -d "$ZTE_REPO/$d" ] || fail "$ZTE_REPO 不是完整的 zte-packages（缺 $d/）"
done

echo "==> zte-packages : $ZTE_REPO"
echo "==> SDK         : $(pwd)"

# ---- 1. 注册 feed（置顶 + 幂等） ----
CONF=feeds.conf
[ -f "$CONF" ] || cp feeds.conf.default "$CONF"
if grep -q '^src-link zte ' "$CONF"; then
	# 用 sed 替换已有行（路径里 '/' 用 '|' 作分隔符）
	sed -i "s|^src-link zte .*|src-link zte $ZTE_REPO|" "$CONF"
else
	sed -i "1i src-link zte $ZTE_REPO" "$CONF"
fi
echo "[1/4] feeds.conf 首行: $(head -1 "$CONF")"

# ---- 2. 清掉已装的同名包 ----
# installed 标志为 1 时 install_src() 直接 return，必须先卸载再装。
./scripts/feeds uninstall openconnect libgnutls >/dev/null 2>&1 || true
rm -f package/feeds/*/openconnect package/feeds/*/gnutls package/feeds/*/libgnutls 2>/dev/null || true
echo "[2/4] 已清除同名包旧链接"

# ---- 3. 更新并从 zte 显式安装 ----
./scripts/feeds update zte
./scripts/feeds install -p zte openconnect
./scripts/feeds install -p zte libgnutls
echo "[3/4] 已从 zte feed 安装 openconnect / libgnutls"

# ---- 4. 替换 core openssl ----
# openssl 是 core 包，feed 里的同名包不会覆盖它。整目录替换：
# 先 rm -rf 再 cp -a "$ZTE_REPO/openssl/." 到目标，避免嵌套成 openssl/openssl。
rm -rf package/libs/openssl
mkdir -p package/libs/openssl
cp -a "$ZTE_REPO/openssl/." package/libs/openssl/
echo "[4/4] 已替换 package/libs/openssl"

# ---- 验证 ----
echo
echo "===== 验证 ====="
rc=0
check() {
	if eval "$2"; then
		echo "  PASS  $1"
	else
		echo "  FAIL  $1" >&2
		rc=1
	fi
}

# 符号链接必须指向本仓库（feeds/zte 是 src-link，最终解析到我们的目录）
check "openconnect 来自本仓库" \
	"[ \"\$(readlink -f package/feeds/zte/openconnect 2>/dev/null)\" = \"$ZTE_REPO/openconnect\" ]"
check "gnutls 来自本仓库" \
	"[ \"\$(readlink -f package/feeds/zte/gnutls 2>/dev/null)\" = \"$ZTE_REPO/gnutls\" ]"

# 不能有官方 feed 的同名链接残留
check "无官方 openconnect 链接" \
	"[ ! -e package/feeds/packages/openconnect ]"
check "无官方 gnutls 链接" \
	"[ ! -e package/feeds/packages/gnutls ]"

# 版本钉死
check "openconnect 版本 9.12" \
	"grep -q '^PKG_VERSION:=9.12' package/feeds/zte/openconnect/Makefile"
check "gnutls 版本 3.8.10" \
	"grep -q '^PKG_VERSION:=3.8.10' package/feeds/zte/gnutls/Makefile"
check "openssl 版本 3.5.7" \
	"grep -q '^PKG_VERSION:=3.5.7' package/libs/openssl/Makefile"

# 关键补丁都在
check "openssl keyhook 补丁" \
	"[ -f package/libs/openssl/patches/160-zxsec-tls12-keyhook.patch ]"
check "gnutls keyhook 补丁" \
	"[ -f package/feeds/zte/gnutls/patches/100-zxsec-key-hook.patch ]"
check "openconnect GnuTLS 补丁" \
	"[ -f package/feeds/zte/openconnect/patches/140-gnutls-record-layer.patch ]"

# 后端选项（Config.in 必须提供 GnuTLS / OpenSSL 两个选择）
check "openconnect 双后端选项" \
	"grep -q 'OPENCONNECT_GNUTLS' package/feeds/zte/openconnect/Config.in && grep -q 'OPENCONNECT_OPENSSL' package/feeds/zte/openconnect/Config.in"

echo
if [ "$rc" -eq 0 ]; then
	echo "全部 PASS：三个包已正确接入，可以 make menuconfig 了。"
else
	echo "有 FAIL 项，请检查 feeds.conf 与 package/feeds/zte/ 下的链接。" >&2
fi
exit "$rc"
