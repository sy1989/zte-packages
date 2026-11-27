#
# Copyright (C) 2026 ZTE Packages
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=openconnect
PKG_VERSION:=9.12
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://www.infradead.org/openconnect/download
PKG_HASH:=a2bedce3aa4dfe75e36e407e48e8e8bc91d46def5335ac9564fbf91bd4b2413e

PKG_LICENSE:=LGPL-2.1-or-later
PKG_LICENSE_FILES:=COPYING.LGPL
PKG_CPE_ID:=cpe:/a:infradead:openconnect

PKG_CONFIG_DEPENDS:= \
	CONFIG_OPENCONNECT_OPENSSL \
	CONFIG_OPENCONNECT_GNUTLS

PKG_BUILD_FLAGS:=no-mips16
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/openconnect/config
	source "$(SOURCE)/Config.in"
endef

define Package/openconnect
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libxml2 +kmod-tun +resolveip +vpnc-scripts \
	   +OPENCONNECT_OPENSSL:libopenssl \
	   +OPENCONNECT_GNUTLS:libgnutls +OPENCONNECT_GNUTLS:libtasn1 \
	   $(ICONV_DEPENDS) $(INTL_DEPENDS)
  TITLE:=OpenConnect VPN client (OpenSSL/ZXSEC or GnuTLS)
  MAINTAINER:=ZTE Packages <packages@example.com>
  URL:=https://www.infradead.org/openconnect/
  SUBMENU:=VPN
endef

define Package/openconnect/description
	A VPN client compatible with several SSL VPN implementations (ocserv, Cisco AnyConnect, Juniper, Palo Alto)

	Two TLS backends are selectable at build time:

	* OpenSSL + ZXSEC: the DTLS data path is taken over by a
	  self-managed record layer that submits records to
	  /dev/zx279133-sec in batches (SUBMIT_BATCH, up to 16 records per
	  ioctl) while keeping the wire format unchanged. The CSTP/TCP
	  channel uses the same record layer once TLS1.2 or TLS1.3 with
	  AES-GCM is negotiated (TLS1.3: nonce = static_iv XOR seq, AAD =
	  5-byte record header, inner content type after decrypt). Needs
	  the ZXSEC-enabled libssl from this feed; falls back to plain
	  OpenSSL at run time (ZXSEC_DISABLE=1) or when the key hook is
	  missing. DTLS stays DTLS1.2 (ocserv/openconnect do not negotiate
	  DTLS1.3).
	* GnuTLS + ZXSEC: the DTLS and CSTP/TCP record layers are taken over
	  in exactly the same way as the OpenSSL backend, with CSTP
	  supporting TLS1.2 and TLS1.3 (AES-GCM). The gnutls package
	  in this feed carries key hooks in _gnutls_set_keys() and
	  _tls13_set_keys() and exports the current record sequence number
	  so the self-managed codec can stay in sync after the handshake.
	  Requires libgnutls from this feed.
endef

TARGET_LDFLAGS += -Wl,--export-dynamic

CONFIGURE_ARGS += \
	--disable-shared \
	--with-libiconv-prefix=$(ICONV_PREFIX) \
	--with-libintl-prefix=$(INTL_PREFIX) \
	--with-vpnc-script=/lib/netifd/vpnc-script \
	--without-libpcsclite \
	--without-stoken \
	--without-libpskc \
	--without-gssapi \
	--without-lz4 \
	--without-libproxy

ifeq ($(CONFIG_OPENCONNECT_GNUTLS),y)
CONFIGURE_ARGS += \
	--with-gnutls \
	--without-openssl
else
CONFIGURE_ARGS += \
	--without-gnutls
endif

# 所有补丁对两个后端都应用：后端专属文件（openssl.c / gnutls.c 等）
# 在 configure 时只会编译其中一个，另一个保持未使用状态。
# src/ 里的 zxsec-*.c 由 Build/Prepare/Default 自动拷进构建目录
# （`[ ! -d ./src/ ] || cp -fpR ./src/. $(PKG_BUILD_DIR)`），不需要额外规则；
# 130 补丁把它们加进 libopenconnect 的对象列表，两个后端都会链入。

define Package/openconnect/install
	$(INSTALL_DIR) $(1)/etc/openconnect/
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/openconnect.sh $(1)/lib/netifd/proto/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openconnect $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/openconnect-wrapper $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/openconnect.upgrade $(1)/lib/upgrade/keep.d/openconnect
endef

$(eval $(call BuildPackage,openconnect))
