# BubbleUI — OpenWRT package definition.
#
# Build via the OpenWRT SDK:
#
#   ln -s $(pwd)/package/bubbleui ${SDK_PATH}/package/bubbleui
#   cd ${SDK_PATH}
#   make package/bubbleui/compile V=s
#
# The package is "pure" in the §15 sense: it installs onto vanilla
# OpenWRT 23.05+ without any image-level patches. See DESIGN.md §10.
#
# Source layout assumptions:
#   - The repo's backend/ directory is the Go module
#     (github.com/framefilter/bubbleui/backend).
#   - The frontend dist (pre-built before the package build) lives at
#     frontend/dist/ relative to the repo root. CI runs `pnpm build`
#     before invoking the SDK; manual builds need to do the same.

include $(TOPDIR)/rules.mk

PKG_NAME:=bubbleui
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=framefilter

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

# Path to the BubbleUI checkout. The SDK build sets this via
# `make BUBBLEUI_SRC=/path/to/repo package/bubbleui/compile`. Defaults
# to two dirs above this Makefile, which is where it'd live in a
# typical `feeds.d/bubbleui/bubbleui` symlink.
BUBBLEUI_SRC?=$(CURDIR)/../..

GO_SRC_DIR:=$(BUBBLEUI_SRC)/backend
GO_PKG:=github.com/framefilter/bubbleui/backend
GO_PKG_BUILD_PKG:=\
	$(GO_PKG)/cmd/bubble-authd \
	$(GO_PKG)/cmd/bubble-vpnd \
	$(GO_PKG)/cmd/bubble-netd \
	$(GO_PKG)/cmd/bubble-hwd

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/bubbleui
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=BubbleUI travel router admin UI
  URL:=https://github.com/framefilter/bubbleui
  DEPENDS:=$(GO_ARCH_DEPENDS) \
           +nginx-ssl \
           +nftables \
           +wireguard-tools \
           +dnsmasq-full \
           +https-dns-proxy \
           +yubikey-personalization \
           +ca-bundle \
           +px5g-mbedtls
endef

define Package/bubbleui/description
  Focused, security-conscious admin UI for travel routers running
  vanilla OpenWRT. Hardware-key auth (YubiKey HMAC + WebAuthn),
  WireGuard with a real kill switch, captive-portal sign-in window
  with tightly-scoped firewall holes, encrypted DNS by default.

  Reference hardware is the GL.iNet GL-AXT1800; any vanilla-OpenWRT-
  compatible device meeting the resource floor in DESIGN.md §13.3
  is in Tier 2 "should work" support.
endef

define Package/bubbleui/conffiles
/etc/config/bubbleui
/etc/bubble/credentials.db
/etc/bubble/vpn.db
/etc/bubble/ui.pem
/etc/bubble/ui.key
endef

# We don't fetch source — the SDK build copies $(GO_SRC_DIR) into
# $(PKG_BUILD_DIR) instead of unpacking a tarball.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -a $(GO_SRC_DIR)/. $(PKG_BUILD_DIR)/
	$(call GoMod/Go/Prepare)
endef

define Package/bubbleui/install
	# Daemons. golang-package.mk drops them in $(GO_PKG_BUILD_BIN_DIR).
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/bubble-authd $(1)/usr/sbin/bubble-authd
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/bubble-vpnd  $(1)/usr/sbin/bubble-vpnd
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/bubble-netd  $(1)/usr/sbin/bubble-netd
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/bubble-hwd   $(1)/usr/sbin/bubble-hwd

	# Frontend (pre-built). $(BUBBLEUI_SRC)/frontend/dist must exist.
	$(INSTALL_DIR) $(1)/usr/share/bubbleui
	cp -a $(BUBBLEUI_SRC)/frontend/dist/. $(1)/usr/share/bubbleui/

	# Init scripts.
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bubble-authd $(1)/etc/init.d/bubble-authd
	$(INSTALL_BIN) ./files/etc/init.d/bubble-vpnd  $(1)/etc/init.d/bubble-vpnd
	$(INSTALL_BIN) ./files/etc/init.d/bubble-netd  $(1)/etc/init.d/bubble-netd
	$(INSTALL_BIN) ./files/etc/init.d/bubble-hwd   $(1)/etc/init.d/bubble-hwd

	# UCI default config + first-boot setup.
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/bubbleui $(1)/etc/config/bubbleui

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bubbleui $(1)/etc/uci-defaults/bubbleui

	# Reverse-proxy + TLS termination via nginx.
	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_DATA) ./files/etc/nginx/conf.d/bubbleui.conf $(1)/etc/nginx/conf.d/bubbleui.conf

	# State directory placeholder so postinst-time DB creation has a home.
	$(INSTALL_DIR) $(1)/etc/bubble
endef

define Package/bubbleui/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
# uci-defaults will run on first boot; if we're installing onto a
# live system we run it now too.
[ -x /etc/uci-defaults/bubbleui ] && /etc/uci-defaults/bubbleui
/etc/init.d/bubble-authd enable
/etc/init.d/bubble-vpnd  enable
/etc/init.d/bubble-netd  enable
/etc/init.d/bubble-hwd   enable
/etc/init.d/bubble-authd start || true
/etc/init.d/bubble-vpnd  start || true
/etc/init.d/bubble-netd  start || true
/etc/init.d/bubble-hwd   start || true
exit 0
endef

define Package/bubbleui/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/bubble-hwd   stop    2>/dev/null || true
/etc/init.d/bubble-netd  stop    2>/dev/null || true
/etc/init.d/bubble-vpnd  stop    2>/dev/null || true
/etc/init.d/bubble-authd stop    2>/dev/null || true
/etc/init.d/bubble-hwd   disable 2>/dev/null || true
/etc/init.d/bubble-netd  disable 2>/dev/null || true
/etc/init.d/bubble-vpnd  disable 2>/dev/null || true
/etc/init.d/bubble-authd disable 2>/dev/null || true
exit 0
endef

$(eval $(call GoBinPackage,bubbleui))
$(eval $(call BuildPackage,bubbleui))
