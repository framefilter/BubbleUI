# BubbleUI — OpenWRT package definition.
#
# We deliberately do NOT use golang-package.mk: BubbleUI's daemons are
# CGO-free static binaries, and pinning to OpenWRT's per-release Go
# toolchain wiring buys us nothing while making CI fragile across
# 23.05 / 24.10 / SNAPSHOT. Instead, CI cross-compiles with the host
# Go toolchain and points this Makefile at the resulting binaries
# via $(BUBBLEUI_BIN). The SDK build is just an .ipk-packaging step.
#
# Build via the OpenWRT SDK (CI does this; manual steps mirror it):
#
#   # Cross-compile the daemons + frontend ahead of time:
#   (cd backend && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
#       go build -trimpath -ldflags='-s -w' \
#       -o /tmp/bubbleui-bin/aarch64/ ./cmd/...)
#   (cd frontend && pnpm install --frozen-lockfile && pnpm build)
#
#   # Symlink and compile inside the SDK:
#   ln -s $(pwd)/package/bubbleui ${SDK}/package/bubbleui
#   cd ${SDK}
#   make package/bubbleui/compile V=s \
#       BUBBLEUI_SRC=/path/to/BubbleUI \
#       BUBBLEUI_BIN=/tmp/bubbleui-bin/aarch64
#
# BUBBLEUI_SRC defaults to two dirs above this Makefile (typical
# feeds.d/bubbleui/bubbleui layout). BUBBLEUI_BIN is required.

include $(TOPDIR)/rules.mk

PKG_NAME:=bubbleui
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=framefilter

BUBBLEUI_SRC?=$(CURDIR)/../..
BUBBLEUI_BIN?=

include $(INCLUDE_DIR)/package.mk

define Package/bubbleui
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=BubbleUI travel router admin UI
  URL:=https://github.com/framefilter/bubbleui
  DEPENDS:=+nginx-ssl \
           +nftables \
           +wireguard-tools \
           +dnsmasq-full \
           +https-dns-proxy \
           +ca-bundle \
           +px5g-mbedtls
endef

define Package/bubbleui/description
  Focused, security-conscious admin UI for travel routers running
  vanilla OpenWRT. Hardware-key auth via WebAuthn (FIDO2 — security
  keys, platform authenticators), WireGuard with a real kill switch,
  captive-portal sign-in window with tightly-scoped firewall holes,
  encrypted DNS by default.

  Reference hardware is the GL.iNet GL-AXT1800; any vanilla-OpenWRT-
  compatible device meeting the resource floor in DESIGN.md §13.3
  is in Tier 2 "should work" support.
endef

define Package/bubbleui/conffiles
/etc/config/bubbleui
endef

# The cert/key and SQLite databases under /etc/bubble/ are runtime-
# created (uci-defaults generates the cert pair; the daemons create
# the DBs on first write), so they aren't package conffiles. They
# survive upgrades because the package install doesn't ship over them.

# No source fetch / unpack / compile — the binaries are pre-built.
define Build/Prepare
	$(if $(BUBBLEUI_BIN),,$(error BUBBLEUI_BIN is required: point at the directory containing pre-built bubble-* binaries))
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
	@echo "bubbleui: packaging pre-built binaries from $(BUBBLEUI_BIN)"
	@for b in bubble-authd bubble-vpnd bubble-netd bubble-hwd; do \
		[ -x $(BUBBLEUI_BIN)/$$b ] || { echo "missing $(BUBBLEUI_BIN)/$$b"; exit 1; }; \
	done
	@[ -d $(BUBBLEUI_SRC)/frontend/dist ] || { echo "missing $(BUBBLEUI_SRC)/frontend/dist (run pnpm build)"; exit 1; }
endef

define Package/bubbleui/install
	# Daemons.
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(BUBBLEUI_BIN)/bubble-authd $(1)/usr/sbin/bubble-authd
	$(INSTALL_BIN) $(BUBBLEUI_BIN)/bubble-vpnd  $(1)/usr/sbin/bubble-vpnd
	$(INSTALL_BIN) $(BUBBLEUI_BIN)/bubble-netd  $(1)/usr/sbin/bubble-netd
	$(INSTALL_BIN) $(BUBBLEUI_BIN)/bubble-hwd   $(1)/usr/sbin/bubble-hwd

	# Frontend (pre-built).
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
	$(INSTALL_DATA) ./files/etc/nginx/conf.d/bubbleui.conf      $(1)/etc/nginx/conf.d/bubbleui.conf
	$(INSTALL_DATA) ./files/etc/nginx/conf.d/bubbleui.proxy.inc $(1)/etc/nginx/conf.d/bubbleui.proxy.inc

	# State directory placeholder.
	$(INSTALL_DIR) $(1)/etc/bubble
endef

define Package/bubbleui/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
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

$(eval $(call BuildPackage,bubbleui))
