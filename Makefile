# -------------------------------
# Project directories & binary
# -------------------------------
VERSION      ?= $(shell date +%Y.%m.%d)
BUILD_TIME   ?= $(shell date -u +"%Y-%m-%dT%H:%M:%S")
TAG          ?= v$(VERSION)

RPM_VERSION  := $(shell echo "$(VERSION)" | sed 's/-.*//; s/[^A-Za-z0-9._+~]/./g')
RPM_TS       := $(shell echo "$(BUILD_TIME)" | sed 's/.*T//; s/://g')
RPM_RELEASE  := 1.$(RPM_TS)
RPM_ARCH     := $(shell command -v rpm >/dev/null 2>&1 && rpm --eval '%{_arch}' || echo x86_64)

BIN_DIR := bin
MAIN_DIR := cmd/nxs
BINARY := $(BIN_DIR)/nxs
PKGROOT      ?= build/pkgroot
RPMTOP       ?= packaging/rpm
SPECFILE     ?= $(RPMTOP)/SPECS/nxs.spec
ARCH         ?= x86_64

override ARCH    := amd64
override VERSION := $(shell date +%Y.%m.%d-%H%M%S)
override PKGROOT := build/pkgroot
override OUTDIR  := build/deb
BIN := bin/nxs
CONFIG_DIR := configs
DEB_SRC := packaging/debian/DEBIAN

SCRIPTS_DIR := scripts
PLUGINS_DIR := plugins

# --- Remote Sync ---
REMOTE_USER ?= chris
REMOTE_HOST ?= repo.nixpal.com
REMOTE_PORT ?= 65535
REMOTE_DIR  ?= ~/packages/
SYNC_ON_RELEASE ?= 1

RSYNC_FLAGS ?= -av --partial --inplace
SSH_CMD     ?= ssh -p $(REMOTE_PORT)

# -------------------------------
# Go build target config (CPU/OS)
# -------------------------------
GOOS    ?= linux
GOARCH  ?= amd64
GOAMD64 ?= v1
GOAMD64 := $(strip $(GOAMD64))
CGO_ENABLED ?= 0

.PHONY: help setup update build run clean git sync sync-release rpm release clean-deb clean-rpm distclean deb

help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

setup: ## First-time setup after git clone
	go mod tidy
	@echo "✅ Setup complete."

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.' || true
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

run: build ## Run the application
	@./$(BINARY)

# Git helper
git: ## Commit + push with custom message
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push

# Sync built packages to remote repository
sync: sync-release ## Alias for sync-release

sync-release: ## Rsync build artifacts to remote package host
	@if [ "$(SYNC_ON_RELEASE)" = "1" ]; then \
		if [ -d build/deb ] || [ -d packaging/rpm/RPMS ]; then \
			mkdir -p build/release-sync; \
			rm -f build/release-sync/*; \
			find build packaging/rpm -type f \( -name '*.deb' -o -name '*.rpm' \) -exec cp -f {} build/release-sync/ \; 2>/dev/null || true; \
			if [ -n "$$(find build/release-sync -type f 2>/dev/null)" ]; then \
				rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" build/release-sync/ $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR); \
				echo "✅ Synced artifacts to $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)"; \
			else \
				echo "⚠️ No artifacts found to sync."; \
			fi; \
		else \
			echo "⚠️ No build directories found (build/deb or packaging/rpm/RPMS)."; \
		fi; \
	else \
		echo "ℹ️ Remote sync disabled (SYNC_ON_RELEASE=$(SYNC_ON_RELEASE))."; \
	fi


build: ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	@echo "→ Building for $(GOOS)/$(GOARCH) (GOAMD64=$(GOAMD64), CGO_ENABLED=$(CGO_ENABLED))"
	env -u GOAMD64 \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) CGO_ENABLED=$(CGO_ENABLED) \
	go build -a \
		-tags netgo,osusergo \
		-ldflags "-X 'main.Version=$(shell date +%Y.%m.%d)' -X 'main.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)'" \
		-o $(BINARY) ./$(MAIN_DIR)
	@echo "✅ Built: $(BINARY)"

clean:
	@rm -f bin/nxs
	@rm -rf build/pkgroot
	@echo "🧹 Cleaned: bin, build/pkgroot"

clean-deb:
	@rm -rf build/deb
	@rm -f  build/*.deb build/deb/*.deb build/deb/*/*.deb
	@find build -maxdepth 2 -type f -name '*.deb' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: deb artifacts"

clean-rpm:
	@rm -rf packaging/rpm/BUILD packaging/rpm/BUILDROOT
	@rm -rf packaging/rpm/RPMS packaging/rpm/SRPMS packaging/rpm/SOURCES
	@find packaging/rpm -type f -name '*.rpm' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: rpm artifacts (kept SPECS/)"

distclean: clean clean-deb clean-rpm
	@echo "🧨 Distclean done"

deb: build
	@echo "PKGROOT=[$(PKGROOT)] OUTDIR=[$(OUTDIR)]"
	@test -n "$(PKGROOT)" && test -n "$(OUTDIR)"
	@rm -rf "$(PKGROOT)" && mkdir -p "$(PKGROOT)/DEBIAN" \
		"$(PKGROOT)/usr/bin" \
		"$(PKGROOT)/lib/systemd/system" \
		"$(PKGROOT)/usr/share/nxs/configs" \
		"$(PKGROOT)/etc/nxs" \
		"$(OUTDIR)"

	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"

	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/nxs"
	@install -m0640 "packaging/nxs.service" "$(PKGROOT)/lib/systemd/system/nxs.service"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf" "$(PKGROOT)/etc/nxs/nxs.conf"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf.example" "$(PKGROOT)/usr/share/nxs/configs/nxs.conf.example"

	@chmod 0755 "$(PKGROOT)/DEBIAN/postinst" "$(PKGROOT)/DEBIAN/prerm" "$(PKGROOT)/DEBIAN/postrm" 2>/dev/null || true
	@fakeroot dpkg-deb --build "$(PKGROOT)" "$(OUTDIR)/nxs_$(VERSION)-1_$(ARCH).deb"
	@echo "📦 Built: $(OUTDIR)/nxs_$(VERSION)-1_$(ARCH).deb"


rpm: build ## Build .rpm package
	@echo "PKGROOT=[$(PKGROOT)] RPMTOP=[$(RPMTOP)] SPECFILE=[$(SPECFILE)]"
	@test -n "$(PKGROOT)" && test -n "$(RPMTOP)" && test -n "$(SPECFILE)"
	@rm -rf "$(PKGROOT)"
	@mkdir -p "$(PKGROOT)/usr/bin" "$(PKGROOT)/lib/systemd/system" "$(PKGROOT)/usr/share/nxs/configs" "$(PKGROOT)/etc/nxs"
	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/nxs"
	@install -m0640 "packaging/nxs.service" "$(PKGROOT)/lib/systemd/system/nxs.service"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf" "$(PKGROOT)/etc/nxs/nxs.conf"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf.example" "$(PKGROOT)/usr/share/nxs/configs/nxs.conf.example"
	@mkdir -p "$(RPMTOP)/BUILD" "$(RPMTOP)/BUILDROOT" "$(RPMTOP)/RPMS" "$(RPMTOP)/SOURCES" "$(RPMTOP)/SRPMS"
	@rpmbuild \
		--define "_topdir $(abspath $(RPMTOP))" \
		--define "pkgroot $(abspath $(PKGROOT))" \
		--define "projectroot $(abspath .)" \
		--define "version $(RPM_VERSION)" \
		--define "release $(RPM_RELEASE)" \
		-bb "$(SPECFILE)"
	@echo "📦 Built RPM under $(RPMTOP)/RPMS"

release: clean build deb rpm sync-release ## Full release pipeline (build + deb + rpm + sync)
	@echo "🚀 Release completed for version $(VERSION)"
