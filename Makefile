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

BIN_DIR  := bin
MAIN_DIR := cmd/nxs
BINARY   := $(BIN_DIR)/nxs
PKGROOT  ?= build/pkgroot
RPMTOP   ?= packaging/rpm
SPECFILE ?= $(RPMTOP)/SPECS/nxs.spec
ARCH     ?= x86_64

override ARCH    := amd64
override VERSION := $(shell date +%Y.%m.%d-%H%M%S)
override PKGROOT := build/pkgroot
override OUTDIR  := build/deb
BIN        := bin/nxs
CONFIG_DIR := configs
DEB_SRC    := packaging/debian/DEBIAN
SERVICE    := packaging/nxs.service

# --- Remote Sync ---
REMOTE_USER ?= chris
REMOTE_HOST ?= repo.nixpal.com
REMOTE_PORT ?= 65535
REMOTE_DIR  ?= ~/packages/
SYNC_ON_RELEASE ?= 1

RSYNC_FLAGS ?= -av --partial --inplace
SSH_CMD     ?= ssh -p $(REMOTE_PORT)

# --- Go build ---
GOOS        ?= linux
GOARCH      ?= amd64
GOAMD64     ?= v1
GOAMD64     := $(strip $(GOAMD64))
CGO_ENABLED ?= 0

GH := gh

# -------------------------------
# Phony targets
# -------------------------------
.PHONY: help setup update build run clean git clean-deb clean-rpm distclean \
        stage-pkgroot stage-rpm rpm_prep_dirs rpm_spec_version deb rpm release sync

# -------------------------------
# Help
# -------------------------------
help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# -------------------------------
# Setup / update
# -------------------------------
setup: ## First-time setup after git clone
	go mod tidy
	@echo "✅ Setup complete."

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.' || true
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

# -------------------------------
# Build
# -------------------------------
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

run: build ## Run the binary
	@./$(BINARY)

# -------------------------------
# Staging (shared by deb + rpm)
# -------------------------------
stage-pkgroot: build
	@echo "→ Staging into $(PKGROOT)"
	@mkdir -p \
		$(PKGROOT)/usr/bin \
		$(PKGROOT)/usr/lib/systemd/system \
		$(PKGROOT)/usr/share/nxs/configs \
		$(PKGROOT)/usr/share/nxs/signatures \
		$(PKGROOT)/etc/nxs
	@cp -f $(BINARY) $(PKGROOT)/usr/bin/nxs
	@cp -f $(SERVICE) $(PKGROOT)/usr/lib/systemd/system/nxs.service
	@[ -f $(PKGROOT)/etc/nxs/nxs.conf ] || cp -f $(CONFIG_DIR)/nxs.conf $(PKGROOT)/etc/nxs/
	@cp -f $(CONFIG_DIR)/nxs.conf.example  $(PKGROOT)/usr/share/nxs/configs/
	@cp -f $(CONFIG_DIR)/hashdb.csv        $(PKGROOT)/usr/share/nxs/configs/
	@find $(CONFIG_DIR)/signatures -maxdepth 1 \( -name '*.yar' -o -name '*.yara' \) \
		-exec install -m0644 {} $(PKGROOT)/usr/share/nxs/signatures/ \;

stage-rpm: stage-pkgroot
	@echo "→ Ensuring RPM systemd unit path"
	@mkdir -p $(PKGROOT)/usr/lib/systemd/system
	@cp -f $(SERVICE) $(PKGROOT)/usr/lib/systemd/system/nxs.service

# -------------------------------
# DEB
# -------------------------------
deb: build ## Build .deb package
	@echo "PKGROOT=[$(PKGROOT)] OUTDIR=[$(OUTDIR)]"
	@test -n "$(PKGROOT)" && test -n "$(OUTDIR)"
	@rm -rf "$(PKGROOT)" && mkdir -p \
		"$(PKGROOT)/DEBIAN" \
		"$(PKGROOT)/usr/bin" \
		"$(PKGROOT)/lib/systemd/system" \
		"$(PKGROOT)/usr/share/nxs/configs" \
		"$(PKGROOT)/usr/share/nxs/signatures" \
		"$(PKGROOT)/etc/nxs" \
		"$(OUTDIR)"
	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"
	@install -m0755 "$(BIN)"     "$(PKGROOT)/usr/bin/nxs"
	@install -m0644 "$(SERVICE)" "$(PKGROOT)/lib/systemd/system/nxs.service"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf"         "$(PKGROOT)/etc/nxs/nxs.conf"
	@install -m0640 "$(CONFIG_DIR)/nxs.conf.example" "$(PKGROOT)/usr/share/nxs/configs/"
	@install -m0640 "$(CONFIG_DIR)/hashdb.csv"        "$(PKGROOT)/usr/share/nxs/configs/"
	@find $(CONFIG_DIR)/signatures -maxdepth 1 \( -name '*.yar' -o -name '*.yara' \) \
		-exec install -m0644 {} "$(PKGROOT)/usr/share/nxs/signatures/" \;
	@chmod 0755 "$(PKGROOT)/DEBIAN/postinst" "$(PKGROOT)/DEBIAN/prerm" "$(PKGROOT)/DEBIAN/postrm" 2>/dev/null || true
	@fakeroot dpkg-deb --build "$(PKGROOT)" "$(OUTDIR)/nxs_$(VERSION)-1_$(ARCH).deb"
	@echo "📦 Built: $(OUTDIR)/nxs_$(VERSION)-1_$(ARCH).deb"

# -------------------------------
# RPM helpers
# -------------------------------
rpm_prep_dirs:
	@mkdir -p $(RPMTOP)/{BUILD,BUILDROOT,RPMS,SRPMS,SPECS,SOURCES}

rpm_spec_version:
	@sed -i 's/^Version:.*/Version:        $(RPM_VERSION)/' $(SPECFILE)
	@sed -i 's/^Release:.*/Release:        $(RPM_RELEASE)%{?dist}/' $(SPECFILE)

# -------------------------------
# RPM
# -------------------------------
rpm: rpm_prep_dirs rpm_spec_version stage-rpm ## Build .rpm package
	@echo "→ Creating RPM: nxs-$(RPM_VERSION)-$(RPM_RELEASE)"
	@rpmbuild \
		--define "_topdir $(CURDIR)/$(RPMTOP)" \
		--define "_binary_payload w9.gzdio" \
		--define "debug_package %{nil}" \
		--define "pkgroot $(CURDIR)/$(PKGROOT)" \
		--define "projectroot $(CURDIR)" \
		--buildroot "$(CURDIR)/$(RPMTOP)/BUILDROOT" \
		--target $(RPM_ARCH) \
		-bb $(SPECFILE)
	@echo "✅ RPMs under: $(RPMTOP)/RPMS/$(RPM_ARCH)"

# -------------------------------
# Sync to remote package repo
# -------------------------------
sync: ## Upload latest deb + rpm to remote repo server
	@set -euo pipefail; \
	DEB_FILE="$$(ls -1t build/deb/nxs_*_amd64.deb 2>/dev/null | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/nxs-*.rpm 2>/dev/null | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "❌ No .deb found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "❌ No .rpm found in packaging/rpm/RPMS"; exit 1; }; \
	echo "🌐 Syncing to $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)"; \
	$(SSH_CMD) $(REMOTE_USER)@$(REMOTE_HOST) "mkdir -p $(REMOTE_DIR)/deb $(REMOTE_DIR)/rpm"; \
	echo "→ Upload: $$DEB_FILE → $(REMOTE_DIR)/deb/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$DEB_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/deb/"; \
	echo "→ Upload: $$RPM_FILE → $(REMOTE_DIR)/rpm/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$RPM_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/rpm/"; \
	if [ -f checksums.txt ]; then \
		rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" checksums.txt "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/"; \
	fi; \
	echo "✅ Remote sync complete."

# -------------------------------
# Release (deb + rpm + GitHub)
# -------------------------------
release: deb rpm ## Build packages + create GitHub release
	@set -euo pipefail; \
	echo "🔐 Checking GitHub auth..."; \
	$(GH) auth status -h github.com >/dev/null || { echo "Run: gh auth login"; exit 1; }; \
	DEB_FILE="$$(ls -1t build/deb/nxs_*_amd64.deb | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/nxs-*.rpm | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "No .deb found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "No .rpm found in packaging/rpm/RPMS"; exit 1; }; \
	echo "📦 DEB=$$DEB_FILE"; echo "📦 RPM=$$RPM_FILE"; \
	sha256sum "$$DEB_FILE" "$$RPM_FILE" > checksums.txt; \
	REPO="chrismfz/nxs"; \
	echo "🚀 Ensuring release $(TAG) exists..."; \
	if ! $(GH) release view "$(TAG)" --repo "$$REPO" >/dev/null 2>&1; then \
		$(GH) release create "$(TAG)" \
			--repo "$$REPO" \
			--title "nxs $(TAG)" \
			--notes "Automated release" \
			--draft; \
		echo "✅ Created draft release $(TAG)."; \
	else \
		echo "↻ Release $(TAG) already exists."; \
	fi; \
	echo "⬆️  Uploading assets..."; \
	$(GH) release upload "$(TAG)" "$$DEB_FILE" "$$RPM_FILE" checksums.txt \
		--repo "$$REPO" --clobber; \
	echo "✅ Assets uploaded."; \
	echo "📣 Publishing release..."; \
	$(GH) release edit "$(TAG)" --repo "$$REPO" --draft=false; \
	echo "✅ Release $(TAG) published."

# -------------------------------
# Git helper
# -------------------------------
git: ## Commit + push with custom message
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push

# -------------------------------
# Clean
# -------------------------------
clean: ## Remove binary and pkgroot
	@rm -f bin/nxs
	@rm -rf build/pkgroot
	@echo "🧹 Cleaned: bin, build/pkgroot"

clean-deb: ## Remove deb artifacts
	@rm -rf build/deb
	@rm -f build/*.deb build/deb/*.deb
	@find build -maxdepth 2 -type f -name '*.deb' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: deb artifacts"

clean-rpm: ## Remove rpm artifacts (keeps SPECS/)
	@rm -rf packaging/rpm/BUILD packaging/rpm/BUILDROOT
	@rm -rf packaging/rpm/RPMS packaging/rpm/SRPMS packaging/rpm/SOURCES
	@find packaging/rpm -type f -name '*.rpm' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: rpm artifacts (kept SPECS/)"

distclean: clean clean-deb clean-rpm ## Full cleanup
	@echo "🧨 Distclean done"
