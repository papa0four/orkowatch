# =============================================================================
# orkowatch Makefile
# Dev build/install helpers.
#    - End-user install scripts live under scripts/linux/, scripts/macos/ and
#      scripts/windows/.
# Intended for use on Linux, macOS, and WSL.
#
# install/uninstall are Unix-oriented and target /usr/local/bin.
# On native Windows or Git Bash outside WSL, use scripts/windows/install.ps1
# instead.
#
# Contributor Onboarding
# ----------------------
# Prerequisites:
#   - Go 1.26+         https://go.dev/dl/
#   - golangci-lint    https://golangci-lint.run/usage/install/
#   - gosec            go install github.com/securego/gosec/v2/cmd/gosec@latest
#   - govulncheck      go install golang.org/x/vuln/cmd/govulncheck@latest
#   - gitleaks         go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest
#   - checkmake        https://github.com/checkmake/checkmake
#   - syft             https://github.com/anchore/syft
#   - grype            https://github.com/anchore/grype
#   - shfmt            https://github.com/mvdan/sh/releases
#   - shellcheck       https://www.shellcheck.net/
#   - shellharden      https://github.com/anordal/shellharden
#   - pkgsite          go install golang.org/x/pkgsite/cmd/pkgsite@latest
#   - PSScriptAnalyzer Windows/pwsh only, for ps-lint
#
# Quick start:
#   make build         build for current platform
#   make check         run all local quality gates (mirrors CI)
#   make install       install binary to /usr/local/bin (Unix/WSL only)
#
# All targets mirror the CI pipeline. If make check passes locally, the
# pipeline should pass on push.
#
# Every target carries a "## <target>: <description>" line directly above it.
# help renders those in file order under their "##@ <Section>" headings, so a
# new target appears without editing help. makefile-check fails when any target
# defined in this file has no such line, so a target cannot go undocumented and
# therefore cannot go missing from help.
# =============================================================================

BINARY_NAME := owatch
BUILD_DIR   := bin
MAIN_PKG    := ./cmd/owatch/main.go
INSTALL_DIR := /usr/local/bin
SBOM_FILE   := sbom.json

# Directories holding end-user shell scripts, linted together so a script is
# never covered on one platform and skipped on another.
SHELL_SCRIPT_DIRS := scripts/linux scripts/macos

# Current Go target
GOOS    := $(shell go env GOOS)
GOARCH  := $(shell go env GOARCH)

# Windows builds need .exe
ifeq ($(GOOS), windows)
	BINARY := $(BUILD_DIR)/$(BINARY_NAME).exe
else
	BINARY := $(BUILD_DIR)/$(BINARY_NAME)
endif

# Use sudo unless already root
SUDO := $(shell [ "$$(id -u)" -eq 0 ] && echo "" || echo "sudo")

# Resolves the current version from git:
#   - Exactly at a tag:               v1.0.0
#   - N commits ahead of last tag:    v1.0.0-N-g<hash>
#   - No tags exist yet:              g<hash>
#   - Uncommitted changes present:    <above>-dirty
# Falls back to "dev" if git is unavailable
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Cross-platform release targets (mirrors CI cross-build matrix)
RELEASE_TARGETS := \
	linux/amd64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Every intended supported platform. Compiled as a gate, not shipped: a target
# here must build, but it ships only once its modules are implemented
SUPPORTED_TARGETS := \
	linux/amd64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	freebsd/amd64 \
	openbsd/amd64 \
	netbsd/amd64

# The distinct operating systems in SUPPORTED_TARGETS. Build constraints in this
# tree split on GOOS alone, so linting once per GOOS reaches every build-tagged
# file without repeating identical work per architecture. sort also dedupes.
SUPPORTED_GOOS := $(sort $(foreach t,$(SUPPORTED_TARGETS),$(word 1,$(subst /, ,$(t)))))

# =============================================================================
# Targets
# =============================================================================

# Written out rather than built from a variable: checkmake parses this file
# textually and does not expand variables, so a computed list reads to it as no
# phony declaration at all. checkmake's minphony and phonydeclared rules are
# what keep this list complete; makefile-check keeps help coverage complete.
.PHONY: build build-all check-platforms install uninstall fmt fmt-check vet lint lint-platforms govulncheck gosec test check makefile-check gitleaks syft-grype shell-lint ps-lint docs clean help

##@ Build

## build: compile the binary for the current platform into bin/
build:
	@echo "[*] Building $(BINARY_NAME) ($(GOOS)/$(GOARCH)) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build \
		-ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=$(VERSION)" \
		-o $(BINARY) $(MAIN_PKG)
	@echo "[+] Binary written to $(BINARY)"

## build-all: cross-compile for all release targets into bin/
build-all:
	@echo "[*] Building all release targets..."
	@mkdir -p $(BUILD_DIR)
	@$(foreach target,$(RELEASE_TARGETS), \
		$(eval GOOS_T   := $(word 1,$(subst /, ,$(target)))) \
		$(eval GOARCH_T := $(word 2,$(subst /, ,$(target)))) \
		$(eval EXT      := $(if $(filter windows,$(GOOS_T)),.exe,)) \
		echo "[*] Building $(GOOS_T)/$(GOARCH_T)..."; \
		CGO_ENABLED=0 GOOS=$(GOOS_T) GOARCH=$(GOARCH_T) go build \
			-ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=$(VERSION)" \
			-o $(BUILD_DIR)/$(BINARY_NAME)_$(GOOS_T)_$(GOARCH_T)$(EXT) \
			$(MAIN_PKG) || exit 1; \
		echo "[+] Done: $(BINARY_NAME)_$(GOOS_T)_$(GOARCH_T)$(EXT)"; \
	)
	@echo "[+] All targets built."

## check-platforms: verify every supported platform compiles
check-platforms:
	@echo "[*] Verifying every supported platform compiles..."
	@$(foreach target,$(SUPPORTED_TARGETS), \
		$(eval GOOS_T   := $(word 1,$(subst /, ,$(target)))) \
		$(eval GOARCH_T := $(word 2,$(subst /, ,$(target)))) \
		echo "[*] $(GOOS_T)/$(GOARCH_T)..."; \
		CGO_ENABLED=0 GOOS=$(GOOS_T) GOARCH=$(GOARCH_T) go build ./... || exit 1; \
	)
	@echo "[+] All supported platforms compile."

##@ Install / Uninstall

## install: build and install the binary to $(INSTALL_DIR) - Unix/WSL only
install: build
ifeq ($(GOOS), windows)
	@echo "[-] install is not supported on native Windows or Git Bash outside WSL."
	@echo "    Use scripts/windows/install.ps1 instead, or run this target from WSL."
	@exit 1
else
	@echo "[*] Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	$(SUDO) cp $(BINARY) $(INSTALL_DIR)/$(BINARY_NAME)
	$(SUDO) chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[+] $(BINARY_NAME) installed. Run '$(BINARY_NAME) --help' to verify."
endif

## uninstall: remove the installed binary from $(INSTALL_DIR) - Unix/WSL only
uninstall:
ifeq ($(GOOS), windows)
	@echo "[-] uninstall is not supported on native Windows or Git Bash outside WSL."
	@echo "    Use scripts/windows/uninstall.ps1 instead, or run this target from WSL."
	@exit 1
else
	@echo "[*] Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	$(SUDO) rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[+] $(BINARY_NAME) removed."
endif

##@ Quality Gates (mirror CI pipeline)

## fmt: format all Go source files in place
fmt:
	@echo "[*] Formatting Go source files..."
	@gofmt -w .
	@echo "[+] Formatting complete."

## fmt-check: verify Go formatting without modifying files (mirrors CI)
fmt-check:
	@echo "[*] Checking Go formatting..."
	@if [ "$$(gofmt -l . | wc -l)" -gt 0 ]; then \
		echo "[-] The following files are not formatted correctly:"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "[+] All files correctly formatted."

## vet: run go vet across all packages
vet:
	@echo "[*] Running go vet..."
	@go vet ./...
	@echo "[+] vet passed."

## lint: run golangci-lint for the host GOOS only
lint:
	@echo "[*] Running golangci-lint..."
	@golangci-lint run --timeout=5m
	@echo "[+] lint passed."

## lint-platforms: run golangci-lint once per supported GOOS
lint-platforms:
	@echo "[*] Linting every supported GOOS..."
	@$(foreach goos,$(SUPPORTED_GOOS), \
		echo "[*] $(goos)..."; \
		GOOS=$(goos) golangci-lint run --timeout=5m || exit 1; \
	)
	@echo "[+] All supported platforms lint clean."

## govulncheck: scan dependencies for known vulnerabilities
govulncheck:
	@echo "[*] Running govulncheck..."
	@govulncheck ./... && echo "[+] No vulnerabilities found." || (echo "[-] Vulnerabilities detected. Review output above." && exit 1)

## gosec: run Go security static analysis
gosec:
	@echo "[*] Running gosec..."
	@gosec ./... && echo "[+] No security issues found." || (echo "[-] Security issues detected. Review output above." && exit 1)

## test: run all tests with race detector
test:
	@echo "[*] Running tests..."
	@go test -race -count=1 ./...
	@echo "[+] All tests passed."

## check: run every quality gate in sequence
check: makefile-check fmt-check vet lint lint-platforms govulncheck gosec gitleaks syft-grype test check-platforms
	@echo ""
	@echo "[+] All quality gates passed."

##@ Linting

## makefile-check: validate Makefile syntax, execution graph, and help coverage
makefile-check:
	@echo "[*] Validating Makefile syntax..."
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) help > /dev/null && echo "[+] Makefile syntax OK." || (echo "[-] Makefile syntax error." && exit 1)
	@echo "[*] Validating Makefile execution graph..."
	@$(MAKE) -n build > /dev/null && echo "[+] Makefile dry run OK." || (echo "[-] Makefile dry run failed." && exit 1)
	@echo "[*] Checking every target is documented..."
	@missing=""; \
		for t in $$(grep -E '^[a-zA-Z0-9_-]+:([^=]|$$)' $(firstword $(MAKEFILE_LIST)) | sed 's/:.*//'); do \
		grep -qE "^## $$t:" $(firstword $(MAKEFILE_LIST)) || missing="$$missing $$t"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "[-] Targets with no '## <target>:' help line:$$missing"; \
		exit 1; \
	fi
	@echo "[+] All targets documented."
	@echo "[*] Running checkmake..."
	@checkmake $(firstword $(MAKEFILE_LIST))
	@echo "[+] checkmake passed."

## gitleaks: scan for accidentally committed secrets and credentials
gitleaks:
	@echo "[*] Running gitleaks..."
	@gitleaks git --verbose . && echo "[+] No secrets found." || (echo "[-] Secrets detected. Review output above." && exit 1)

## syft-grype: generate SBOM and scan for vulnerabilities
syft-grype:
	@echo "[*] Generating SBOM with syft..."
	@syft . -o syft-json=$(SBOM_FILE) --source-name=orkowatch --source-version=$(VERSION)
	@echo "[*] Scanning SBOM with grype..."
	@grype sbom:$(SBOM_FILE) --fail-on medium && echo "[+] No vulnerabilities found." || (echo "[-] Vulnerabilities detected. Review output above." && exit 1)

## shell-lint: lint and format-check the end-user shell scripts
shell-lint:
	@echo "[*] Checking shell script formatting with shfmt..."
	@shfmt -ln bash -d $(SHELL_SCRIPT_DIRS)
	@echo "[*] Running shellcheck..."
	@shellcheck --severity=warning --shell=bash $(foreach d,$(SHELL_SCRIPT_DIRS),$(d)/*.sh)
	@echo "[*] Running shellharden..."
	@shellharden --check $(foreach d,$(SHELL_SCRIPT_DIRS),$(d)/*.sh)
	@echo "[+] Shell lint passed."

## ps-lint: lint PowerShell scripts in scripts/windows/ (Windows/pwsh only)
ps-lint:
ifeq ($(GOOS), windows)
	@echo "[*] Running PSScriptAnalyzer..."
	@powershell -Command "\
		\$$results = Invoke-ScriptAnalyzer \
			-Path ./scripts/windows \
			-Recurse \
			-Severity Error,Warning \
			-Settings ./scripts/windows/.psscriptanalyzerconfig; \
		if (\$$results) { \
			\$$results | Format-Table RuleName,Severity,ScriptName,Line,Message -AutoSize; \
			exit 1; \
		} \
		Write-Host '[+] PSScriptAnalyzer passed.'"
else
	@echo "[*] ps-lint skipped, not running on Windows."
	@echo "    Run this target from a Windows PowerShell prompt to lint PS1 scripts."
endif

##@ Documentation

## docs: serve godoc locally at http://localhost:6060
docs:
	@echo "[*] Starting godoc server at http://localhost:6060"
	@echo "    Press Ctrl+C to stop."
	@pkgsite -http=:6060

##@ Utilities

## clean: remove all build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(SBOM_FILE)
	@echo "[+] Clean complete."

## help: list all available targets with descriptions
help:
	@echo ""
	@echo "Usage: make <target>"
	@awk ' \
		/^##@ / { printf "\n%s\n", substr($$0, 5); next } \
		/^## [a-zA-Z0-9_-]+:/ { \
			line = substr($$0, 4); \
			i = index(line, ":"); \
			printf "  %-18s %s\n", substr(line, 1, i - 1), substr(line, i + 2); \
		} \
	' $(firstword $(MAKEFILE_LIST))
	@echo ""
