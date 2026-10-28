BINARY  := forge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Go: the local toolchain when installed, otherwise the same commands run in a
# container — so building needs only Docker. Output is owned by you, and the
# module/build caches live in .cache/ (gitignored), never in root-owned dirs.
GO_IMAGE ?= golang:1.27
ifeq ($(shell command -v go 2>/dev/null),)
GO = docker run --rm -u $(shell id -u):$(shell id -g) -v "$(CURDIR)":/src -w /src \
	-e HOME=/tmp -e GOCACHE=/src/.cache/go-build -e GOMODCACHE=/src/.cache/gomod \
	-e GOFLAGS=-buildvcs=false -e CGO_ENABLED -e GOOS -e GOARCH $(GO_IMAGE) go
else
GO = go
endif

# This machine's architecture in Go/Docker terms (for `make try`).
HOST_ARCH := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

# Distros the live tests run on (see internal/steps/live_container_test.go).
DISTROS := ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:12 debian:13
DISTRO  ?= ubuntu:24.04

# make deploy settings.
SSH_PORT ?= 22
SSH_OPTS ?=
ARGS     ?=

.DEFAULT_GOAL := help
.PHONY: help build dist try deploy run test test-distros vet fmt tidy clean FORCE

help: ## show this help
	@echo "forge $(VERSION) — make <target>"
	@echo
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  Examples:"
	@echo "    make try                                  # click through the wizard, nothing is changed"
	@echo "    make deploy HOST=root@203.0.113.10        # build, copy and run on a server"
	@echo "    make deploy HOST=ubuntu@srv ARGS=--dry-run SSH_PORT=2222"

build: ## build ./forge for this machine
	@echo "  build  ./$(BINARY) ($(VERSION))"
	@CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

dist: dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 ## static linux binaries (amd64+arm64) + checksums.txt
	@cd dist && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 > checksums.txt
	@cat dist/checksums.txt

dist/$(BINARY)-linux-%: FORCE
	@mkdir -p dist
	@echo "  build  $@ ($(VERSION))"
	@CGO_ENABLED=0 GOOS=linux GOARCH=$* $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ .

try: dist/$(BINARY)-linux-$(HOST_ARCH) ## click through the wizard in dry-run in a throwaway container (DISTRO=ubuntu:24.04)
	@docker run --rm -it -v "$(CURDIR)/dist/$(BINARY)-linux-$(HOST_ARCH)":/usr/local/bin/forge:ro \
		$(DISTRO) forge --dry-run $(ARGS)

deploy: ## build for HOST's arch, copy it over SSH and run it there (HOST=user@server)
	@test -n "$(HOST)" || { echo "usage: make deploy HOST=user@server [SSH_PORT=22] [SSH_OPTS=...] [ARGS=...]"; exit 2; }
	@SSH_PORT="$(SSH_PORT)" SSH_OPTS="$(SSH_OPTS)" scripts/deploy.sh "$(HOST)" $(ARGS)

run: build ## run forge on THIS machine (only when this machine is the server)
	sudo ./$(BINARY) $(ARGS)

test: ## unit tests (dry-run step engine, every supported distro simulated)
	@$(GO) test ./...

test-distros: ## real apt/sshd/fail2ban steps inside throwaway distro containers
	@mkdir -p dist
	@CGO_ENABLED=0 $(GO) test -c -o dist/steps.test ./internal/steps
	@for img in $(DISTROS); do \
		echo "== $$img"; \
		docker run --rm -e FORGE_LIVE=1 -v "$(CURDIR)/dist/steps.test:/steps.test:ro" $$img \
			/steps.test -test.run Live || exit 1; \
	done

vet: ## go vet
	@$(GO) vet ./...

fmt: ## gofmt -w
	@$(GO) fmt ./...

tidy: ## go mod tidy
	@$(GO) mod tidy

clean: ## remove binaries and the build cache
	@chmod -R u+w .cache 2>/dev/null || true
	rm -rf $(BINARY) dist .cache

FORCE:
