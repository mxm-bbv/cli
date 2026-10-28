BINARY  := forge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath

# Distros the live tests run on (see internal/steps/live_container_test.go).
DISTROS := ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:12 debian:13

.PHONY: build build-linux test test-distros vet fmt tidy clean run

build: ## build for the host platform
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-linux: ## cross-compile static linux binaries (amd64 + arm64)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .

test: ## unit tests (dry-run step engine, every supported distro simulated)
	go test ./...

test-distros: ## real apt/sshd/fail2ban steps inside throwaway containers (needs docker)
	CGO_ENABLED=0 go test -c -o dist/steps.test ./internal/steps
	@for img in $(DISTROS); do \
		echo "== $$img"; \
		docker run --rm -e FORGE_LIVE=1 -v "$(CURDIR)/dist/steps.test:/steps.test:ro" $$img \
			/steps.test -test.run Live || exit 1; \
	done

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

run: build
	sudo ./$(BINARY)

clean:
	rm -rf $(BINARY) dist
