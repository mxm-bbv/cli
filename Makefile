BINARY := forge
VERSION := 0.1.0
LDFLAGS := -s -w

.PHONY: build build-linux vet fmt tidy clean run

build: ## build for the host platform
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-linux: ## cross-compile static linux binaries (amd64 + arm64)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .

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
