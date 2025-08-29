PROJECT_NAME := kfast
PKG := github.com/OWNER/REPO
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Respect go.mod for toolchain; no hard-coded versions
GOFLAGS := -trimpath
LDFLAGS := -s -w \
  -X 'main.version=$${VERSION:-dev}' \
  -X 'main.commit=$(COMMIT)' \
  -X 'main.date=$(DATE)' \
  -X 'main.builtBy=$${BUILT_BY:-local}'

.PHONY: build
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME) ./kfast.go

.PHONY: build-all
build-all:
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_linux_amd64 ./kfast.go
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_linux_arm64 ./kfast.go
	GOOS=darwin  GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_darwin_amd64 ./kfast.go
	GOOS=darwin  GOARCH=arm64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_darwin_arm64 ./kfast.go
	GOOS=windows GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_windows_amd64.exe ./kfast.go
	GOOS=windows GOARCH=arm64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(PROJECT_NAME)_windows_arm64.exe ./kfast.go

.PHONY: release
release:
	goreleaser release --clean

.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean
