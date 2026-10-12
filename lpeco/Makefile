GO ?= go

.PHONY: fmt vet test test-race test-integration test-vm build verify

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test ./... -race

test-integration:
	$(GO) test -tags=integration ./test/integration -count=1 -v

test-vm:
	$(GO) test -tags=vm_integration ./test/integration -run TestDisposableVMFixture -count=1 -v

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/lpeco ./cmd/lpeco
	$(GO) build -trimpath -o bin/lpeco-c2-example ./cmd/lpeco-c2-example

verify: fmt vet test-race build
	git diff --check
