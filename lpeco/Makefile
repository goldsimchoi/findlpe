GO ?= go
GOFMT ?= gofmt

GOVULNCHECK_VERSION ?= v1.9.0
ACTIONLINT_VERSION ?= v1.7.12

.PHONY: fmt fmt-check vet test test-race test-integration test-vm build \
	test-policy test-governance vulncheck verify

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(find . -type f -name '*.go' -not -path './vendor/*' -print0 | xargs -0 -r $(GOFMT) -l)"; \
	status=$$?; \
	if [ "$$status" -ne 0 ]; then exit "$$status"; fi; \
	if [ -n "$$files" ]; then \
		printf '%s\n' "$$files"; \
		exit 1; \
	fi

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

test-policy:
	sh ../.github/scripts/check-pr-policy_test.sh

test-governance:
	sh ../.github/scripts/check-governance.sh ..

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

verify: fmt-check vet test-race build
	git diff --check
