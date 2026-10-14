GO ?= go
GOFMT ?= gofmt

GOVULNCHECK_VERSION ?= v1.9.0
ACTIONLINT_VERSION ?= v1.7.12

.PHONY: fmt fmt-check vet test test-race test-integration prepare-vm test-vm test-benchmark build \
	test-policy test-governance vulncheck lint-actions verify verify-ci

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

prepare-vm:
	test/integration/vm/prepare.sh

test-vm:
	$(GO) test -tags=vm_integration ./test/integration -run TestDisposableVMFixture -count=1 -v

test-benchmark:
	$(GO) test ./benchmark/... -count=1

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/lpeco ./cmd/lpeco
	$(GO) build -trimpath -o bin/lpeco-c2-example ./cmd/lpeco-c2-example
	$(GO) build -trimpath -o bin/lpeco-bench ./benchmark/cmd/lpeco-bench

test-policy:
	sh ../.github/scripts/check-pr-policy_test.sh

test-governance:
	sh ../.github/scripts/check-governance.sh ..

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

lint-actions:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) ../.github/workflows/*.yml

verify: fmt-check vet test-race build
	git diff --check

verify-ci: verify test-policy test-governance lint-actions test-integration test-benchmark vulncheck
