NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m
WARN_COLOR=\033[33;01m
DEPS = $(go list -f '{{range .TestImports}}{{.}} {{end}}' ./... | fgrep -v 'winrm')

# Single source of truth also read by .github/workflows/lint.yaml.
GOLANGCI_LINT_VERSION = $(shell cat .golangci-lint-version)
GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif
GOLANGCI_LINT = $(GOBIN)/golangci-lint

all: deps
	@mkdir -p bin/
	@printf "$(OK_COLOR)==> Building$(NO_COLOR)\n"
	@go build github.com/masterzen/winrm

deps:
	@printf "$(OK_COLOR)==> Installing dependencies$(NO_COLOR)\n"
	@go get -d -v ./...
	@echo $(DEPS) | xargs -n1 go get -d

updatedeps:
	go list ./... | xargs go list -f '{{join .Deps "\n"}}' | grep -v github.com/masterzen/winrm | sort -u | xargs go get -f -u -v

clean:
	@rm -rf bin/ pkg/ src/

format:
	go fmt ./...

test: deps
	@printf "$(OK_COLOR)==> Testing...$(NO_COLOR)\n"
	go test -race ./...

gen-ntlm-fixtures:
	@printf "$(OK_COLOR)==> Regenerating NTLM/bodgit interop fixtures$(NO_COLOR)\n"
	./scripts/ntlm-bodgit-fixtures/generate.sh

test-integration:
	go test ./integrationTest/... -v

lint:
	@if ! $(GOLANGCI_LINT) version 2>/dev/null | grep -q "$(GOLANGCI_LINT_VERSION:v%=%)"; then \
		printf "$(OK_COLOR)==> Installing golangci-lint $(GOLANGCI_LINT_VERSION)$(NO_COLOR)\n"; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	@printf "$(OK_COLOR)==> Linting$(NO_COLOR)\n"
	$(GOLANGCI_LINT) run ./...

.PHONY: all clean deps format gen-ntlm-fixtures lint test test-integration updatedeps
