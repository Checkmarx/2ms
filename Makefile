SHELL=/bin/bash

image_label ?= latest
image_name ?= checkmarx/2ms:$(image_label)
image_file_name ?= checkmarx-2ms-$(image_label).tar

GREEN := $(shell printf "\033[32m")
RED := $(shell printf "\033[31m")
RESET := $(shell printf "\033[0m")

COVERAGE_REQUIRED := 55
MOCKGEN_VERSION := 0.5.2
LINTER_VERSION := 2.5.0

.PHONY: lint
lint: check-linter-version
	go fmt ./...
	golangci-lint run -c ./.golangci.yml

get-linter:
	command -v golangci-lint ||curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v$(LINTER_VERSION)

modtidy:
	go mod tidy
	go mod vendor

.PHONY: test
test:
	go test -race -vet all -coverprofile=cover.out.tmp ./...
	grep -v -e "_mock\.go:" -e "/mocks/" -e "/docs/" cover.out.tmp > cover.out
	go tool cover -func=cover.out
	rm cover.out.tmp

save: build
	docker save $(image_name) > $(image_file_name)

build:
	docker build -t $(image_name) .

build-local:
	GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -a -o ./2ms .

generate: check-mockgen-version
	go generate ./...

check: lint test coverage-check

.PHONY: coverage-check
coverage-check: test
	@coverage=$$(go tool cover -func=cover.out | grep '^total:' | awk '{print $$3}' | sed 's/%//g'); \
	if awk "BEGIN {exit !($$coverage < $(COVERAGE_REQUIRED))}"; then \
		echo "error: coverage ($$coverage%) must be at least $(COVERAGE_REQUIRED)%"; \
		exit 1; \
	else \
		echo "test coverage: $$coverage% (threshold: $(COVERAGE_REQUIRED)%)"; \
	fi

.PHONY: test-coverage
test-coverage: test coverage-check

## cover-report: show html report
## If you don't have the cover.out file yet, just run the tests with make test
cover-report:
	go tool cover -html=cover.out
.PHONY: coverage-check

check-mockgen-version:
	@echo "Checking mockgen version..."
	@if command -v mockgen >/dev/null 2>&1; then \
		INSTALLED_VERSION=$$(mockgen -version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'); \
		if [ "$$INSTALLED_VERSION" = "$(MOCKGEN_VERSION)" ]; then \
			echo "$(GREEN)[OK]$(RESET) mockgen version $(MOCKGEN_VERSION) is installed"; \
		else \
			echo "$(RED)[ERROR]$(RESET) Wrong mockgen version: $$INSTALLED_VERSION (required: $(MOCKGEN_VERSION))"; \
			echo "Please install the correct version using:"; \
			echo "  go install  go.uber.org/mock/mockgen@v$(MOCKGEN_VERSION)"; \
			exit 1; \
		fi; \
	else \
		echo "$(RED)[ERROR]$(RESET) mockgen is not installed"; \
		echo "Please install it using:"; \
			echo "  go install  go.uber.org/mock/mockgen@v$(MOCKGEN_VERSION)"; \
		exit 1; \
	fi

check-linter-version:
	@echo "Checking golangci-lint version..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		INSTALLED_VERSION=$$(golangci-lint --version | grep -oE 'version [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2); \
		if [ "$$INSTALLED_VERSION" = "$(LINTER_VERSION)" ]; then \
			echo "$(GREEN)[OK]$(RESET) golangci-lint version $(LINTER_VERSION) is installed"; \
		else \
			echo "$(RED)[ERROR]$(RESET) Wrong golangci-lint version: $$INSTALLED_VERSION (required: $(LINTER_VERSION))"; \
			echo "Please install the correct version using:"; \
			echo "  make get-linter"; \
			exit 1; \
		fi; \
	else \
		echo "$(RED)[ERROR]$(RESET) golangci-lint is not installed"; \
		echo "Please install it using:"; \
		echo "  make get-linter"; \
		exit 1; \
	fi