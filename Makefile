image_label ?= latest
image_name ?= checkmarx/2ms:$(image_label)
image_file_name ?= checkmarx-2ms-$(image_label).tar

build:
	docker build -t $(image_name) .

save: build
	docker save $(image_name) > $(image_file_name)

run:
	docker run -it $(image_name) $(ARGS)

# To run golangci-lint, you need to install it first: https://golangci-lint.run/usage/install/#local-installation
lint:
	golangci-lint run -v -E gofmt --timeout=5m
lint-fix:
	golangci-lint run -v -E gofmt --fix --timeout=5m