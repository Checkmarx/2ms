image_label ?= latest
image_name ?= checkmarx/2ms:$(image_label)
image_file_name ?= checkmarx-2ms-$(image_label).tar

build:
	docker build -t $(image_name) .

save: build
	docker save $(image_name) > $(image_file_name)

run:
	docker run -it $(image_name) $(ARGS)