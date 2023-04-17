image_label ?= latest
image_name ?= checkmarx/2ms:$(image_label)

build:
	docker build -t $(image_name) .

run:
	docker run -it --rm $(image_name) $(ARGS)