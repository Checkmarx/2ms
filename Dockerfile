# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM cgr.dev/chainguard/go@sha256:ef5ed415d03d60169f72db591ac2f7fc3f8dd8de388956dd9355793601544463 AS builder

WORKDIR /app

#Copy go mod and sum files
COPY go.mod .
COPY go.sum .

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

# COPY the source code as the last step
COPY . .

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -a -installsuffix cgo -o /app/2ms .

# Runtime image
FROM cgr.dev/chainguard/git@sha256:0663e8c8a5c6fcad6cc2c08e7668d7b46f7aee025a923cee19f69475e187752a

WORKDIR /app

USER 65532

COPY --from=builder /app/2ms .

ENTRYPOINT [ "./2ms" ]
