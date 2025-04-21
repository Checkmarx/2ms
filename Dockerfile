# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM cgr.dev/chainguard/go@sha256:7f9e74e1af376a6d238077d8df037a25001997581630bc121c8aecfa5c8da8b3 AS builder

WORKDIR /app

#Copy go mod and sum files
COPY go.mod .
COPY go.sum .

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

# COPY the source code as the last step
COPY . .

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -a -o /app/2ms .

# Runtime image
FROM cgr.dev/chainguard/git@sha256:2545cd570d26257e45c9d302cc459816ffc1e97de90d31e599782d56be7ab40e

WORKDIR /app

COPY --chown=65532:65532 --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo      

ENTRYPOINT [ "/app/2ms" ]
