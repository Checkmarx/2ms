# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx.jfrog.io/docker/chainguard/go:1.22.1-r1--1ebe124fc23465 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/2ms .

# Runtime image
FROM checkmarx.jfrog.io/docker/chainguard/busybox-jq-yq-bash-curl-awscli-git:1.36.1-r4--4993ffaa08557e

RUN git config --global --add safe.directory /repo

COPY --from=builder /app/2ms /2ms
ENTRYPOINT ["/2ms"]
