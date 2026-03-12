# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx/go:1.26.1-r0-ce13f12ff5c411@sha256:ce13f12ff5c4114de1df95b2442911adab6c5a3ee580945176213f78c94ca0c6 AS builder

WORKDIR /app

#Copy go mod and sum files
COPY go.mod .
COPY go.sum .

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

# COPY the source code as the last step
COPY . .

ARG VERSION=dev
RUN GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w -X github.com/checkmarx/2ms/v5/cmd.Version=${VERSION}" -a -o /app/2ms .

# Runtime image
FROM checkmarx/git:2.53.0-r0-550d658abf13b0@sha256:550d658abf13b060746bcc629daaa6eaf6ee66364e5b5fa6216eb92f5e4d0f97

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]