# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx/go:1.26.4-r0-cb8702a93db4a4@sha256:cb8702a93db4a4b07da9c6e6e93bf412091e7b121b6ade95aa4228ec5fae4301 AS builder

WORKDIR /app

#Copy go mod and sum files
COPY go.mod .
COPY go.sum .

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

# COPY the source code as the last step
COPY . .

RUN GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -a -o /app/2ms .

# Runtime image
FROM checkmarx/git:2.55.0-r4-25f9c40d0991ae@sha256:25f9c40d0991aeb3fab4f68bc8b96e9af819ebf3bcd2d882eb1f735a03485967

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]