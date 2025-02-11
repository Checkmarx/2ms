# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM cgr.dev/chainguard/go@sha256:36fee4a2334d13bbf585ad2225ea1ca99fe65de366022e561ac157de26fd5ed6 AS builder

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
FROM cgr.dev/chainguard/git@sha256:d32fb4fbb132929abae2d2f742e3d3bfdbd4937caa7021299130ad096227ced0

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]
