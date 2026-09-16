# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx/go:1.27.1-r0-424cf19b9e848d@sha256:424cf19b9e848d86bbf0ed45b216d782f064bfb6b1dd7eba7f5a8cc3f750088f AS builder

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
FROM checkmarx/git:2.55.0-r7-193d1e713216b7@sha256:193d1e713216b75b63eb05c3ebac0185620565b10a33d2ca1b3a89e8bd46c4fc

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]