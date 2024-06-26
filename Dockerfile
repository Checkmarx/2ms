# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM cgr.dev/chainguard/go@sha256:a06a462f22445088e8bbb4478dedf83228af0db9003cd4f4cde5981694bc3d3d AS builder 

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/2ms .

# Runtime image
FROM cgr.dev/chainguard/wolfi-base@sha256:6bc98699de679ce5e9d1d53b9d06b99acde93584bf539690d61ec538916b1e74

RUN apk add --no-cache bash=5.2.21-r1 git=2.45.1-r0 glibc=2.39-r5 glibc-locale-posix=2.39-r5 ld-linux==2.39-r5 libcrypt1=2.39-r5 && git config --global --add safe.directory /repo

COPY --from=builder /app/2ms .

ENTRYPOINT [ "./2ms" ]
