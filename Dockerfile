# Builder image
FROM golang:1.20.5-alpine3.18 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/2ms .

# Runtime image
# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5
# ^^^^ disable kics Healthcheck result
FROM alpine:3.18

RUN apk add --no-cache git=2.40.1-r0

RUN addgroup -S 2ms && adduser -S 2ms -G 2ms
USER 2ms

RUN git config --global --add safe.directory /repo

COPY --from=builder /app/2ms /2ms
ENTRYPOINT ["/2ms"]

