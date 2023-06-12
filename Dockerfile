# Builder image
FROM golang:1.20.3-alpine3.17 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/2ms .

# Runtime image
# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5
# ^^^^ disable kics Healthcheck result
FROM alpine:3.17.3

RUN addgroup -S kics && adduser -S kics -G kics
USER kics

COPY --from=builder /app/2ms /2ms
ENTRYPOINT ["/2ms"]

