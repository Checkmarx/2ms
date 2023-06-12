# Builder image
FROM golang:1.20.5-alpine3.18 AS builder

WORKDIR /app

COPY . .
RUN go mod download
RUN go build -o /app/2ms .

# Runtime image
# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5
# ^^^^ disable kics Healthcheck result
FROM alpine:3.18

RUN addgroup -S kics && adduser -S kics -G kics
USER kics

COPY --from=builder /app/2ms /2ms
ENTRYPOINT ["/2ms"]

