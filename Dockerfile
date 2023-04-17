# Builder image
FROM golang:1.20.3-alpine3.17 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/2ms .

# Runtime image
FROM alpine
COPY --from=builder /app/2ms /2ms
ENTRYPOINT ["/2ms"]

