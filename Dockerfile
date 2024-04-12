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
FROM cgr.dev/chainguard/bash@sha256:d99fd064eb2893d8fc50a81fad92cc49dceffac291974c64b2491a635a022d9c

#RUN git config --global --add safe.directory /repo

COPY --from=builder /app/2ms .

ENTRYPOINT [ "./2ms" ]