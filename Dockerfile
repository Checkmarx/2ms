# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx/go:1.27.2-r0-dc43c4faad95df@sha256:dc43c4faad95df3daa54d2407c169fefd057960b2e6e4b8b46e85cb3738e057c AS builder

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
FROM checkmarx/git:2.56.0-r2-2489ee3badd412@sha256:2489ee3badd4128af07129b3901a3d9cad43e7d5f6a9ade41f3f10708fb7e328

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]