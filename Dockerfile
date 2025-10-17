# kics-scan disable=b03a748a-542d-44f4-bb86-9199ab4fd2d5,fd54f200-402c-4333-a5a4-36ef6709af2f
# disable kics Healthcheck result
# and "Missing User Instruction" since 2ms container is stopped after scan

# Builder image
FROM checkmarx/go:1.25.2-r0-1362f4e5a16bb5@sha256:1362f4e5a16bb5dd639020ca7890c99245ab4111f8b3bf360eac87df79e2f4cf AS builder

ARG GOEXPERIMENT=jsonv2
ENV GOEXPERIMENT=$GOEXPERIMENT

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
FROM checkmarx/git:2.49.0-r2-d7ebbe7c56dc47@sha256:d7ebbe7c56dc478c08aba611c35b30689090d28605d83130ce4d1e15a84f0389

WORKDIR /app

RUN chown -R 65532:65532 /app

USER 65532

COPY --from=builder /app/2ms /app/2ms

RUN git config --global --add safe.directory /repo

ENTRYPOINT [ "/app/2ms" ]