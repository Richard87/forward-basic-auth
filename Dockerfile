############################
# Shamelessly stolen from
# https://chemidy.medium.com/create-the-smallest-and-secured-golang-docker-image-based-on-scratch-4752223b7324
############################
FROM golang:alpine AS builder

# Git is required for fetching the dependencies.
RUN apk update && apk add --no-cache git

# Create appuser.
ENV USER=appuser
ENV UID=10001

# See https://stackoverflow.com/a/55757473/12429735RUN
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR $GOPATH/src/mypackage/myapp/

COPY . .
# Using go mod.
RUN go mod download
RUN go mod verify
# Build the binary.
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/server

############################
# STEP 2 build a small image
############################
FROM --platform=linux/amd64 scratch
# Import the user and group files from the builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
# Copy our static executable.
COPY --from=builder /go/bin/server /go/bin/server
# Use an unprivileged user.
USER appuser:appuser

# Run the hello binary.
ENTRYPOINT ["/go/bin/server"]