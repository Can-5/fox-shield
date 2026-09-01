# fox-shield origin — multistage distroless build
# Stage 1: build the Go binary.
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/shield ./cmd/shield

# Stage 2: minimal distroless runtime.
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/shield /shield
EXPOSE 8080
ENTRYPOINT ["/shield"]
