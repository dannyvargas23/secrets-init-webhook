# syntax=docker/dockerfile:1

# ── Stage 1: build ─────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk --no-cache add ca-certificates git

WORKDIR /build

# Download dependencies before copying source — improves layer cache reuse.
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

COPY . .

# Static binaries with debug info stripped.
# CGO_ENABLED=0  → fully static, compatible with distroless/scratch
# -trimpath      → remove local filesystem paths from binary (security)
# -ldflags -s -w → strip symbol table and DWARF (smaller binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /webhook ./cmd/webhook

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /secrets-init ./cmd/secrets-init

# ── Stage 2a: webhook runtime ─────────────────────────────────────────────────
# distroless/static-debian13:nonroot — CA certs and tzdata only.
# No shell, no package manager, no libc — minimal attack surface.
FROM gcr.io/distroless/static-debian13:nonroot AS webhook

COPY --from=builder /webhook /webhook
USER 65532:65532
ENTRYPOINT ["/webhook"]

# ── Stage 2b: secrets-init runtime ────────────────────────────────────────────
# Injected into target pods via init container. Resolves awssm:// env vars
# at container startup, then exec's the original application binary.
FROM gcr.io/distroless/static-debian13:nonroot AS secrets-init

COPY --from=builder /secrets-init /secrets-init
USER 65532:65532
ENTRYPOINT ["/secrets-init"]
