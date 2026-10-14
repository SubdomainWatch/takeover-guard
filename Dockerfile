# Multi-stage hardened build for SubdomainWatch Takeover Guard
# Stage 1: Build binary
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Install certificates and build tools
RUN apk add --no-cache ca-certificates git

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and embedded assets
COPY . ./
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w -X main.version=2.2.0" -o /bin/subdomainwatch-guard ./cmd/subdomainwatch-guard

# Stage 2: Hardened Rootless Runtime Container (§2.1)
FROM alpine:3.20

LABEL org.opencontainers.image.title="SubdomainWatch Takeover Guard" \
      org.opencontainers.image.description="Shift-Left IaC Security Gate & Post-Apply Sentinel" \
      org.opencontainers.image.version="2.2.0" \
      org.opencontainers.image.vendor="SubdomainWatch" \
      org.opencontainers.image.source="https://github.com/SubdomainWatch/takeover-guard"

# Security: Create non-root user and group UID 10001 (§2.1)
RUN addgroup -g 10001 guard && \
    adduser -D -u 10001 -G guard -s /sbin/nologin guard && \
    apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/subdomainwatch-guard /usr/local/bin/subdomainwatch-guard

# Create workspace with appropriate permissions
WORKDIR /workspace
RUN chown -R guard:guard /workspace

# Drop all privileges and run as non-root
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/subdomainwatch-guard"]
CMD ["-plan", "tfplan.json"]
