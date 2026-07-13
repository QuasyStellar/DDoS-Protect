# Stage 1: Build the eBPF C program into Go code
FROM ubuntu:24.04 AS bpf-builder

# Install clang, llvm, libbpf-dev, Go, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-headers-generic ca-certificates \
    gcc golang-go \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm || true

WORKDIR /build
COPY src/ ./src/
COPY daemon/generate.go daemon/go.mod daemon/go.sum ./daemon/

ENV GOFLAGS="-trimpath"
ENV GOTOOLCHAIN=auto

RUN cd daemon && go generate ./...

# Stage 2: Compile the Go daemon (with freshly generated BPF objects)
FROM golang:latest AS go-builder
WORKDIR /build

ENV GOTOOLCHAIN=auto
ENV GOFLAGS="-trimpath"

# Cache go modules as a separate layer
COPY daemon/go.mod daemon/go.sum ./
RUN go mod download

# Copy Go sources and freshly generated BPF objects from bpf-builder
COPY daemon/ ./daemon/
COPY --from=bpf-builder /build/daemon/xdpfilter_bpfel.go \
                         /build/daemon/xdpfilter_bpfeb.go \
                         /build/daemon/xdpfilter_bpfel.o \
                         /build/daemon/xdpfilter_bpfeb.o ./daemon/

WORKDIR /build/daemon

# Build for the target platform (multi-arch support via TARGETARCH — #38 fix)
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /out/ddos-daemon .

# Stage 3: Minimal final image with iptables/nftables for NAT Sync
FROM alpine:latest
RUN apk add --no-cache iptables nftables iproute2

COPY --from=go-builder /out/ddos-daemon /ddos-daemon

ENTRYPOINT ["/ddos-daemon"]
