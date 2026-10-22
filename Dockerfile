# syntax=docker/dockerfile:1

# Build on the native platform and cross-compile, so multi-arch builds do not
# run the Go toolchain under emulation.
ARG GO_VERSION=1.27
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/phparmor ./cmd/phparmor

# Directories the non-root runtime user must own (distroless has no shell).
RUN mkdir -p /out/rootfs/var/lib/phparmor/spool /out/rootfs/etc/phparmor \
    && cp deploy/config.container.yaml /out/rootfs/etc/phparmor/config.yaml

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/phparmor /phparmor
COPY --from=build --chown=65532:65532 /out/rootfs/var/lib/phparmor /var/lib/phparmor
COPY --from=build /out/rootfs/etc/phparmor /etc/phparmor

USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/phparmor"]
CMD ["-config", "/etc/phparmor/config.yaml"]
