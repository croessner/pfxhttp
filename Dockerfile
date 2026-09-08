# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.8-alpine3.24
ARG RUNTIME_IMAGE=alpine:3.24

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder

WORKDIR /build

COPY . ./

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

# Set necessary environment variables and compile the app.
ENV CGO_ENABLED=0

RUN apk --no-cache --upgrade add build-base git
RUN if [ -n "${TARGETOS}" ] && [ -n "${TARGETARCH}" ]; then \
        GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" make VERSION="${VERSION}"; \
    else \
        make VERSION="${VERSION}"; \
    fi

FROM ${RUNTIME_IMAGE}

ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/croessner/pfxhttp

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="${SOURCE}"
LABEL org.opencontainers.image.description="Postfix to HTTP wrapper"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN addgroup -S pfxhttp; \
    adduser -S pfxhttp -G pfxhttp -D -H -s /bin/nologin

RUN apk --no-cache --upgrade add ca-certificates bash curl
RUN mkdir /etc/pfxhttp

COPY --from=builder ["/build/pfxhttp", "./"]
COPY --from=builder ["/build/pfxhttp.yml", "/etc/pfxhttp/"]
COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

ENV ZONEINFO=/zoneinfo.zip

EXPOSE 23450

USER pfxhttp

CMD ["/usr/app/pfxhttp"]
