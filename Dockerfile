FROM --platform=$BUILDPLATFORM golang:1.23-alpine3.20 AS builder

WORKDIR /build

COPY . ./

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=0

RUN apk --no-cache --upgrade add build-base git
RUN make

FROM --platform=$BUILDPLATFORM alpine:3

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/pfxhttp"
LABEL org.opencontainers.image.description="Postfix to HTTP wrapper"
LABEL org.opencontainers.image.licenses=MIT
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
