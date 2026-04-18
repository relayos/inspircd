FROM alpine:3.21 AS builder

LABEL maintainer="RelayOS"

ARG CONFIGUREARGS="--enable-extras=ssl_gnutls,m_gecosjson,m_tarpit,m_webirc_metadata,m_metadata_trigger,m_http_metrics,m_geo_metadata,m_connectionhash_verify,mysql"
ARG BUILD_DEPENDENCIES="geoip-dev mariadb-dev pcre2-dev rapidjson-dev utfcpp"

RUN apk add --no-cache \
      bash \
      g++ \
      gcc \
      git \
      gnutls-dev \
      make \
      mariadb-dev \
      pcre2-dev \
      perl \
      pkgconfig \
      rapidjson-dev \
      ${BUILD_DEPENDENCIES}

RUN addgroup -g 10000 -S inspircd \
    && adduser -u 10000 -h /inspircd/ -D -S -G inspircd inspircd

WORKDIR /src/inspircd
COPY . /src/inspircd

RUN find src/modules -maxdepth 1 -type l -delete \
    && rm -rf build .configure GNUmakefile include/config.h \
    && make clean || true

RUN ./configure --prefix /inspircd --example-dir /inspircd/examples --uid 10000 --gid 10000 --development
RUN echo "$CONFIGUREARGS" | xargs --no-run-if-empty ./configure
RUN make -j"$(getconf _NPROCESSORS_ONLN)" install CPPFLAGS=-DUSE_SYSTEM_UTFCPP

RUN rm -rf /inspircd/conf/* \
    && mkdir -p /inspircd/conf

FROM alpine:3.21

ARG RUN_DEPENDENCIES="geoip mariadb-connector-c pcre2"

RUN apk add --no-cache \
      curl \
      gnutls \
      gnutls-utils \
      jq \
      mariadb-client \
      netcat-openbsd \
      su-exec \
      ${RUN_DEPENDENCIES} \
    && addgroup -g 10000 -S inspircd \
    && adduser -u 10000 -h /inspircd/ -D -S -G inspircd inspircd

COPY --from=builder --chown=inspircd:inspircd /inspircd/ /inspircd/
COPY --chown=inspircd:inspircd docker/custom_entrypoint.sh /inspircd/custom_entrypoint.sh

RUN chmod +x /inspircd/custom_entrypoint.sh

USER root
WORKDIR /

EXPOSE 6667 6697 7000 7443

ENTRYPOINT ["/bin/sh", "/inspircd/custom_entrypoint.sh"]

HEALTHCHECK \
    --interval=60s \
    --timeout=3s \
    --start-period=60s \
    --retries=3 \
  CMD /usr/bin/nc -z localhost 6667
