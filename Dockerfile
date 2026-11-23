# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

ARG TARGETARCH=amd64
ARG TYPST_VERSION=0.13.1

WORKDIR /app

# Typst CLI loading for target
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl xz-utils ca-certificates; \
    case "${TARGETARCH}" in \
        amd64) TYPST_ARCH="x86_64-unknown-linux-musl" ;; \
        *) echo "Nicht unterstützte Architektur: ${TARGETARCH} (nur amd64 wird unterstützt)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${TYPST_ARCH}.tar.xz" -o /tmp/typst.tar.xz; \
    tar -xJf /tmp/typst.tar.xz -C /tmp; \
    install -m 0755 "/tmp/typst-${TYPST_ARCH}/typst" /usr/local/bin/typst; \
    rm -rf /tmp/typst* /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY static ./static
COPY templates ./templates
COPY seeds/example_pack ./seeds/example_pack

ENV SQLX_OFFLINE=true
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl fonts-liberation; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 ins-isms; \
    useradd --system --uid 10001 --gid ins-isms --home-dir /var/lib/ins-isms --shell /usr/sbin/nologin ins-isms; \
    mkdir -p /var/lib/ins-isms/blobs /etc/ins-isms/pdf-templates; \
    chown -R ins-isms:ins-isms /var/lib/ins-isms /etc/ins-isms

COPY --from=builder /app/target/release/ins-isms /usr/local/bin/ins-isms
COPY --from=builder /usr/local/bin/typst /usr/local/bin/typst
COPY --from=builder /app/seeds/example_pack /opt/ins-isms/seeds/example_pack

WORKDIR /var/lib/ins-isms
USER ins-isms:ins-isms

ENV APP_ENV=production \
    BIND_ADDR=0.0.0.0:8080 \
    STORAGE_BACKEND=local \
    STORAGE_LOCAL_PATH=/var/lib/ins-isms/blobs \
    TYPST_BIN_PATH=/usr/local/bin/typst \
    TYPST_FONT_PATHS=/usr/share/fonts/truetype/liberation \
    SEED_STARTER_CONTENT=false

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/ins-isms"]
