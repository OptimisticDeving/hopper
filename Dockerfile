FROM rustlang/rust:nightly-alpine AS builder

RUN apk --no-cache add libc-dev
RUN addgroup -S -g 65532 builder
RUN adduser -D -S -u 65532 -G builder builder

USER builder:builder

WORKDIR /home/builder/hopper

ADD . .
RUN --mount=type=cache,target=/home/builder/hopper/target,uid=65532,gid=65532\
    --mount=type=cache,target=/home/builder/.cargo,uid=65532,gid=65532\
    cargo build --release && cp /home/builder/hopper/target/release/hopper /home/builder/hopper/hopper

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /bin/
COPY --from=builder --chown=root:root /home/builder/hopper/hopper hopper

USER nonroot:nonroot

WORKDIR /app/
ENTRYPOINT [ "/bin/hopper" ]