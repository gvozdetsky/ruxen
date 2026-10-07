# ruxen in a container. From the repository root:
#
#   docker build -f contrib/docker/Dockerfile -t ruxen .
#   docker run --rm -p 8080:8080 \
#       --security-opt seccomp=contrib/docker/seccomp-io_uring.json ruxen
#
# Docker's default seccomp profile denies io_uring, which ruxen runs on;
# seccomp-io_uring.json is that profile plus the three io_uring calls.
# Mount your configuration over /etc/ruxen/ruxen.conf; listen on ports
# above 1024, since the container runs as an unprivileged user.

FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/ruxen /usr/local/bin/ruxen

FROM debian:bookworm-slim
COPY --from=build /usr/local/bin/ruxen /usr/local/bin/ruxen
COPY examples/minimal.conf /etc/ruxen/ruxen.conf
# ruxen doesn't switch users (the `user` directive), and refuses to start
# as root without `user root;`: run it as a user of its own.
RUN useradd --system --no-create-home --uid 10001 ruxen
USER ruxen
EXPOSE 8080
# SIGQUIT is the graceful stop (requests in flight finish); `docker stop`
# sends SIGKILL after its timeout.
STOPSIGNAL SIGQUIT
CMD ["ruxen", "-c", "/etc/ruxen/ruxen.conf"]
