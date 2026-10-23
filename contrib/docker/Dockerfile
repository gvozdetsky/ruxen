# ruxen in a container. From the repository root:
#
#   docker build -f contrib/docker/Dockerfile -t ruxen .
#   docker run --rm -p 8080:8080 \
#       --security-opt seccomp=contrib/docker/seccomp-io_uring.json ruxen
#
# Docker's default seccomp profile denies io_uring; ruxen then runs on
# epoll, which is slower. seccomp-io_uring.json is that profile plus the
# three io_uring calls and unshare(CLONE_FILES), which gives each worker its
# own fd table: with it, ruxen runs on io_uring.
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
# nginx's mime.types, for a configuration that does `include mime.types` (#38).
COPY examples/mime.types /etc/ruxen/mime.types
# Its licence, nginx's, comes with it (#479).
COPY LICENSE NOTICE /usr/share/doc/ruxen/
# Run as a user of its own from the start, so nothing in the container
# runs as root (`user` only applies when ruxen starts as root).
RUN useradd --system --no-create-home --uid 10001 ruxen
USER ruxen
EXPOSE 8080
# SIGQUIT is the graceful stop (requests in flight finish); `docker stop`
# sends SIGKILL after its timeout.
STOPSIGNAL SIGQUIT
CMD ["ruxen", "-c", "/etc/ruxen/ruxen.conf"]
