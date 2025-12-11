FROM debian:stable-slim

RUN apt update && apt install -y --no-install-recommends \
        mingw-w64 \
        make \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace