FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        python3 \
        python3-pip \
        python3-venv \
        strace \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash sandbox
WORKDIR /workspace
