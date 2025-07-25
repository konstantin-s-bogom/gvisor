FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y curl gnupg2 git \
        python-is-python3 python3 python3-distutils python3-pip \
        build-essential crossbuild-essential-arm64 qemu-user-static \
        openjdk-11-jdk-headless zip unzip \
        apt-transport-https ca-certificates gnupg-agent \
        software-properties-common \
        pkg-config libffi-dev patch diffutils libssl-dev iptables kmod \
        clang crossbuild-essential-amd64 erofs-utils busybox-static libbpf-dev \
        iproute2 netcat libnuma-dev

# This package is needed to build eBPF on amd64, but not on arm64 where it
# doesn't exist.
RUN test "$(uname -m)" != x86_64 && exit 0 || apt-get install -y libc6-dev-i386

# Install Docker client for the website build.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository \
   "deb https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
RUN apt-get -y install docker-ce-cli

# Install gcloud.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-410.0.0-linux-x86_64.tar.gz | \
    tar zxf - google-cloud-sdk && \
    google-cloud-sdk/install.sh --quiet && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Download the official bazel binary. The APT repository isn't used because there is not packages for arm64.
RUN sh -c 'curl -o /usr/local/bin/bazel https://releases.bazel.build/8.3.1/release/bazel-8.3.1-linux-$(uname -m | sed s/aarch64/arm64/) && chmod ugo+x /usr/local/bin/bazel'
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bazel"]
