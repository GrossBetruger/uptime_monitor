# Build stage for CentOS 7.8.2003 on x86_64 architecture
FROM centos:7.8.2003 AS builder

# Fix yum repositories - CentOS 7 EOL, use vault.centos.org
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo

# Install build dependencies
# Note: openssl-devel is included for potential native dependencies, 
# but the project uses rustls-tls which doesn't require it
RUN yum update -y && \
    yum install -y \
    curl \
    ca-certificates \
    gcc \
    gcc-c++ \
    make \
    pkgconfig \
    openssl-devel \
    git \
    && yum clean all

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust installation
RUN rustc --version && cargo --version

# Set working directory
WORKDIR /build

# Copy Cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

ARG USER_NAME=UdiK

# Build the release binary
# Since we're building on CentOS 7.8.2003, the default target is x86_64-unknown-linux-gnu
# The binary will be compatible with CentOS 7.8.2003's glibc 2.17
# USER_NAME is used at compile time via option_env!() macro
RUN export USER_NAME=${USER_NAME}; cargo build --release
RUN target/release/uptime_monitor -t

# Runtime stage - minimal CentOS 7.8.2003 image
FROM centos:7.8.2003

# Fix yum repositories - CentOS 7 EOL, use vault.centos.org
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo

# Install runtime and build dependencies (for manual rebuilding)
RUN yum update -y && \
    yum install -y \
    ca-certificates \
    curl \
    gcc \
    gcc-c++ \
    make \
    pkgconfig \
    openssl-devel \
    git \
    && yum clean all

# Install Rust toolchain for manual rebuilding
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust installation
RUN rustc --version && cargo --version

# Copy the compiled binary from builder stage
COPY --from=builder /build/target/release/uptime_monitor /usr/local/bin/uptime_monitor

# Copy the Cargo project files for reference/debugging
COPY --from=builder /build /build

# Create a non-root user for security (optional)
# RUN useradd -m -u 1000 uptime && \
    # chown uptime:uptime /usr/local/bin/uptime_monitor

# Set working directory
WORKDIR /app

# # Switch to non-root user
# USER uptime

