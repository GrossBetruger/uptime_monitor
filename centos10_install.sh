sudo dnf -y install curl ca-certificates gcc gcc-c++ make pkgconf-pkg-config openssl-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
rustc --version
cargo --version
rustup component add rustfmt clippy rust-analyzer
sudo dnf install git

