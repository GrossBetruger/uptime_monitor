export USER_NAME=OrenK; cargo build --release; for i in $(seq 100); do target/release/uptime_monitor --url http://0.0.0.0:3000/ingest &; done
