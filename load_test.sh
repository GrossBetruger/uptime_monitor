for i in $(seq 1000); do ./target/release/uptime_monitor 1 http://35.192.73.198:3000/ingest   & sleep 0.1; done
