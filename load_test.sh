IP="$1"
for i in $(seq 10); do
  ./target/release/uptime_monitor 1 "http://$IP:3000/ingest" &
  sleep 0.1
done

