for user in $(cat users.csv); do export USER_NAME=$user; echo "Building for: $user" && ./build_for_windows.sh && mv target/x86_64-pc-windows-gnu/release/uptime_monitor.exe "uptime_monitor_$user.exe" && cargo build && cp target/debug/uptime_monitor monitor_$user && ./monitor_$user -t ; done

sh build_for_centos.sh 
sh extract_binary_centos.sh
mv uptime_monitor_centos uptime_monitor_udik
