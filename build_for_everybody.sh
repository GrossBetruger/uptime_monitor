for user in $(cat users.csv); do export USER_NAME=$user; echo "Building for: $user" && ./build_for_windows.sh && mv target/x86_64-pc-windows-gnu/release/uptime_monitor.exe "uptime_monitor_$user.exe" && cargo build --release && cp target/release/uptime_monitor monitor_$user && ./monitor_$user -t ; done

sh build_for_centos.sh 
sh extract_binary_centos.sh
mv uptime_monitor_centos uptime_monitor_udik

# Replace binaries in release_binaries with newly built ones (only if they exist in release_binaries)
# Then delete all newly built binaries from root directory
echo "Updating release_binaries..."
for binary in uptime_monitor_*.exe monitor_* uptime_monitor_udik; do
    if [ -f "$binary" ]; then
        if [ -f "release_binaries/$binary" ]; then
            echo "Replacing release_binaries/$binary"
            mv "$binary" "release_binaries/$binary"
        else
            echo "Deleting $binary (not in release_binaries)"
            rm "$binary"
        fi
    fi
done
echo "Done updating release_binaries."
