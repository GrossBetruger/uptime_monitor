use std::env;
use std::net::{SocketAddr, TcpStream};
use std::process::exit;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn usage_and_exit() -> ! {
    eprintln!("Usage: uptime_monitor <interval_seconds>");
    eprintln!("Example: uptime_monitor 5");
    exit(1);
}

fn parse_interval() -> Duration {
    let secs_str = env::args().nth(1).unwrap_or_else(|| usage_and_exit());
    let secs: u64 = secs_str.parse().unwrap_or_else(|_| {
        eprintln!("Invalid number of seconds: {}", secs_str);
        usage_and_exit();
    });
    if secs == 0 {
        eprintln!("Interval must be at least 1 second.");
        usage_and_exit();
    }
    Duration::from_secs(secs)
}

fn check_internet(timeout: Duration) -> bool {
    // Well-known public DNS servers (using IPs avoids relying on DNS)
    let targets: [SocketAddr; 3] = [
        "1.1.1.1:53".parse().unwrap(),
        "8.8.8.8:53".parse().unwrap(),
        "1.0.0.1:53".parse().unwrap(),
    ];

    for addr in targets {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() {
    let interval = parse_interval();
    let timeout = Duration::from_secs(2);

    println!(
        "Starting uptime monitor: checking connectivity every {}s (timeout {}s). Press Ctrl+C to stop.",
        interval.as_secs(),
        timeout.as_secs()
    );

    loop {
        let online = check_internet(timeout);
        let status = if online { "online" } else { "offline" };
        // Print a simple timestamp (Unix seconds) to make logs easy to parse
        println!("[{}] Internet is {}", now_unix(), status);

        sleep(interval);
    }
}

