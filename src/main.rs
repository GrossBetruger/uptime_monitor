use std::env;
use std::net::{SocketAddr, TcpStream};
use std::process::exit;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn usage_and_exit() -> ! {
    eprintln!("Usage: uptime_monitor <interval_seconds> <report_url>");
    eprintln!("Example: uptime_monitor 5 https://webhook.site/your-id");
    exit(1);
}

fn parse_args() -> (Duration, String) {
    let mut args = env::args().skip(1);
    let secs_str = args.next().unwrap_or_else(|| usage_and_exit());
    let url = args.next().unwrap_or_else(|| usage_and_exit());
    let secs: u64 = secs_str.parse().unwrap_or_else(|_| {
        eprintln!("Invalid number of seconds: {}", secs_str);
        usage_and_exit();
    });
    if secs == 0 {
        eprintln!("Interval must be at least 1 second.");
        usage_and_exit();
    }
    (Duration::from_secs(secs), url)
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

fn report_status(url: &str, online: bool, timeout: Duration) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        timestamp: u64,
        status: &'a str,
    }

    let status = if online { "online" } else { "offline" };
    let payload = Payload {
        timestamp: now_unix(),
        status,
    };

    // Build a small blocking client with a timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .map_err(|e| format!("http post failed: {e}"))?;

    // Consider any 2xx a success
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("server responded with {}", resp.status()))
    }
}

fn main() {
    let (interval, url) = parse_args();
    let net_timeout = Duration::from_secs(2);
    let http_timeout = Duration::from_secs(5);

    println!(
        "Starting uptime monitor: check every {}s; reporting to {}",
        interval.as_secs(),
        url
    );
    println!("Press Ctrl+C to stop.");

    loop {
        let online = check_internet(net_timeout);
        let status_text = if online { "online" } else { "offline" };

        match report_status(&url, online, http_timeout) {
            Ok(_) => println!("[{}] Internet is {} (reported)", now_unix(), status_text),
            Err(e) => eprintln!("[{}] Internet is {} (report failed: {})", now_unix(), status_text, e),
        }

        sleep(interval);
    }
}

