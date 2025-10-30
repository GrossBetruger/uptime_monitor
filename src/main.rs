use std::env;
use std::net::{SocketAddr, TcpStream};
use std::process::exit;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::Write;


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

fn is_internet_up(timeout: Duration) -> bool {
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

fn now_unix_and_rfc3339() -> (u64, String) {
    let unix = now_unix();
    let iso = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    (unix, iso)
}

fn log_offline(logger_file: &str, line: &str) -> Result<(), String> {
    // create file if not exists
    if ! std::path::Path::new(logger_file).exists() {
        std::fs::File::create(logger_file).unwrap();
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(logger_file)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .map_err(|e| format!("failed to write offline log: {e}"))?;

    Ok(())
}

fn report_status(line: &str, url: &str) -> Result<(), String> {
    let timeout = Duration::from_secs(5);

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let resp = client
        .get(url)
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body(line.to_string())
        .send()
        .map_err(|e| format!("http get failed: {e}"))?;
    if resp.status().is_success() { Ok(()) } else {
        let code = resp.status();
        let text = resp.text().unwrap_or_else(|_| "<no body>".into());
        Err(format!("server responded with {}: {}", code, text))
    }
}

fn get_public_ip() -> String {
    use serde::Deserialize;
    
    #[derive(Deserialize)]
    struct IpResponse {
        ip: String,
    }
    
    let client = reqwest::blocking::Client::new();
    let resp = client.get("https://api.ipify.org?format=json").send().unwrap();
    let ip_response: IpResponse = resp.json().unwrap();
    ip_response.ip
}

fn get_isn_info() -> String {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Data {
        connection: Connection,
    }
    #[derive(Deserialize)]
    struct Connection {
        org: String,
    }
    #[derive(Deserialize)]
    struct IsnResponse {
        data: Data,
    }
    let client = reqwest::blocking::Client::new();
    let resp = client.get("https://api.ipwho.org/me").send().unwrap();
    let isn_response: IsnResponse = resp.json().unwrap();
    isn_response.data.connection.org
}


fn report_main(logger_file: &str, url: &str, public_ip: &str, isn_info: &str) {
    let (unix, iso) = now_unix_and_rfc3339();
    let status_text = "online";
    let line = format!("{} {} {} {} {}\n", unix, iso, public_ip, isn_info, status_text);
    
    match report_status(&line, &url) {
        Ok(_) => {
            println!("[{}] Internet is {} (reported), public IP: {}", now_unix(), status_text, public_ip);
            if std::path::Path::new(logger_file).exists() {
                for line in std::fs::read_to_string(logger_file).unwrap().lines() {
                    report_status(&line, &url).unwrap();
                    println!("{}", line);
                    // sleep(Duration::from_secs(1));
                }
            }
            // remove offline.log
            if std::path::Path::new(logger_file).exists() {
                std::fs::remove_file(logger_file).unwrap();
            }
        }
        Err(e) => {
            eprintln!("[{}] Internet is {} (report failed: {}), public IP: {}", now_unix(), status_text, e, public_ip);
            // log_offline(&logger_file, &line).expect("failed to log offline");
        }
    }
}


fn main() {
    let (interval, url) = parse_args();
    let isn_info = get_isn_info();
    let logger_file = "offline.log";
    let public_ip = get_public_ip();
    // init logger file
    if std::path::Path::new(logger_file).exists() {
        std::fs::write(logger_file, "").unwrap();
    }
    
    println!(
        "Starting uptime monitor: check every {}s; reporting to {}",
        interval.as_secs(),
        &url
    );
    println!("Press Ctrl+C to stop.");
    let net_timeout = Duration::from_secs(2);

    loop {
        
        match is_internet_up(net_timeout) {
            true => report_main(logger_file, &url, &public_ip, &isn_info),
            false => {
                let (unix, iso) = now_unix_and_rfc3339();
                let offline_line = format!("{} {} {} {} {}\n", unix, iso, public_ip, isn_info, "offline");
                eprintln!("[{}] Internet is offline (logged locally to be reported later)", now_unix());
                log_offline(&logger_file, &offline_line).expect("failed to log offline");
            }
        }
     

        sleep(interval);
    }

}

