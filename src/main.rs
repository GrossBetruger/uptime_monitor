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

fn now_unix_and_rfc3339() -> (u64, String) {
    let unix = now_unix();
    let iso = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    (unix, iso)
}

fn log_offline(logger_file: &str) -> Result<(), String> {
    let (unix, iso) = now_unix_and_rfc3339();
    let line = format!("{} {} offline\n", unix, iso);
    std::fs::OpenOptions::new()
        .append(true)
        .open(logger_file)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .map_err(|e| format!("failed to write offline log: {e}"))?;

    Ok(())
}

fn report_status(line: &str, url: &str) -> Result<(), String> {
    // Support either `gist://<ID>/status.txt` or `https://api.github.com/gists/<ID>`
    if let Some(rest) = url.strip_prefix("gist://") {
        return report_status_gist(rest, "status.txt", &line);
    }

    if url.starts_with("https://api.github.com/gists/") {
        // Extract gist id from API URL
        let gist_id = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        return report_status_gist(gist_id, "status.txt", &line);
    }

    // // Fallback: generic plain-text POST
    // let client = reqwest::blocking::Client::builder()
    //     .timeout(timeout)
    //     .build()
    //     .map_err(|e| format!("failed to build http client: {e}"))?;
    // let resp = client
    //     .post(url)
    //     .header(reqwest::header::CONTENT_TYPE, "text/plain")
    //     .body(line)
    //     .send()
    //     .map_err(|e| format!("http post failed: {e}"))?;
    // if resp.status().is_success() { Ok(()) } else {
    //     let code = resp.status();
    //     let text = resp.text().unwrap_or_else(|_| "<no body>".into());
    //     Err(format!("server responded with {}: {}", code, text))
    // }
    Ok(())
}
fn report_status_gist(gist_id: &str, file_name: &str, line: &str) -> Result<(), String> {

    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    let timeout = Duration::from_secs(3);

    let token = std::env::var("GIST_TOKEN")
        .map_err(|_| "missing GIST_TOKEN env var (GitHub PAT with 'gist' scope)".to_string())?;

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    // --- 1) GET current gist to read existing content (if any) ---
    #[derive(Deserialize)]
    struct GistFile { content: Option<String>, truncated: Option<bool> }
    #[derive(Deserialize)]
    struct Gist { files: HashMap<String, GistFile> }

    let get_url = format!("https://api.github.com/gists/{}", gist_id);
    let gist_resp = client
        .get(&get_url)
        .header(reqwest::header::USER_AGENT, "uptime-monitor/0.3")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("gist GET failed: {e}"))?;
    if !gist_resp.status().is_success() {
        let code = gist_resp.status();
        let body = gist_resp.text().unwrap_or_default();
        return Err(format!("gist GET {}: {}", code, body));
    }
    let gist: Gist = gist_resp.json().map_err(|e| format!("gist GET parse failed: {e}"))?;

    let mut current = gist.files.get(file_name).and_then(|f| f.content.clone()).unwrap_or_default();
    if !current.is_empty() && !current.ends_with('\n') { current.push('\n'); }
    current.push_str(line);

    // --- 2) PATCH updated content back ---
    #[derive(Serialize)]
    struct GistUpdateFile { content: String }
    #[derive(Serialize)]
    struct GistUpdate { files: HashMap<String, GistUpdateFile> }

    let mut files = HashMap::new();
    files.insert(file_name.to_string(), GistUpdateFile { content: current });
    let update = GistUpdate { files };

    let patch_resp = client
        .patch(&get_url)
        .header(reqwest::header::USER_AGENT, "uptime-monitor/0.3")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .bearer_auth(&token)
        .json(&update)
        .send()
        .map_err(|e| format!("gist PATCH failed: {e}"))?;

    if patch_resp.status().is_success() {
        Ok(())
    } else {
        let code = patch_resp.status();
        let body = patch_resp.text().unwrap_or_default();
        Err(format!("gist PATCH {}: {}", code, body))
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

fn main() {
    let (interval, url) = parse_args();
    let net_timeout = Duration::from_secs(2);
    let logger_file = "offline.log";
    let public_ip = get_public_ip();
    // init logger file
    if std::path::Path::new(logger_file).exists() {
        std::fs::write(logger_file, "").unwrap();
    }
    
    println!(
        "Starting uptime monitor: check every {}s; reporting to {}",
        interval.as_secs(),
        url
    );
    println!("Press Ctrl+C to stop.");

    loop {
        let online = check_internet(net_timeout);
        let (unix, iso) = now_unix_and_rfc3339();
        let status_text = if online { "online" } else { "offline" };
        let line = format!("{} {} {} {}\n", unix, iso, public_ip, status_text);
        match report_status(&line, &url) {
            Ok(_) => println!("[{}] Internet is {} (reported), public IP: {}", now_unix(), status_text, public_ip),
            Err(e) => {
                eprintln!("[{}] Internet is {} (report failed: {}), public IP: {}", now_unix(), status_text, e, public_ip);
                log_offline(&logger_file).expect("failed to log offline");
            }
        }

        sleep(interval);
    }
}

