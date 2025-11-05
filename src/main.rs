use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use polars::prelude::CsvReadOptions;
use polars::prelude::*;
use std::fs::File;
use std::io::Cursor;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH}; // brings `.decode()` into scope

const COMPILED_USER_ID: &str = match option_env!("USER_NAME") {
    Some(v) => v,
    None => "OrenK",
};

#[derive(Parser, Debug)]
#[command(name = "uptime_monitor")]
#[command(about = "Monitors internet uptime and reports status to a URL")]
#[command(version)]
struct Args {
    /// Interval in seconds between checks (must be at least 1)
    #[arg(short, long, value_name = "INTERVAL_SECONDS", value_parser = clap::value_parser!(u64).range(1..), default_value = "1")]
    interval_seconds: u64,

    #[arg(short, long, value_name = "USER", default_value = COMPILED_USER_ID)]
    user: String,

    /// Add a new user to users.csv (optional user name)
    #[arg(long = "add-user", value_name = "NEW_USER")]
    add_user: Option<Option<String>>,

    #[arg(short, long, value_name = "TEST", action = clap::ArgAction::SetTrue)]
    test: bool,

    /// Optional URL to override the URL from deobfuscation
    #[arg(long, value_name = "URL")]
    url: Option<String>,
}

fn _create_users_csv() -> PolarsResult<()> {
    // Helper method to statically create users.csv and commit it to the repository

    // Name must be PlSmallStr on 0.51 => "user".into()
    let users = Series::new(
        "user".into(),
        &[
            "OrenK", "DanGo", "OriA", "Drier", "MichaelZ", "TomerB", "NisimY", "UdiK", "Lioz",
        ],
    );

    // DataFrame::new takes Vec<Column>, so Series -> Column with .into()
    let mut df = DataFrame::new(vec![users.into()])?;

    // Write CSV (header on)
    let mut file = File::create("users.csv")?;
    CsvWriter::new(&mut file)
        .include_header(true)
        .finish(&mut df)?;

    Ok(())
}

fn parse_args() -> (Duration, String, Option<Option<String>>, bool, Option<String>) {
    let args = Args::parse();
    (
        Duration::from_secs(args.interval_seconds),
        args.user,
        args.add_user,
        args.test,
        args.url,
    )
}

fn is_internet_up(timeout: Duration) -> bool {
    // Well-known public DNS servers (using IPs avoids relying on DNS)
    let targets: [SocketAddr; 3] = [
        "1.1.1.1:53".parse().unwrap(), // Cloudflare DNS
        "8.8.8.8:53".parse().unwrap(), // Google DNS
        "1.0.0.1:53".parse().unwrap(), // Cloudflare DNS
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
    if !std::path::Path::new(logger_file).exists() {
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
    if resp.status().is_success() {
        Ok(())
    } else {
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
    let resp = client
        .get("https://api.ipify.org?format=json")
        .send()
        .unwrap();
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

fn report_main(logger_file: &str, url: &str, user_name: &str, public_ip: &str, isn_info: &str) {
    let (unix, iso) = now_unix_and_rfc3339();
    let status_text = "online";
    let line = format!(
        "{} {} {} {} {} {}\n",
        unix, iso, user_name, public_ip, isn_info, status_text
    );

    match report_status(&line, &url) {
        Ok(_) => {
            println!(
                "[{}] Internet is {} (reported), public IP: {}",
                now_unix(),
                status_text,
                public_ip
            );
            let mut unreported_offline: Vec<String> = Vec::new();
            if std::path::Path::new(logger_file).exists() {
                for line in std::fs::read_to_string(logger_file).unwrap().lines() {
                    match report_status(&line, &url) {
                        Ok(_) => {
                            println!("{}", line);
                        }
                        Err(e) => {
                            eprintln!("failed to report status: {}", e);
                            unreported_offline.push(line.to_string());
                        }
                    }
                    // sleep(Duration::from_secs(1));
                }
            }
            // remove offline.log
            if std::path::Path::new(logger_file).exists() {
                std::fs::remove_file(logger_file).expect("failed to remove offline.log");
            }

            if !unreported_offline.is_empty() {
                std::fs::write(logger_file, unreported_offline.join("\n")).expect("failed to write unreported offline");
            }
        }
        Err(e) => {
            eprintln!(
                "[{}] Internet is {} (report failed: {}), public IP: {}",
                now_unix(),
                status_text,
                e,
                public_ip
            );
            // log_offline(&logger_file, &line).expect("failed to log offline");
        }
    }
}

fn _prompt_user_name() -> String {
    println!("Enter your name: ");
    let mut name = String::new();
    std::io::stdin().read_line(&mut name).unwrap();
    name.trim().to_string()
}

fn users_series_from_url(url: &str) -> Result<Series, Box<dyn std::error::Error>> {
    let bytes = reqwest::blocking::get(url)?.error_for_status()?.bytes()?;
    let cursor = Cursor::new(bytes);

    let df = CsvReader::new(cursor)
        .with_options(CsvReadOptions::default().with_has_header(true))
        .finish()?;

    Ok(df.column("user")?.as_materialized_series_maintain_scalar())
}

fn server_str_from_url(url: &str) -> String {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(url)
        .send()
        .expect("[get request] failed to get server from url");
    let server_str: String = resp
        .text()
        .expect("[text response] failed to get server from url");
    server_str
}

fn decode_any_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD
        .decode(s)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| general_purpose::URL_SAFE.decode(s))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(s))
}

pub fn deobfuscate_server_str(server_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut text = server_str.trim().to_owned();

    for _ in 0..3 {
        let bytes = decode_any_b64(&text)?;
        // If the intermediate values are base64 strings, they're ASCII -> UTF-8 is safe here.
        text = String::from_utf8(bytes)?.trim().to_owned();
    }

    Ok(text)
}

fn add_user(new_user: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch all known users from GitHub
    let github_url =
        "https://raw.githubusercontent.com/GrossBetruger/uptime_monitor/refs/heads/main/users.csv";
    let mut known_users: Series = users_series_from_url(github_url)?;

    // If a new user is provided, append it
    if let Some(user) = new_user {
        // Check if user already exists
        let user_exists = known_users.str()?.equal(user.as_str()).any();
        if user_exists {
            println!("User '{}' already exists in users.csv", user);
            return Ok(());
        }

        // Append the new user
        // Convert Series to Vec<String>, append new user, then create new Series
        let mut users_vec: Vec<String> = known_users
            .str()?
            .into_iter()
            .map(|opt| opt.unwrap_or_default().to_string())
            .collect();
        users_vec.push(user.clone());
        known_users = Series::new("user".into(), users_vec);
        println!("Adding user '{}' to users.csv", user);
    } else {
        println!("No user name provided. Use --add-user <USER_NAME> to add a user.");
        return Ok(());
    }

    // Create DataFrame and write to local users.csv file
    let mut df = DataFrame::new(vec![known_users.into()])?;
    let mut file = File::create("users.csv")?;
    CsvWriter::new(&mut file)
        .include_header(true)
        .finish(&mut df)?;

    println!("Successfully updated users.csv");
    Ok(())
}

fn main() {
    _create_users_csv().unwrap();
    let (interval, user_arg, add_user_arg, test, url_override) = parse_args();

    // If add-user argument is present, run add_user and exit
    if let Some(new_user) = add_user_arg {
        match add_user(new_user) {
            Ok(_) => {
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error adding user: {}", e);
                std::process::exit(1);
            }
        }
    }

    if test {
        println!("welcome {}", user_arg);
        std::process::exit(0);
    };

    let url = if let Some(override_url) = url_override {
        println!("Using provided URL: {}", override_url);
        override_url
    } else {
        let server_str = server_str_from_url(
            "https://raw.githubusercontent.com/GrossBetruger/uptime_monitor/main/server.txt",
        );
        let deobfuscated_server_str =
            deobfuscate_server_str(&server_str.trim()).expect("failed to deobfuscate server string");
        println!("Server: {}", deobfuscated_server_str);
        deobfuscated_server_str
    };

    let known_users: Series = users_series_from_url(
        "https://raw.githubusercontent.com/GrossBetruger/uptime_monitor/refs/heads/main/users.csv",
    )
    .expect("failed to get users from url");
    let df = DataFrame::new(vec![known_users.clone().into()]).unwrap(); // Cast to df for pretty printing
    println!("Known users:\n{df:?}");

    // let user_name = prompt_user_name();
    let user_name = user_arg;

    match known_users.str().unwrap().equal(user_name.as_str()).any() {
        true => {
            println!("User: {} connected!", user_name);
        }
        false => {
            panic!("User: {} is not known", user_name);
        }
    }

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
            true => report_main(logger_file, &url, &user_name, &public_ip, &isn_info),
            false => {
                let (unix, iso) = now_unix_and_rfc3339();
                let offline_line = format!(
                    "{} {} {} {} {} {}\n",
                    unix, iso, user_name, public_ip, isn_info, "offline"
                );
                eprintln!(
                    "[{}] Internet is offline (logged locally to be reported later)",
                    now_unix()
                );
                log_offline(&logger_file, &offline_line).expect("failed to log offline");
            }
        }

        sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn rfc3339_to_unix(rfc3339_str: &str) -> Result<u64, String> {
        chrono::DateTime::parse_from_rfc3339(rfc3339_str)
            .map(|dt| dt.timestamp() as u64)
            .map_err(|e| format!("Failed to parse RFC3339 string: {}", e))
    }

    #[test]
    fn test_get_public_ip() {
        let ip = get_public_ip();
        assert!(!ip.is_empty());
    }

    #[test]
    fn test_get_isn_info() {
        let isn_info = get_isn_info();
        assert!(!isn_info.is_empty());
    }

    #[test]
    fn test_report_main() {
        let logger_file = "offline.log";
        let url = "https://api.github.com/gists/628c7bbc22cbc46b97e4d343059eeac7";
        let user_name = "OrenK";
        let public_ip = "127.0.0.1";
        let isn_info = "Israel";
        report_main(logger_file, &url, &user_name, &public_ip, &isn_info);
    }

    #[test]
    fn test_users_series_from_url() {
        let url = "https://raw.githubusercontent.com/GrossBetruger/uptime_monitor/refs/heads/main/users.csv";
        let users_series = users_series_from_url(url).unwrap();
        assert!(!users_series.is_empty());
    }

    #[test]
    fn test_log_offline() {
        let logger_file = "test_logger.log";
        let line = "1730336000 2025-02-28T12:53:20+02:00 OrenK 127.0.0.1 Israel online\n";
        log_offline(logger_file, &line).unwrap();
        assert!(std::path::Path::new(logger_file).exists());
        std::fs::remove_file(logger_file).unwrap();
    }

    #[test]
    fn test_is_internet_up() {
        let result = is_internet_up(Duration::from_secs(2));
        assert!(result);
    }

    #[test]
    fn test_now_unix_and_rfc3339() {
        let (unix, iso): (u64, String) = now_unix_and_rfc3339();
        let unix_timestamp = rfc3339_to_unix(&iso).unwrap();
        assert_eq!(unix, unix_timestamp);
    }

    #[test]
    fn test_url_fetching() {
        let url = "https://raw.githubusercontent.com/GrossBetruger/uptime_monitor/main/server.txt";
        let server_str = server_str_from_url(url);
        assert!(!server_str.is_empty());
        let deobfuscated_server_str = deobfuscate_server_str(&server_str).unwrap();
        let re = Regex::new(r"^http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/\w+$").unwrap();
        assert!(re.is_match(&deobfuscated_server_str));
    }
}
