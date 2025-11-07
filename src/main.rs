use clap::{Arg, Command};
use mailparse::parse_mail;
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use colored::*;

#[derive(Serialize, Debug)]
struct EmailData {
    filename: Option<String>,
    received_spf: Option<String>,
    spf_passed: Option<bool>,
    return_path: Option<String>,
    from: Option<String>,
    to: Option<String>,
    reply_to: Option<String>,
    subject: Option<String>,
    links: Vec<String>,
    emails_in_body: Vec<String>,
    dkim_result: Option<String>,

}


fn main() {

    fn print_banner() {
        let banner = r#"
___________              .__.__    __________                                   
\_   _____/ _____ _____  |__|  |   \______   \_____ _______  ______ ___________ 
 |    __)_ /     \\__  \ |  |  |    |     ___/\__  \\_  __ \/  ___// __ \_  __ \
 |        \  Y Y  \/ __ \|  |  |__  |    |     / __ \|  | \/\___ \\  ___/|  | \/
/_______  /__|_|  (____  /__|____/  |____|    (____  /__|  /____  >\___  >__|   
        \/      \/     \/                          \/           \/     \/       
        "#;
        println!("{}", banner.bright_blue().bold());
    }

    /// Prints EmailData to terminal with bold headings
    fn print_email_data(data: &EmailData) {
    // ANSI escape codes for bold
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    println!("{}Make sure to manually check the file for residual artifacts{}\n", BOLD, RESET);
    println!("{}File Name:{} {}", BOLD, RESET, data.filename.as_deref().unwrap_or("N/A"));
    println!("{}Received SPF:{} {}", BOLD, RESET, data.received_spf.as_deref().unwrap_or("N/A"));
    println!(
        "{}SPF Passed:{} {}",
        BOLD,
        RESET,
        data.spf_passed
        .map(|p| p.to_string())
        .unwrap_or("N/A".to_string())
        );
    println!("{}DKIM Result:{} {}", BOLD, RESET, data.dkim_result.as_deref().unwrap_or("N/A"));
    println!("{}Return Path:{} {}", BOLD, RESET, data.return_path.as_deref().unwrap_or("N/A"));
    println!("{}From:{} {}", BOLD, RESET, data.from.as_deref().unwrap_or("N/A"));
    println!("{}To:{} {}", BOLD, RESET, data.to.as_deref().unwrap_or("N/A"));
    println!("{}Reply-To:{} {}", BOLD, RESET, data.reply_to.as_deref().unwrap_or("N/A"));
    println!("{}Subject:{} {}", BOLD, RESET, data.subject.as_deref().unwrap_or("N/A"));
    
    println!();

    println!("{}Links:{}\n", BOLD, RESET);
    for link in &data.links {
        println!("  - {}", link);
    }

    println!();

    println!("{}Emails Found in Body:{}\n", BOLD, RESET);
for email in &data.emails_in_body {
    println!("  - {}", email);

    println!();
}
}


let matches = Command::new("eml_parser")
.version("0.2.2")
.about("Parses .eml files (single or batch) and extracts SPF, headers, and links")
.arg(
    Arg::new("file")
    .short('f')
    .long("file")
    .help("Path to a single .eml file")
    .num_args(1),
    )
.arg(
    Arg::new("batch")
    .short('b')
    .long("batch")
    .help("Path to a directory containing multiple .eml files")
    .num_args(1),
    )
.arg(
    Arg::new("output")
    .short('o')
    .long("output")
    .help("Output format: csv, json, or txt")
    .num_args(1),
    )
.get_matches();

let output_format = matches.get_one::<String>("output").map(|s| s.as_str());

if let Some(batch_dir) = matches.get_one::<String>("batch").map(|s| s.as_str()) {
        // --- Batch mode ---
        let paths = fs::read_dir(batch_dir)
        .expect("Failed to read directory")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension()?.to_string_lossy().to_lowercase() == "eml" {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

        if paths.is_empty() {
            println!("No .eml files found in {}", batch_dir);
            return;
        }

        let mut results = Vec::new();

        print_banner();

        for path in paths {
            match process_eml(&path) {
                Ok(mut data) => {
                    data.filename = Some(path.file_name().unwrap().to_string_lossy().to_string());

                    print_email_data(&data);

println!(); // extra newline between emails


results.push(data);
}
Err(e) => eprintln!("Failed to process {}: {}", path.display(), e),
}
}

        // --- Optional combined output ---
        if let Some(fmt) = output_format {
            match fmt {
                "json" => {
                    let json = serde_json::to_string_pretty(&results).unwrap();
                    let mut file = File::create("output.json").unwrap();
                    file.write_all(json.as_bytes()).unwrap();
                    println!("Saved JSON results to output.json");
                }
                "csv" => {
                    let mut wtr = csv::Writer::from_path("output.csv").unwrap();
                    for r in results {
                        wtr.serialize(r).unwrap();
                    }
                    wtr.flush().unwrap();
                    println!("Saved CSV results to output.csv");
                }
                "txt" => {
                    let mut file = File::create("output.txt").unwrap();
                    for r in results {
                        writeln!(file, "{:#?}\n", r).unwrap();
                    }
                    println!("Saved TXT results to output.txt");
                }
                _ => println!("Unknown output format: {}", fmt),
            }
        }

    } else if let Some(file_path) = matches.get_one::<String>("file").map(|s| s.as_str()) {
        // --- Single file mode ---
        match process_eml(Path::new(file_path)) {
            Ok(mut data) => {
                data.filename = Some(
                    Path::new(file_path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                    );

                print_banner();

                print_email_data(&data);

                println!();

                if let Some(fmt) = output_format {
                    let base_name = Path::new(file_path)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();

                    match fmt {
                        "json" => {
                            let json = serde_json::to_string_pretty(&data).unwrap();
                            let mut file =
                            File::create(format!("{}_output.json", base_name)).unwrap();
                            file.write_all(json.as_bytes()).unwrap();
                            println!("Saved JSON to {}_output.json", base_name);
                        }
                        "csv" => {
                            let mut wtr =
                            csv::Writer::from_path(format!("{}_output.csv", base_name))
                            .unwrap();
                            wtr.serialize(&data).unwrap();
                            wtr.flush().unwrap();
                            println!("Saved CSV to {}_output.csv", base_name);
                        }
                        "txt" => {
                            let mut file =
                            File::create(format!("{}_output.txt", base_name)).unwrap();
                            writeln!(file, "{:#?}", data).unwrap();
                            println!("Saved TXT to {}_output.txt", base_name);
                        }
                        _ => println!("Unknown output format: {}", fmt),
                    }
                }
            }
            Err(e) => eprintln!("Error processing file {}: {}", file_path, e),
        }

    } else {
        println!("Error: must provide either -f or -b argument.\nRun with --help for usage info.");
    }
}

/// Processes one .eml file and extracts data
fn process_eml(path: &Path) -> Result<EmailData, Box<dyn std::error::Error>> {
    let raw = fs::read(path)?;
    let parsed = parse_mail(&raw)?;

    let headers = parsed.get_headers();
    let mut data = EmailData {
        filename: None,
        received_spf: None,
        spf_passed: None,
        dkim_result: None,
        return_path: None,
        from: None,
        to: None,
        reply_to: None,
        subject: None,
        links: vec![],
        emails_in_body: vec![],
        
    };

    for header in headers {
        let key = header.get_key().to_lowercase();
        let val = header.get_value();

match key.as_str() {
    "received-spf" => {
        data.received_spf = Some(val.clone());
        data.spf_passed = Some(val.to_lowercase().contains("pass"));
    }
    "return-path" => data.return_path = Some(val.clone()),
    "from" => data.from = Some(val.clone()),
    "to" => data.to = Some(val.clone()),
    "reply-to" => data.reply_to = Some(val.clone()),
    "subject" => data.subject = Some(val.clone()),
    "authentication-results" => {
        // Check for DKIM result in Authentication-Results header
        if let Some(cap) = Regex::new(r"dkim=(pass|fail|none|neutral|temperror|permerror)")
            .unwrap()
            .captures(&val)
        {
            data.dkim_result = Some(cap[1].to_string());
        } else {
            data.dkim_result = Some("none".to_string());
        }
    }
    "dkim-signature" => {
        // If DKIM-Signature exists but no result yet, mark as present
        if data.dkim_result.is_none() {
            data.dkim_result = Some("present (no result)".to_string());
        }
    }
    _ => {}
}

    }

let body = parsed.get_body().unwrap_or_default();

// Extract regular http(s) links
let link_regex = Regex::new(r#"https?://[^\s<>"']+"#).unwrap();
data.links = link_regex
    .find_iter(&body)
    .map(|m| m.as_str().to_string())
    .collect();

let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
data.emails_in_body = email_regex
    .find_iter(&body)
    .map(|m| m.as_str().to_string())
    .collect();


    Ok(data)
}
