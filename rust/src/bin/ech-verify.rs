use ech_auth::{verify_pkix_versioned, verify_rpk, ECHAuth, ECHAuthMethod, SPKIHash, SpecVersion};
use std::io::{self, Read};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

fn print_usage() {
    eprintln!("Usage: ech-verify [OPTIONS]");
    eprintln!();
    eprintln!("Reads ECHAuth extension from stdin (hex-encoded)");
    eprintln!("Verifies signature");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --config-tbs HEX        ECHConfig with signature zeroed (hex, required)");
    eprintln!("  --trusted-key HASH      SHA-256 hash of trusted SPKI (64 hex digits)");
    eprintln!("                          Can be specified multiple times for RPK");
    eprintln!("                          If omitted, uses trusted_keys from ECHAuth");
    eprintln!("  --public-name NAME      Public name for PKIX SAN check (required for PKIX)");
    eprintln!("  --trust-anchor FILE     Trust anchor certificate (DER, for PKIX)");
    eprintln!("  --current-time UNIX     Current Unix timestamp (default: now)");
    eprintln!("  --version VER           Wire format: pr2 (default) or published");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut ech_config_tbs: Option<Vec<u8>> = None;
    let mut trusted_keys_override: Option<Vec<SPKIHash>> = None;
    let mut public_name: Option<String> = None;
    let mut trust_anchors: Vec<Vec<u8>> = Vec::new();
    let mut current_time: Option<u64> = None;
    let mut spec_version = SpecVersion::PR2;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config-tbs" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --config-tbs requires an argument");
                    process::exit(1);
                }
                ech_config_tbs = Some(hex::decode(&args[i]).unwrap_or_else(|_| {
                    eprintln!("Error: invalid hex in --config-tbs");
                    process::exit(1);
                }));
            }
            "--trusted-key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --trusted-key requires an argument");
                    process::exit(1);
                }
                let decoded = hex::decode(args[i].trim()).unwrap_or_else(|_| {
                    eprintln!("Error: invalid hex in --trusted-key");
                    process::exit(1);
                });
                if decoded.len() != 32 {
                    eprintln!("Error: trusted key hash must be 32 bytes (64 hex digits)");
                    process::exit(1);
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&decoded);
                if let Some(ref mut keys) = trusted_keys_override {
                    keys.push(hash);
                } else {
                    trusted_keys_override = Some(vec![hash]);
                }
            }
            "--public-name" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --public-name requires an argument");
                    process::exit(1);
                }
                public_name = Some(args[i].clone());
            }
            "--trust-anchor" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --trust-anchor requires an argument");
                    process::exit(1);
                }
                let cert_der = std::fs::read(&args[i]).unwrap_or_else(|e| {
                    eprintln!("Error reading trust anchor: {}", e);
                    process::exit(1);
                });
                trust_anchors.push(cert_der);
            }
            "--current-time" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --current-time requires an argument");
                    process::exit(1);
                }
                current_time = Some(args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: invalid current-time");
                    process::exit(1);
                }));
            }
            "--version" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --version requires an argument");
                    process::exit(1);
                }
                spec_version = match args[i].as_str() {
                    "pr2" => SpecVersion::PR2,
                    "published" => SpecVersion::Published,
                    _ => {
                        eprintln!("Error: unknown version: {} (use pr2 or published)", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                eprintln!("Error: unknown option: {}", args[i]);
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    // Validate required arguments
    if ech_config_tbs.is_none() {
        eprintln!("Error: --config-tbs is required");
        print_usage();
        process::exit(1);
    }

    // Read ECHAuth from stdin
    let mut stdin_data = String::new();
    io::stdin().read_to_string(&mut stdin_data)?;
    let ech_auth_data = hex::decode(stdin_data.trim())?;

    // Decode ECHAuth
    let mut ech_auth = ECHAuth::decode_versioned(&ech_auth_data, spec_version)?;

    // Override trusted keys if provided (for RPK)
    if let Some(keys) = trusted_keys_override {
        ech_auth.trusted_keys = keys;
    }

    // Get current time if not provided
    let current_time = current_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    });

    let config_tbs = ech_config_tbs.unwrap();

    // Verify based on method
    let result = match ech_auth.method {
        ECHAuthMethod::Rpk => verify_rpk(&config_tbs, &ech_auth, current_time),
        ECHAuthMethod::Pkix => {
            if public_name.is_none() {
                eprintln!("Error: --public-name is required for PKIX verification");
                process::exit(1);
            }
            if trust_anchors.is_empty() {
                eprintln!("Error: --trust-anchor is required for PKIX verification");
                process::exit(1);
            }
            let trust_anchor_refs: Vec<Vec<u8>> = trust_anchors;
            verify_pkix_versioned(
                &config_tbs,
                &ech_auth,
                &public_name.unwrap(),
                &trust_anchor_refs,
                current_time,
                spec_version,
            )
        }
    };

    match result {
        Ok(()) => {
            println!("Verification successful");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            std::process::exit(1);
        }
    }
}
