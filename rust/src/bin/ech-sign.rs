use ech_auth::{
    sign_pkix_ecdsa, sign_pkix_ed25519, sign_rpk, sign_rpk_ecdsa, ECHAuth, ECHAuthMethod,
    SpecVersion,
};
use ed25519_dalek::SigningKey;
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::process;

fn print_usage() {
    eprintln!("Usage: ech-sign [OPTIONS]");
    eprintln!();
    eprintln!("Reads ECHConfig from stdin (hex-encoded)");
    eprintln!("Outputs signed ECHAuth extension to stdout (hex-encoded)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --method METHOD         rpk (default) or pkix");
    eprintln!("  --algorithm ALG         ed25519 (default) or ecdsa-p256");
    eprintln!("  --key FILE              Signing key file (required)");
    eprintln!("  --not-after TIMESTAMP   Unix epoch seconds (required for RPK, ignored for PKIX)");
    eprintln!("  --cert-chain FILE       Certificate chain for PKIX (DER format, required for PKIX)");
    eprintln!("  --version VER           Wire format: pr2 (default) or published");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut method = "rpk";
    let mut algorithm = "ed25519";
    let mut key_file: Option<String> = None;
    let mut not_after: Option<u64> = None;
    let mut cert_chain_file: Option<String> = None;
    let mut spec_version = SpecVersion::PR2;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --method requires an argument");
                    process::exit(1);
                }
                method = match args[i].as_str() {
                    "rpk" | "pkix" => args[i].as_str(),
                    _ => {
                        eprintln!("Error: unknown method: {}", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--algorithm" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --algorithm requires an argument");
                    process::exit(1);
                }
                algorithm = match args[i].as_str() {
                    "ed25519" | "ecdsa-p256" => args[i].as_str(),
                    _ => {
                        eprintln!("Error: unknown algorithm: {}", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --key requires an argument");
                    process::exit(1);
                }
                key_file = Some(args[i].clone());
            }
            "--not-after" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --not-after requires an argument");
                    process::exit(1);
                }
                not_after = Some(args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: invalid not-after timestamp");
                    process::exit(1);
                }));
            }
            "--cert-chain" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --cert-chain requires an argument");
                    process::exit(1);
                }
                cert_chain_file = Some(args[i].clone());
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

    // Validate arguments
    if key_file.is_none() {
        eprintln!("Error: --key is required");
        print_usage();
        process::exit(1);
    }
    if method == "rpk" && not_after.is_none() {
        eprintln!("Error: --not-after is required for RPK method");
        print_usage();
        process::exit(1);
    }
    if method == "pkix" && cert_chain_file.is_none() {
        eprintln!("Error: --cert-chain is required for PKIX method");
        print_usage();
        process::exit(1);
    }

    // Read signing key
    let key_data = std::fs::read(key_file.unwrap())?;

    // Read ECHConfig from stdin
    let mut stdin_data = String::new();
    io::stdin().read_to_string(&mut stdin_data)?;
    let ech_config_tbs = hex::decode(stdin_data.trim())?;

    // Sign based on method and algorithm
    let signature = match (method, algorithm) {
        ("rpk", "ed25519") => {
            let signing_key = parse_ed25519_key(&key_data)?;
            sign_rpk(&ech_config_tbs, &signing_key, not_after.unwrap())
        }
        ("rpk", "ecdsa-p256") => {
            let signing_key = parse_ecdsa_key(&key_data)?;
            sign_rpk_ecdsa(&ech_config_tbs, &signing_key, not_after.unwrap())
        }
        ("pkix", "ed25519") => {
            let signing_key = parse_ed25519_key(&key_data)?;
            let cert_chain = parse_cert_chain(&cert_chain_file.unwrap())?;
            sign_pkix_ed25519(&ech_config_tbs, &signing_key, cert_chain)
        }
        ("pkix", "ecdsa-p256") => {
            let signing_key = parse_ecdsa_key(&key_data)?;
            let cert_chain = parse_cert_chain(&cert_chain_file.unwrap())?;
            sign_pkix_ecdsa(&ech_config_tbs, &signing_key, cert_chain)
        }
        _ => unreachable!(),
    };

    // Build ECHAuth based on method
    let ech_auth = if method == "rpk" {
        // Compute SPKI hash for trusted_keys
        let mut hasher = Sha256::new();
        hasher.update(&signature.authenticator);
        let spki_hash: [u8; 32] = hasher.finalize().into();

        ECHAuth {
            method: ECHAuthMethod::Rpk,
            trusted_keys: vec![spki_hash],
            signature: Some(signature),
        }
    } else {
        ECHAuth {
            method: ECHAuthMethod::Pkix,
            trusted_keys: vec![],
            signature: Some(signature),
        }
    };

    // Encode and output
    let encoded = ech_auth.encode_versioned(spec_version);
    println!("{}", hex::encode(encoded));

    Ok(())
}

fn parse_ed25519_key(key_data: &[u8]) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if key_data.len() == 32 {
        // Raw bytes
        Ok(SigningKey::from_bytes(&key_data.try_into().unwrap()))
    } else if key_data.len() == 64 {
        // Hex encoded
        let hex_str = String::from_utf8(key_data.to_vec())?;
        let decoded = hex::decode(hex_str.trim())?;
        Ok(SigningKey::from_bytes(&decoded.try_into().unwrap()))
    } else {
        Err("signing key must be 32 bytes (raw) or 64 hex digits".into())
    }
}

fn parse_ecdsa_key(key_data: &[u8]) -> Result<EcdsaSigningKey, Box<dyn std::error::Error>> {
    if key_data.len() == 32 {
        // Raw bytes
        let secret_key = p256::SecretKey::from_slice(key_data)?;
        Ok(EcdsaSigningKey::from(secret_key))
    } else if key_data.len() == 64 {
        // Hex encoded
        let hex_str = String::from_utf8(key_data.to_vec())?;
        let decoded = hex::decode(hex_str.trim())?;
        let secret_key = p256::SecretKey::from_slice(&decoded)?;
        Ok(EcdsaSigningKey::from(secret_key))
    } else {
        Err("signing key must be 32 bytes (raw) or 64 hex digits".into())
    }
}

fn parse_cert_chain(file: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    // Read DER-encoded certificate chain
    // For simplicity, assume single certificate file
    let cert_der = std::fs::read(file)?;
    Ok(vec![cert_der])
}
