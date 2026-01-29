use ech_auth::*;
use std::process;

fn print_usage() {
    eprintln!("Usage: ech-generate [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --public-name NAME      Public name (required)");
    eprintln!("  --config-id ID          Config ID (default: 0)");
    eprintln!("  --kem KEM               KEM algorithm: x25519 (default), p256");
    eprintln!("  --hpke-key HEX          HPKE public key in hex (required)");
    eprintln!("  --kdf KDF               KDF: sha256 (default), sha384");
    eprintln!("  --aead AEAD             AEAD: aes128, aes256, chacha20 (default: aes128)");
    eprintln!("  --max-name-length N     Maximum name length (default: 0)");
    eprintln!("  --output FORMAT         Output format: hex (default), base64");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut public_name: Option<String> = None;
    let mut config_id: u8 = 0;
    let mut kem = DHKEM_X25519_SHA256;
    let mut hpke_key: Option<Vec<u8>> = None;
    let mut kdf = HKDF_SHA256;
    let mut aead = AES_128_GCM;
    let mut max_name_length: u8 = 0;
    let mut output_format = "hex";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--public-name" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --public-name requires an argument");
                    process::exit(1);
                }
                public_name = Some(args[i].clone());
            }
            "--config-id" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --config-id requires an argument");
                    process::exit(1);
                }
                config_id = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: invalid config-id");
                    process::exit(1);
                });
            }
            "--kem" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --kem requires an argument");
                    process::exit(1);
                }
                kem = match args[i].as_str() {
                    "x25519" => DHKEM_X25519_SHA256,
                    "p256" => DHKEM_P256_SHA256,
                    _ => {
                        eprintln!("Error: unknown KEM: {}", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--hpke-key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --hpke-key requires an argument");
                    process::exit(1);
                }
                hpke_key = Some(hex::decode(&args[i]).unwrap_or_else(|_| {
                    eprintln!("Error: invalid hex in --hpke-key");
                    process::exit(1);
                }));
            }
            "--kdf" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --kdf requires an argument");
                    process::exit(1);
                }
                kdf = match args[i].as_str() {
                    "sha256" => HKDF_SHA256,
                    "sha384" => HKDF_SHA384,
                    _ => {
                        eprintln!("Error: unknown KDF: {}", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--aead" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --aead requires an argument");
                    process::exit(1);
                }
                aead = match args[i].as_str() {
                    "aes128" => AES_128_GCM,
                    "aes256" => AES_256_GCM,
                    "chacha20" => CHACHA20_POLY1305,
                    _ => {
                        eprintln!("Error: unknown AEAD: {}", args[i]);
                        process::exit(1);
                    }
                };
            }
            "--max-name-length" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --max-name-length requires an argument");
                    process::exit(1);
                }
                max_name_length = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: invalid max-name-length");
                    process::exit(1);
                });
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --output requires an argument");
                    process::exit(1);
                }
                output_format = match args[i].as_str() {
                    "hex" | "base64" => args[i].as_str(),
                    _ => {
                        eprintln!("Error: unknown output format: {}", args[i]);
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
    if public_name.is_none() {
        eprintln!("Error: --public-name is required");
        print_usage();
        process::exit(1);
    }
    if hpke_key.is_none() {
        eprintln!("Error: --hpke-key is required");
        print_usage();
        process::exit(1);
    }

    // Build ECHConfig
    let config = ECHConfigBuilder::new()
        .config_id(config_id)
        .kem_id(kem)
        .public_key(hpke_key.unwrap())
        .add_cipher_suite(kdf, aead)
        .maximum_name_length(max_name_length)
        .public_name(&public_name.unwrap())
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Error building ECHConfig: {}", e);
            process::exit(1);
        });

    // Encode
    let encoded = config.encode();

    // Output
    match output_format {
        "hex" => println!("{}", hex::encode(&encoded)),
        "base64" => println!("{}", base64_encode(&encoded)),
        _ => unreachable!(),
    }
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap()
}
