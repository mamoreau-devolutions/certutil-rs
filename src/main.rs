use anyhow::{Context, Result};
use certutil_rs::cli::{Cli, Command, EncodeCliFmt, StoreLocation, TlsAction};
use certutil_rs::win;
use certutil_rs::win::codec::EncodeFormat;
use certutil_rs::win::verify::VerifyOptions;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Dump { infile } => {
            let report = win::dump::dump_file(&infile)?;
            print!("{report}");
        }
        Command::Verify {
            urlfetch,
            timeout_ms,
            ssl_dns_name,
            ssl_client_dns_name,
            policy_authenticode,
            policy_authenticode_ts,
            policy_basic_constraints,
            policy_nt_auth,
            probe_urls,
            probe_revocation,
            crtblob,
        } => {
            let opts = VerifyOptions {
                urlfetch,
                timeout_ms,
                ssl_dns_name,
                probe_urls,
                probe_revocation,
                ssl_client_dns_name,
                policy_authenticode,
                policy_authenticode_ts,
                policy_basic_constraints,
                policy_nt_auth,
            };
            let report = win::verify::verify_cert_file_with_options(&crtblob, opts)?;
            print!("{report}");
        }
        Command::Encode {
            infile,
            outfile,
            fmt: cli_fmt,
            hex_spaced,
        } => {
            let (codec_fmt, label) = match (cli_fmt, hex_spaced) {
                (EncodeCliFmt::Hex, true) => (EncodeFormat::HexSpaced, "hex spaced"),
                (EncodeCliFmt::Hex, false) => (EncodeFormat::Hex, "hex"),
                (EncodeCliFmt::Base64Pem, _) => (EncodeFormat::Base64Pem, "base64 PEM"),
                (EncodeCliFmt::Base64Raw, _) => (EncodeFormat::Base64Raw, "base64"),
            };
            let text = win::codec::encode_file(&infile, codec_fmt)?;
            std::fs::write(&outfile, text.as_bytes())
                .with_context(|| format!("write {}", outfile.display()))?;
            println!(
                "Encoded {} -> {} ({label})",
                infile.display(),
                outfile.display(),
            );
        }
        Command::Decode { infile, outfile } => {
            let bytes = win::codec::decode_file(&infile)?;
            std::fs::write(&outfile, &bytes)
                .with_context(|| format!("write {}", outfile.display()))?;
            println!(
                "Decoded {} -> {} ({} bytes)",
                infile.display(),
                outfile.display(),
                bytes.len()
            );
        }
        Command::Hashfile { path, alg } => {
            let alg = win::hashfile::HashAlg::parse(alg.trim())
                .with_context(|| format!("unknown hash algorithm {alg:?} (use MD5, SHA1, SHA256, SHA384)"))?;
            let report = win::hashfile::hash_file(&path, alg)?;
            print!("{report}");
        }
        Command::Store {
            store,
            location,
            filter,
        } => {
            let loc = match location {
                StoreLocation::CurrentUser => win::store_view::StoreLocationKind::CurrentUser,
                StoreLocation::LocalMachine => win::store_view::StoreLocationKind::LocalMachine,
            };
            let report = win::store_view::view_system_store(&store, loc, filter.as_deref())?;
            print!("{report}");
        }
        Command::Tls { action } => match action {
            TlsAction::Fetch {
                host,
                explicit_port,
                output,
                server_name,
                insecure,
                verbose,
                format,
            } => {
                if insecure {
                    eprintln!(
                        "Warning: TLS certificate verification is DISABLED (--insecure); use only for diagnostics."
                    );
                }
                let default_port = explicit_port.unwrap_or(443);
                let (der, diag) = win::tls_fetch::fetch_tls_leaf_der_with_diagnostics(
                    &host,
                    default_port,
                    server_name.as_deref(),
                    insecure,
                    verbose,
                )?;
                if let Some(d) = diag {
                    print!("{d}");
                }
                win::tls_fetch::write_leaf_certificate(&output, &der, format.as_deref())?;
                println!(
                    "Wrote leaf certificate ({} bytes DER) to {}",
                    der.len(),
                    output.display()
                );
            }
        },
        Command::Url { target, timeout_ms } => {
            let t = timeout_ms.unwrap_or(0);
            let report = win::url::url_command_target(&target, t)?;
            print!("{report}");
        }
    }
    Ok(())
}
