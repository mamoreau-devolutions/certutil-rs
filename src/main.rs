use anyhow::Result;
use certutil_rs::cli::{Cli, Command, TlsAction};
use certutil_rs::win;
use certutil_rs::win::verify::VerifyOptions;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Dump { infile } => {
            let der = win::dump::read_cert_file(&infile)?;
            let report = win::dump::dump_cert_bytes(&der)?;
            print!("{report}");
        }
        Command::Verify {
            urlfetch,
            timeout_ms,
            ssl_dns_name,
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
            };
            let report = win::verify::verify_cert_file_with_options(&crtblob, opts)?;
            print!("{report}");
        }
        Command::Tls { action } => match action {
            TlsAction::Fetch {
                host,
                explicit_port,
                output,
                server_name,
                insecure,
                format,
            } => {
                if insecure {
                    eprintln!(
                        "Warning: TLS certificate verification is DISABLED (--insecure); use only for diagnostics."
                    );
                }
                let default_port = explicit_port.unwrap_or(443);
                let der = win::tls_fetch::fetch_tls_leaf_der(
                    &host,
                    default_port,
                    server_name.as_deref(),
                    insecure,
                )?;
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
