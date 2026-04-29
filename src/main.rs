use anyhow::Result;
use certutil_rs::cli::{Cli, Command};
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
            crtblob,
        } => {
            let opts = VerifyOptions {
                urlfetch,
                timeout_ms,
            };
            let report = win::verify::verify_cert_file_with_options(&crtblob, opts)?;
            print!("{report}");
        }
        Command::Url { target, timeout_ms } => {
            let t = timeout_ms.unwrap_or(0);
            let report = win::url::url_command_target(&target, t)?;
            print!("{report}");
        }
    }
    Ok(())
}
