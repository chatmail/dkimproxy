#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

use anyhow::{Context as _, Result};
use cfdkim::DKIMResult;
use mailparse::MailHeaderMap;
use slog::Drain;
use std::io::Read;

#[tokio::main]
async fn main() -> Result<()> {
    let decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, o!());

    let mut input = Vec::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle.read_to_end(&mut input)?;

    let parsed_email = mailparse::parse_mail(&input)?;
    let headers = parsed_email.get_headers();
    let from = headers.get_all_headers("From");
    let from_domain: String = match &from[..] {
        [] => {
            error!(logger, "No From header");
            return Ok(());
        }
        [header] => {
            let addr = match mailparse::addrparse_header(&header)?.extract_single_info() {
                Some(info) => info.addr,
                None => {
                    error!(logger, "From is not a single address");
                    return Ok(());
                }
            };
            let (_, domain) = addr
                .split_once('@')
                .context("Cannot split domain from From")?;
            domain.to_string()
        }
        _ => {
            error!(logger, "Multiple From headers");
            return Ok(());
        }
    };

    let res: DKIMResult = cfdkim::verify_email(&logger, &from_domain, &parsed_email).await?;
    if let Some(err) = &res.error() {
        error!(logger, "dkim verify fail: {}", err);
    }

    println!("domain={} dkim={}", &from_domain, res.with_detail());
    Ok(())
}
