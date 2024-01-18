#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

use anyhow::{Context as _, Result};
use cfdkim::DKIMResult;
use mailparse::MailHeaderMap;
use slog::Drain;

#[tokio::main]
async fn main() -> Result<()> {
    let decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, o!());

    let input = std::io::read_to_string(std::io::stdin())?.replace("\n", "\r\n");

    let parsed_email = mailparse::parse_mail(input.as_bytes())?;
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
