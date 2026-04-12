#![deny(clippy::unwrap_used)]

mod cli;
mod commands;
mod error;
mod output;
mod rpc;

use clap::Parser;

use cli::{ChainAction, Cli, Command, WalletAction};
use error::BttError;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    let cli = Cli::parse();
    let pretty = cli.pretty;

    match run(cli).await {
        Ok(()) => {}
        Err(e) => {
            output::print_error(&e, pretty);
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> Result<(), BttError> {
    let pretty = cli.pretty;
    let quiet = cli.quiet;

    match cli.command {
        Command::Chain { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            )?;
            match action {
                ChainAction::Info => {
                    let info = commands::chain::info(&endpoint).await?;
                    output::print_success(&info, pretty, quiet);
                }
                ChainAction::Balance { address } => {
                    let balance = commands::chain::balance(&endpoint, &address).await?;
                    output::print_success(&balance, pretty, quiet);
                }
            }
        }
        Command::Wallet { action } => match action {
            WalletAction::List => {
                let wallets = commands::wallet::list()?;
                output::print_success(&wallets, pretty, quiet);
            }
        },
        Command::Skill => {
            if !quiet {
                print!("{}", commands::skill::skill_md());
            }
        }
    }

    Ok(())
}
