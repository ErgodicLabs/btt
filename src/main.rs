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
    let cli = Cli::parse();
    let pretty = cli.pretty;

    match run(cli).await {
        Ok(()) => {}
        Err(e) => output::print_error(&e, pretty),
    }
}

async fn run(cli: Cli) -> Result<(), BttError> {
    let pretty = cli.pretty;

    match cli.command {
        Command::Chain { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            );
            match action {
                ChainAction::Info => {
                    let info = commands::chain::info(&endpoint).await?;
                    output::print_success(&info, pretty);
                }
                ChainAction::Balance { address } => {
                    let balance = commands::chain::balance(&endpoint, &address).await?;
                    output::print_success(&balance, pretty);
                }
            }
        }
        Command::Wallet { action } => match action {
            WalletAction::List => {
                let wallets = commands::wallet::list()?;
                output::print_success(&wallets, pretty);
            }
        },
        Command::Skill => {
            // Skill command bypasses JSON envelope — it emits raw markdown
            print!("{}", commands::skill::skill_md());
        }
    }

    Ok(())
}
