#![deny(clippy::unwrap_used)]

mod cli;
mod commands;
mod error;
mod output;
mod rpc;

use clap::Parser;

use cli::{ChainAction, Cli, Command, StakeAction, WalletAction};
use error::BttError;

#[tokio::main]
async fn main() {
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
    // `--quiet` is reserved for suppressing non-essential status output
    // (progress indicators, banners, hints). None of those exist in the
    // current scaffold, so it is intentionally unused for successful
    // results. Success payloads are always emitted because they are the
    // actual result of the command. Errors are never suppressed.
    let _quiet = cli.quiet;

    match cli.command {
        Command::Chain { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            )?;
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
            WalletAction::Create {
                name,
                hotkey,
                n_words,
            } => {
                let password = commands::wallet_keys::read_password("Enter password for coldkey: ")?;
                let result =
                    commands::wallet_keys::create(&name, &hotkey, n_words, &password)?;
                // Mnemonic is always shown, even with --quiet
                output::print_success(&result, pretty, false);
            }
            WalletAction::NewColdkey { name, n_words } => {
                let password = commands::wallet_keys::read_password("Enter password for coldkey: ")?;
                let result = commands::wallet_keys::new_coldkey(&name, n_words, &password)?;
                output::print_success(&result, pretty, false);
            }
            WalletAction::NewHotkey {
                name,
                hotkey,
                n_words,
            } => {
                let result = commands::wallet_keys::new_hotkey(&name, &hotkey, n_words)?;
                output::print_success(&result, pretty, false);
            }
            WalletAction::RegenColdkey {
                name,
                mnemonic,
                seed,
            } => {
                let password = commands::wallet_keys::read_password("Enter password for coldkey: ")?;
                let result = commands::wallet_keys::regen_coldkey(
                    &name,
                    mnemonic.as_deref(),
                    seed.as_deref(),
                    &password,
                )?;
                output::print_success(&result, pretty, quiet);
            }
            WalletAction::RegenHotkey {
                name,
                hotkey,
                mnemonic,
                seed,
            } => {
                let result = commands::wallet_keys::regen_hotkey(
                    &name,
                    &hotkey,
                    mnemonic.as_deref(),
                    seed.as_deref(),
                )?;
                output::print_success(&result, pretty, quiet);
            }
            WalletAction::Sign {
                name,
                hotkey,
                message,
                use_hotkey,
            } => {
                let password = if use_hotkey {
                    None
                } else {
                    Some(commands::wallet_keys::read_password("Enter password for coldkey: ")?)
                };
                let password_ref = password.as_ref().map(|p| p.as_str());
                let result = commands::wallet_keys::sign(
                    &name,
                    &hotkey,
                    &message,
                    use_hotkey,
                    password_ref,
                )?;
                output::print_success(&result, pretty, quiet);
            }
            WalletAction::Verify {
                message,
                signature,
                ss58,
            } => {
                let result = commands::wallet_keys::verify(&message, &signature, &ss58)?;
                output::print_success(&result, pretty, quiet);
            }
        },
        Command::Stake { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            )?;
            match action {
                StakeAction::List { wallet, ss58 } => {
                    let result = commands::stake::list(
                        &endpoint,
                        wallet.as_deref(),
                        ss58.as_deref(),
                    )
                    .await?;
                    output::print_success(&result, pretty, quiet);
                }
                StakeAction::Add {
                    wallet,
                    hotkey,
                    netuid,
                    amount,
                } => {
                    let result = commands::stake::add(
                        &endpoint,
                        &wallet,
                        &hotkey,
                        netuid,
                        amount,
                    )
                    .await?;
                    output::print_success(&result, pretty, quiet);
                }
                StakeAction::Remove {
                    wallet,
                    hotkey,
                    netuid,
                    amount,
                    all,
                } => {
                    let result = commands::stake::remove(
                        &endpoint,
                        &wallet,
                        &hotkey,
                        netuid,
                        amount,
                        all,
                    )
                    .await?;
                    output::print_success(&result, pretty, quiet);
                }
            }
        }
        Command::Skill => {
            // `btt skill` emits the SKILL.md document. This is the
            // command's primary output, not a status line, so `--quiet`
            // does not suppress it.
            print!("{}", commands::skill::skill_md());
        }
    }

    Ok(())
}
