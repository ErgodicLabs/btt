#![deny(clippy::unwrap_used)]

mod cli;
mod commands;
mod error;
mod output;
mod rpc;

use clap::Parser;
use zeroize::Zeroizing;

use cli::{ChainAction, Cli, Command, StakeAction, SubnetAction, WalletAction};
use commands::password_file;
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

/// Resolve a coldkey password: from `--password-file` if given, otherwise
/// prompted interactively. Returns a zeroizing string that is wiped on drop.
fn resolve_coldkey_password(
    password_file_arg: Option<&str>,
) -> Result<Zeroizing<String>, BttError> {
    if let Some(path) = password_file_arg {
        password_file::read_password_file(path)
    } else {
        commands::wallet_keys::read_password("Enter password for coldkey: ")
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
                password_file,
                force,
            } => {
                let password = resolve_coldkey_password(password_file.as_deref())?;
                let result =
                    commands::wallet_keys::create(&name, &hotkey, n_words, &password, force)?;
                output::print_success(&result, pretty);
            }
            WalletAction::NewColdkey {
                name,
                n_words,
                password_file,
                force,
            } => {
                let password = resolve_coldkey_password(password_file.as_deref())?;
                let result =
                    commands::wallet_keys::new_coldkey(&name, n_words, &password, force)?;
                output::print_success(&result, pretty);
            }
            WalletAction::NewHotkey {
                name,
                hotkey,
                n_words,
                force,
            } => {
                let result =
                    commands::wallet_keys::new_hotkey(&name, &hotkey, n_words, force)?;
                output::print_success(&result, pretty);
            }
            WalletAction::RegenColdkey {
                name,
                mnemonic,
                seed,
                password_file,
                force,
            } => {
                let password = resolve_coldkey_password(password_file.as_deref())?;
                let result = commands::wallet_keys::regen_coldkey(
                    &name,
                    mnemonic.as_deref(),
                    seed.as_deref(),
                    &password,
                    force,
                )?;
                output::print_success(&result, pretty);
            }
            WalletAction::RegenHotkey {
                name,
                hotkey,
                mnemonic,
                seed,
                force,
            } => {
                let result = commands::wallet_keys::regen_hotkey(
                    &name,
                    &hotkey,
                    mnemonic.as_deref(),
                    seed.as_deref(),
                    force,
                )?;
                output::print_success(&result, pretty);
            }
            WalletAction::Sign {
                name,
                hotkey,
                message,
                use_hotkey,
                password_file,
            } => {
                let password = if use_hotkey {
                    None
                } else {
                    Some(resolve_coldkey_password(password_file.as_deref())?)
                };
                let password_ref = password.as_ref().map(|p| p.as_str());
                let result = commands::wallet_keys::sign(
                    &name,
                    &hotkey,
                    &message,
                    use_hotkey,
                    password_ref,
                )?;
                output::print_success(&result, pretty);
            }
            WalletAction::Verify {
                message,
                signature,
                ss58,
            } => {
                let result = commands::wallet_keys::verify(&message, &signature, &ss58)?;
                output::print_success(&result, pretty);
            }
            WalletAction::Cleanup {
                dry_run,
                wallet,
                older_than,
            } => {
                let report = commands::wallet::cleanup(commands::wallet::CleanupOptions {
                    dry_run,
                    wallet,
                    older_than,
                })?;
                output::print_success(&report, pretty);
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
                    output::print_success(&result, pretty);
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
                    output::print_success(&result, pretty);
                }
                StakeAction::Remove {
                    wallet,
                    hotkey,
                    netuid,
                    amount_alpha,
                    amount_tao,
                    all,
                } => {
                    let source = match (amount_alpha, amount_tao, all) {
                        (Some(a), None, false) => commands::stake::RemoveAmount::Alpha(a),
                        (None, Some(t), false) => commands::stake::RemoveAmount::Tao(t),
                        (None, None, true) => commands::stake::RemoveAmount::All,
                        (None, None, false) => {
                            return Err(error::BttError::invalid_input(
                                "provide exactly one of --amount-alpha, --amount-tao, or --all",
                            ));
                        }
                        _ => {
                            // clap's conflicts_with_all should prevent this
                            // at parse time, but defend in depth.
                            return Err(error::BttError::invalid_input(
                                "--amount-alpha, --amount-tao, and --all are mutually exclusive",
                            ));
                        }
                    };
                    let result = commands::stake::remove(
                        &endpoint,
                        &wallet,
                        &hotkey,
                        netuid,
                        source,
                    )
                    .await?;
                    output::print_success(&result, pretty);
                }
            }
        }
        Command::Subnet { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            )?;
            match action {
                SubnetAction::LockCost => {
                    let info = commands::subnet::lock_cost(&endpoint).await?;
                    output::print_success(&info, pretty);
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
