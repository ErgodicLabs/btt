#![deny(clippy::unwrap_used)]

mod cli;
mod commands;
mod error;
mod output;
mod rpc;

use std::io::Write;

use clap::Parser;
use zeroize::Zeroizing;

use cli::{AxonAction, ChainAction, Cli, Command, StakeAction, SubnetAction, UtilsAction, WalletAction};
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
    // `--quiet` suppresses non-essential stderr status output: the
    // legacy wallet directory migration warning and the `--force`
    // destruction warnings. Suppressed via a process-wide atomic in
    // `commands::paths` that the warning sites read at print time.
    // Structured errors (`{ok:false,error:...}`) and stdout JSON
    // payloads are NEVER suppressed — `--quiet` is a display flag,
    // not a "hide my mistakes" flag. See issue #85 for the full
    // scoping decision.
    commands::paths::set_quiet(cli.quiet);

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
                // Issue #86: hotkeys are stored unencrypted on disk, so
                // `--password-file` is a silent no-op when paired with
                // `--use-hotkey`. Surface the no-op as a clear stderr
                // warning so a CI script that passes a generic
                // `--password-file` regardless of key type does not
                // think the file is being consulted when it isn't.
                // Respects `--quiet` via the is_quiet() check.
                if let Some(msg) = sign_password_file_warning(use_hotkey, password_file.is_some())
                {
                    if !commands::paths::is_quiet() {
                        let _ = writeln!(std::io::stderr(), "{msg}");
                    }
                }
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
            WalletAction::SwapHotkey {
                name,
                old_hotkey,
                new_hotkey,
            } => {
                let endpoint = rpc::resolve_endpoint(
                    cli.url.as_deref(),
                    cli.network.as_deref(),
                )?;
                let result = commands::swap_hotkey::swap_hotkey(
                    &endpoint, &name, &old_hotkey, &new_hotkey,
                )
                .await?;
                output::print_success(&result, pretty);
            }
            WalletAction::GetIdentity { ss58 } => {
                let endpoint = rpc::resolve_endpoint(
                    cli.url.as_deref(),
                    cli.network.as_deref(),
                )?;
                let result =
                    commands::identity::get_identity(&endpoint, &ss58).await?;
                output::print_success(&result, pretty);
            }
            WalletAction::SetIdentity {
                name,
                display_name,
                url,
                description,
                image,
                discord,
                github_repo,
                github_username,
            } => {
                let endpoint = rpc::resolve_endpoint(
                    cli.url.as_deref(),
                    cli.network.as_deref(),
                )?;
                let result = commands::identity::set_identity(
                    &endpoint,
                    &name,
                    commands::identity::SetIdentityFields {
                        display_name: &display_name,
                        url: &url,
                        description: &description,
                        image: &image,
                        discord: &discord,
                        github_repo: &github_repo,
                        github_username: &github_username,
                    },
                )
                .await?;
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
                StakeAction::Move {
                    wallet,
                    origin_hotkey,
                    destination_hotkey,
                    origin_netuid,
                    destination_netuid,
                    amount,
                } => {
                    let result = commands::stake::move_stake(
                        &endpoint,
                        commands::stake::MoveStakeParams {
                            wallet: &wallet,
                            origin_hotkey: &origin_hotkey,
                            destination_hotkey: &destination_hotkey,
                            origin_netuid,
                            destination_netuid,
                            amount_tao: amount,
                        },
                    )
                    .await?;
                    output::print_success(&result, pretty);
                }
                StakeAction::Transfer {
                    wallet,
                    dest_coldkey,
                    hotkey,
                    netuid,
                    amount,
                } => {
                    let result = commands::stake::transfer_stake(
                        &endpoint, &wallet, &dest_coldkey, &hotkey, netuid, amount,
                    )
                    .await?;
                    output::print_success(&result, pretty);
                }
                StakeAction::Swap {
                    wallet,
                    hotkey,
                    origin_netuid,
                    destination_netuid,
                    amount,
                } => {
                    let result = commands::stake::swap_stake(
                        &endpoint,
                        &wallet,
                        &hotkey,
                        origin_netuid,
                        destination_netuid,
                        amount,
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
                SubnetAction::List => {
                    let result = commands::subnet::list(&endpoint).await?;
                    output::print_success(&result, pretty);
                }
                SubnetAction::Metagraph { netuid } => {
                    let result =
                        commands::subnet::metagraph(&endpoint, netuid).await?;
                    output::print_success(&result, pretty);
                }
                SubnetAction::Hyperparameters { netuid } => {
                    let result =
                        commands::subnet::hyperparameters(&endpoint, netuid).await?;
                    output::print_success(&result, pretty);
                }
                SubnetAction::Register {
                    name,
                    hotkey,
                    netuid,
                } => {
                    let result =
                        commands::register::register(&endpoint, &name, &hotkey, netuid)
                            .await?;
                    output::print_success(&result, pretty);
                }
            }
        }
        Command::Axon { action } => {
            let endpoint = rpc::resolve_endpoint(
                cli.url.as_deref(),
                cli.network.as_deref(),
            )?;
            match action {
                AxonAction::Set {
                    name,
                    hotkey,
                    netuid,
                    ip,
                    port,
                    ip_type,
                    protocol,
                    version,
                } => {
                    let result = commands::axon::set(
                        &endpoint,
                        commands::axon::AxonParams {
                            wallet: &name,
                            hotkey: &hotkey,
                            netuid,
                            ip: &ip,
                            port,
                            ip_type,
                            protocol,
                            version,
                        },
                    )
                    .await?;
                    output::print_success(&result, pretty);
                }
            }
        }
        Command::Utils { action } => match action {
            UtilsAction::Convert { rao, tao } => {
                let result = match (rao, tao) {
                    (Some(r), None) => commands::utils::convert_rao_to_tao(r),
                    (None, Some(t)) => commands::utils::convert_tao_to_rao(t)?,
                    _ => {
                        return Err(BttError::invalid_input(
                            "provide exactly one of --rao or --tao",
                        ));
                    }
                };
                output::print_success(&result, pretty);
            }
            UtilsAction::Latency => {
                let endpoint = rpc::resolve_endpoint(
                    cli.url.as_deref(),
                    cli.network.as_deref(),
                )?;
                let result = commands::utils::latency(&endpoint).await?;
                output::print_success(&result, pretty);
            }
        },
        Command::Skill => {
            // `btt skill` emits the SKILL.md document. This is the
            // command's primary output, not a status line, so `--quiet`
            // does not suppress it.
            print!("{}", commands::skill::skill_md());
        }
    }

    Ok(())
}

/// Decide whether `wallet sign` should emit the
/// "--password-file is ignored with --use-hotkey" warning, and if so,
/// return the exact message text. Extracted as a pure function so the
/// decision is unit-testable without touching stderr or the process-
/// wide `--quiet` state.
///
/// The caller (`main::run`) applies the `!is_quiet()` gate around the
/// actual stderr write; this function only answers "should a warning
/// fire given the two relevant flags?".
fn sign_password_file_warning(use_hotkey: bool, password_file_present: bool) -> Option<&'static str> {
    if use_hotkey && password_file_present {
        Some(
            "btt: warning: --password-file is ignored with --use-hotkey \
             (hotkeys are unencrypted)",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue #86: assert the warning decision is correct for all four
    // combinations of (use_hotkey, password_file_present). The pure
    // function returns Some(msg) for exactly the (true, true) case.

    #[test]
    fn sign_warning_fires_for_hotkey_and_password_file() {
        let msg = sign_password_file_warning(true, true)
            .expect("warning must fire when both --use-hotkey and --password-file are set");
        assert!(msg.contains("--password-file is ignored"));
        assert!(msg.contains("--use-hotkey"));
        assert!(msg.contains("unencrypted"));
    }

    #[test]
    fn sign_warning_does_not_fire_for_use_hotkey_alone() {
        assert!(sign_password_file_warning(true, false).is_none());
    }

    #[test]
    fn sign_warning_does_not_fire_for_password_file_alone() {
        assert!(sign_password_file_warning(false, true).is_none());
    }

    #[test]
    fn sign_warning_does_not_fire_for_neither() {
        assert!(sign_password_file_warning(false, false).is_none());
    }
}
