use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "btt", version, about = "Minimal, secure Bittensor CLI")]
pub struct Cli {
    /// RPC endpoint URL
    #[arg(long, global = true)]
    pub url: Option<String>,

    /// Network shorthand: finney, test, local
    #[arg(long, global = true)]
    pub network: Option<String>,

    /// Human-readable output instead of JSON
    #[arg(long, global = true, default_value_t = false)]
    pub pretty: bool,

    /// Suppress non-essential output
    #[arg(long, global = true, default_value_t = false)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Chain interaction commands
    Chain {
        #[command(subcommand)]
        action: ChainAction,
    },

    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Emit SKILL.md for AI agent integration
    Skill,
}

#[derive(Subcommand, Debug)]
pub enum ChainAction {
    /// Display chain info: name, runtime version, block number
    Info,

    /// Query free balance for an SS58 address
    Balance {
        /// SS58-encoded address to query
        address: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletAction {
    /// List wallets in ~/.bittensor/wallets/
    List,
}
