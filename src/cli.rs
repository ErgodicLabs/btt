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

    /// Staking operations
    Stake {
        #[command(subcommand)]
        action: StakeAction,
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

    /// Create a new wallet (coldkey + hotkey pair)
    Create {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Number of mnemonic words (12 or 24)
        #[arg(long, default_value_t = 12)]
        n_words: u32,
    },

    /// Generate a new coldkey only
    NewColdkey {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Number of mnemonic words (12 or 24)
        #[arg(long, default_value_t = 12)]
        n_words: u32,
    },

    /// Generate a new hotkey for an existing wallet
    NewHotkey {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Number of mnemonic words (12 or 24)
        #[arg(long, default_value_t = 12)]
        n_words: u32,
    },

    /// Restore a coldkey from mnemonic or seed
    RegenColdkey {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// BIP39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Hex-encoded seed (0x...)
        #[arg(long)]
        seed: Option<String>,
    },

    /// Restore a hotkey from mnemonic or seed
    RegenHotkey {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// BIP39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Hex-encoded seed (0x...)
        #[arg(long)]
        seed: Option<String>,
    },

    /// Sign a message with a wallet key
    Sign {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name (when using --use-hotkey)
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Sign with hotkey instead of coldkey
        #[arg(long, default_value_t = false)]
        use_hotkey: bool,
    },

    /// Verify a signature
    Verify {
        /// Message that was signed
        #[arg(long)]
        message: String,
        /// Hex-encoded signature (0x...)
        #[arg(long)]
        signature: String,
        /// SS58 address of the signer
        #[arg(long)]
        ss58: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum StakeAction {
    /// List all stakes for a wallet
    List {
        /// Wallet name (reads coldkeypub.txt for the SS58 address)
        #[arg(long)]
        wallet: Option<String>,
        /// SS58 address to query directly (alternative to --wallet)
        #[arg(long)]
        ss58: Option<String>,
    },

    /// Stake TAO from coldkey to hotkey on a subnet
    Add {
        /// Wallet name (coldkey will be decrypted for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address to stake to
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Amount in TAO (e.g. 10.5)
        #[arg(long)]
        amount: f64,
    },

    /// Unstake TAO from hotkey back to coldkey
    Remove {
        /// Wallet name (coldkey will be decrypted for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address to unstake from
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Amount in TAO (e.g. 10.5). Ignored if --all is set.
        #[arg(long, required_unless_present = "all")]
        amount: Option<f64>,
        /// Unstake all TAO from this hotkey on this subnet
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}
