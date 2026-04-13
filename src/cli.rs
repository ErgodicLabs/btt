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
        /// Read coldkey password from file at <path>. For non-interactive
        /// automation only. The file's first line (up to but not including
        /// the trailing newline) is taken as the password. Security note:
        /// anyone who can read the file can recover your password. Ensure
        /// the file is mode 0600, on a tmpfs (/dev/shm) if possible, and
        /// shredded immediately after use. Do not use this with mainnet
        /// wallets unless your filesystem, process listing, and shell
        /// history are all under your control.
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
    },

    /// Generate a new coldkey only
    NewColdkey {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Number of mnemonic words (12 or 24)
        #[arg(long, default_value_t = 12)]
        n_words: u32,
        /// Read coldkey password from file at <path>. For non-interactive
        /// automation only. The file's first line (up to but not including
        /// the trailing newline) is taken as the password. Security note:
        /// anyone who can read the file can recover your password. Ensure
        /// the file is mode 0600, on a tmpfs (/dev/shm) if possible, and
        /// shredded immediately after use. Do not use this with mainnet
        /// wallets unless your filesystem, process listing, and shell
        /// history are all under your control.
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Overwrite an existing coldkey file if one is present. Without
        /// this flag, the command refuses to run when the target key file
        /// already exists. The existing coldkey is destroyed before the
        /// new one is written; recovering the old key requires its
        /// mnemonic or seed.
        #[arg(long, default_value_t = false)]
        force: bool,
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
        /// Overwrite an existing hotkey file if one is present. Without
        /// this flag, the command refuses to run when the target key file
        /// already exists. The existing hotkey is destroyed before the
        /// new one is written; recovering the old key requires its
        /// mnemonic or seed.
        #[arg(long, default_value_t = false)]
        force: bool,
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
        /// Read coldkey password from file at <path>. For non-interactive
        /// automation only. The file's first line (up to but not including
        /// the trailing newline) is taken as the password. Security note:
        /// anyone who can read the file can recover your password. Ensure
        /// the file is mode 0600, on a tmpfs (/dev/shm) if possible, and
        /// shredded immediately after use. Do not use this with mainnet
        /// wallets unless your filesystem, process listing, and shell
        /// history are all under your control.
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
        /// Overwrite an existing coldkey file if one is present. Without
        /// this flag, the command refuses to run when the target key file
        /// already exists. The existing coldkey is destroyed before the
        /// restored one is written.
        #[arg(long, default_value_t = false)]
        force: bool,
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
        /// Overwrite an existing hotkey file if one is present. Without
        /// this flag, the command refuses to run when the target key file
        /// already exists. The existing hotkey is destroyed before the
        /// restored one is written.
        #[arg(long, default_value_t = false)]
        force: bool,
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
        /// Read coldkey password from file at <path>. For non-interactive
        /// automation only. The file's first line (up to but not including
        /// the trailing newline) is taken as the password. Security note:
        /// anyone who can read the file can recover your password. Ensure
        /// the file is mode 0600, on a tmpfs (/dev/shm) if possible, and
        /// shredded immediately after use. Do not use this with mainnet
        /// wallets unless your filesystem, process listing, and shell
        /// history are all under your control. Ignored when --use-hotkey
        /// is set.
        #[arg(long, value_name = "PATH")]
        password_file: Option<String>,
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

    /// Unstake alpha from a hotkey back to the coldkey on a subnet.
    ///
    /// The `remove_stake` pallet extrinsic takes its amount in ALPHA (the
    /// subnet's own token), not TAO. Since dTAO, 1 alpha != 1 TAO on any
    /// non-root subnet, so you must pick a denomination:
    ///
    ///   --amount-alpha <N>   Submit N alpha directly.
    ///   --amount-tao   <N>   Ask to unstake ~N TAO worth. btt queries the
    ///                        subnet pool's head-block spot price and
    ///                        converts to alpha before signing. Slippage
    ///                        still applies on execution.
    ///   --all                Unstake the full current alpha balance.
    ///
    /// Exactly one of the three must be provided.
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
        /// Amount in ALPHA (subnet token). Conflicts with --amount-tao and
        /// --all. Sent directly as `amount_unstaked` after 9-decimal
        /// scaling.
        #[arg(long, conflicts_with_all = ["amount_tao", "all"])]
        amount_alpha: Option<f64>,
        /// Amount in TAO. btt queries the subnet's pool price at the head
        /// block and converts TAO -> alpha before signing. Displayed
        /// result reports the submitted alpha amount. Conflicts with
        /// --amount-alpha and --all.
        #[arg(long, conflicts_with_all = ["amount_alpha", "all"])]
        amount_tao: Option<f64>,
        /// Unstake the entire alpha balance on this (hotkey, netuid).
        /// Conflicts with --amount-alpha and --amount-tao.
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}
