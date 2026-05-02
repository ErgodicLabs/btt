use clap::{Parser, Subcommand};

/// Clap `value_parser` for the `--seed` flag on `wallet regen-coldkey`
/// and `wallet regen-hotkey`.
///
/// The subtensor sr25519 seed is 32 bytes, conventionally encoded as a
/// `0x`-prefixed 64-character lowercase hex string (66 characters
/// total). This parser rejects anything else at clap parse time so the
/// user gets a clear, actionable error before the key-decryption path
/// runs.
///
/// Accepts: `0x` prefix + exactly 64 hex digits (case-insensitive).
///
/// Rejects:
/// - missing `0x` prefix
/// - wrong length (not exactly 66 chars including prefix, i.e. not
///   exactly 64 hex digits after the prefix)
/// - non-hex characters
///
/// Returns the input string unchanged on success. The downstream
/// `recover_keypair` path still runs `hex::decode` and a
/// `len == 32` check as a defense-in-depth backstop against any
/// future caller that bypasses clap. This parser is the primary UX
/// gate; the runtime check is the correctness gate.
pub fn parse_seed_hex(s: &str) -> Result<String, String> {
    let stripped = s.strip_prefix("0x").ok_or_else(|| {
        format!(
            "seed must start with `0x` and be followed by exactly 64 hex characters \
             (32-byte sr25519 seed); got `{s}`"
        )
    })?;
    if stripped.len() != 64 {
        return Err(format!(
            "seed must be exactly 64 hex characters after the `0x` prefix \
             (32-byte sr25519 seed); got {} characters",
            stripped.len()
        ));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "seed must contain only hex characters [0-9a-fA-F] after the `0x` \
             prefix; got `{s}`"
        ));
    }
    Ok(s.to_string())
}

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

    /// Subnet read-only queries (registration cost, metagraph, hyperparameters, etc.)
    Subnet {
        #[command(subcommand)]
        action: SubnetAction,
    },

    /// Axon endpoint advertising for miners and validators
    Axon {
        #[command(subcommand)]
        action: AxonAction,
    },

    /// Weight commit/reveal for validators
    Weights {
        #[command(subcommand)]
        action: WeightsAction,
    },

    /// Concentrated liquidity management (dTAO AMM)
    Liquidity {
        #[command(subcommand)]
        action: LiquidityAction,
    },

    /// Utility commands (unit conversion, latency test)
    Utils {
        #[command(subcommand)]
        action: UtilsAction,
    },

    /// Emit SKILL.md for AI agent integration
    Skill,
}

#[derive(Subcommand, Debug)]
pub enum UtilsAction {
    /// Convert between TAO and RAO denominations.
    ///
    /// 1 TAO = 1,000,000,000 RAO (10^9). Provide either `--rao` or
    /// `--tao`; the command outputs both representations.
    Convert {
        /// Amount in RAO (smallest unit). Mutually exclusive with `--tao`.
        #[arg(long, conflicts_with = "tao")]
        rao: Option<u64>,
        /// Amount in TAO (decimal). Mutually exclusive with `--rao`.
        #[arg(long)]
        tao: Option<f64>,
    },

    /// Measure RPC endpoint latency.
    ///
    /// Connects to the endpoint, fetches the latest block, and reports
    /// the round-trip time in milliseconds. Uses the same connection
    /// path as all other btt commands.
    Latency,
}

#[derive(Subcommand, Debug)]
pub enum WeightsAction {
    /// Commit a hash of the weight vector. Hotkey-signing.
    ///
    /// Submits `SubtensorModule::commit_weights`. The hash is a 32-byte
    /// hex string (0x-prefixed or raw). The validator reveals the actual
    /// weights later with `weights reveal`.
    Commit {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// 32-byte commit hash (hex, 0x-prefixed or raw)
        #[arg(long)]
        hash: String,
    },

    /// Reveal the actual weights after a commit. Hotkey-signing.
    ///
    /// Submits `SubtensorModule::reveal_weights`. The UIDs, values, and
    /// salt must match what was used to compute the commit hash.
    Reveal {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Comma-separated UIDs
        #[arg(long, value_delimiter = ',')]
        uids: Vec<u16>,
        /// Comma-separated weight values
        #[arg(long, value_delimiter = ',')]
        values: Vec<u16>,
        /// Comma-separated salt values
        #[arg(long, value_delimiter = ',')]
        salt: Vec<u16>,
        /// Version key
        #[arg(long, default_value_t = 0)]
        version_key: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum LiquidityAction {
    /// Add a concentrated liquidity position on a subnet's dTAO AMM.
    ///
    /// Submits `Swap::add_liquidity`. Coldkey-signing. Specifies a tick
    /// range and liquidity amount in RAO. The position earns fees from
    /// swaps that cross the range. Note: this extrinsic may be disabled
    /// on mainnet until the subnet owner enables user liquidity.
    Add {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Lower tick bound (i32, price = 1.0001^tick)
        #[arg(long)]
        tick_low: i32,
        /// Upper tick bound (i32, price = 1.0001^tick)
        #[arg(long)]
        tick_high: i32,
        /// Liquidity amount in TAO (decimal)
        #[arg(long)]
        amount: f64,
    },

    /// Remove a liquidity position entirely. Coldkey-signing.
    ///
    /// Submits `Swap::remove_liquidity`. Returns TAO to coldkey balance
    /// and Alpha to coldkey->hotkey stake, including accrued fees.
    Remove {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Position ID to remove
        #[arg(long)]
        position_id: u128,
    },

    /// Modify liquidity on an existing position. Coldkey-signing.
    ///
    /// Submits `Swap::modify_position`. Positive delta adds liquidity;
    /// negative delta removes it.
    Modify {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Position ID to modify
        #[arg(long)]
        position_id: u128,
        /// Liquidity delta (abstract L-units from Uniswap-V3
        /// concentrated-liquidity math, NOT a RAO amount). Positive
        /// adds, negative removes. See the upstream pallet_subtensor_swap
        /// docs for the math.
        #[arg(long, allow_hyphen_values = true)]
        delta: i64,
    },

    /// List liquidity positions for a coldkey on a subnet. Read-only.
    ///
    /// Queries `Swap::Positions` storage. Returns position IDs, tick
    /// ranges, and liquidity amounts.
    List {
        /// Coldkey SS58 address to query
        #[arg(long)]
        ss58: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
    },

    /// Query pool state for a subnet. Read-only.
    ///
    /// Returns the current tick, liquidity depth, and whether user
    /// liquidity and V3 initialization are enabled.
    Pool {
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum AxonAction {
    /// Advertise the axon endpoint (IP, port) for a hotkey on a subnet.
    ///
    /// Submits a `SubtensorModule::serve_axon` extrinsic. Hotkey-signing
    /// (lower risk than coldkey). Other nodes use this endpoint to
    /// discover and connect to the miner or validator.
    Set {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet id
        #[arg(long)]
        netuid: u16,
        /// IP address (IPv4 or IPv6)
        #[arg(long)]
        ip: String,
        /// Port number
        #[arg(long)]
        port: u16,
        /// IP type (4 or 6). Auto-detected from the IP address if 0.
        #[arg(long, default_value_t = 0)]
        ip_type: u8,
        /// Protocol identifier
        #[arg(long, default_value_t = 4)]
        protocol: u8,
        /// Axon version
        #[arg(long, default_value_t = 0)]
        version: u32,
    },

    /// Clear the axon endpoint for a hotkey on a subnet. Hotkey-signing.
    ///
    /// Submits `SubtensorModule::serve_axon` with zeroed IP, port,
    /// protocol, and version fields, effectively de-advertising the
    /// endpoint.
    Reset {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet id
        #[arg(long)]
        netuid: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum SubnetAction {
    /// Query the current TAO cost to register a new subnet.
    ///
    /// Reads `SubnetRegistrationRuntimeApi::get_network_registration_cost`
    /// on the head block. The value returned is the cost computed by the
    /// runtime at query time; it decays between registrations per the
    /// `NetworkLockReductionInterval` schedule, so repeated calls at
    /// different blocks will return different values. This is a read-only
    /// query — no wallet, no signing, no extrinsic.
    LockCost,

    /// Enumerate every subnet currently registered on the chain.
    ///
    /// Reads `SubnetInfoRuntimeApi::get_subnets_info` on the head block
    /// and returns one row per subnet with id, owner ss58, current UID
    /// count, slot cap, tempo, burn, emission, difficulty, and immunity
    /// period. Rows are sorted ascending by netuid. Read-only; no
    /// wallet, no signing, no extrinsic.
    List,

    /// Dump the full metagraph of a given subnet.
    ///
    /// Reads `SubnetInfoRuntimeApi::get_metagraph(netuid)` on the head
    /// block and returns a subnet-level header plus one row per UID
    /// with the hotkey, coldkey, stake, rank, trust, consensus,
    /// incentive, dividends, emission, active, validator permit, and
    /// last-update columns. Read-only; no wallet, no signing, no
    /// extrinsic. Exits with a structured error if the netuid does
    /// not exist on chain.
    Metagraph {
        /// Subnet id to dump the metagraph for.
        #[arg(long)]
        netuid: u16,
    },

    /// Dump the full hyperparameter set of a given subnet.
    ///
    /// Reads `SubnetInfoRuntimeApi::get_subnet_hyperparams(netuid)` on
    /// the head block and returns all 27 runtime hyperparameter fields
    /// (rho, kappa, tempo, immunity_period, min/max_allowed_weights,
    /// min/max_burn, min/max_difficulty, adjustment_alpha, commit-
    /// reveal settings, liquid alpha, etc.). Read-only; no wallet,
    /// no signing, no extrinsic. Exits with a structured error if
    /// the netuid does not exist on chain.
    Hyperparameters {
        /// Subnet id to dump the hyperparameters for.
        #[arg(long)]
        netuid: u16,
    },

    /// Dump the dynamic-pricing info (dTAO market state + identity) for a given subnet.
    ///
    /// Reads `SubnetInfoRuntimeApi::get_dynamic_info(netuid)` on the
    /// head block and returns the dTAO market state (alpha supply,
    /// alpha-vs-TAO reserves, recent emission rate) along with the
    /// subnet-owner identity (hotkey, coldkey) and the on-chain
    /// identity record the owner has registered (name, description,
    /// github URL, website, discord, logo URL). Read-only; no wallet,
    /// no signing, no extrinsic. Exits with a structured error if the
    /// netuid does not exist on chain.
    Info {
        /// Subnet id to query.
        #[arg(long)]
        netuid: u16,
    },

    /// Register a hotkey on a subnet by paying the burn cost.
    ///
    /// Submits a `SubtensorModule::burned_register` extrinsic. Coldkey-
    /// signing. The burn cost varies per subnet and changes between
    /// blocks — query it first with `btt subnet lock-cost` (note: that
    /// command shows the subnet *creation* cost; the per-UID burn cost
    /// is a different storage value that this command will display
    /// before prompting for confirmation in a future iteration).
    Register {
        /// Wallet name (coldkey used for signing and paying the burn)
        #[arg(long)]
        name: String,
        /// SS58 address of the hotkey to register
        #[arg(long)]
        hotkey: String,
        /// Subnet id to register on
        #[arg(long)]
        netuid: u16,
    },
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
    /// List wallets in the btt config directory (linux:
    /// $XDG_CONFIG_HOME/btt/wallets or $HOME/.config/btt/wallets; macOS:
    /// $HOME/Library/Application Support/btt/wallets; windows:
    /// %APPDATA%\btt\wallets). Legacy $HOME/.bittensor/wallets is used
    /// automatically if present and the new location is not.
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
        /// Overwrite an existing wallet if one is present. Without this
        /// flag, the command refuses to run when a coldkey or hotkey file
        /// at the target wallet path already exists. With this flag, the
        /// existing coldkey AND hotkey are destroyed before the new pair
        /// is written. THIS IS IRREVERSIBLE — recovering the old wallet
        /// requires its mnemonic or seed. Back up the existing mnemonic
        /// first if you have not.
        #[arg(long, default_value_t = false)]
        force: bool,
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
        /// BIP39 mnemonic phrase. Mutually exclusive with `--seed`; exactly
        /// one of the two must be provided.
        #[arg(long, conflicts_with = "seed")]
        mnemonic: Option<String>,
        /// 32-byte sr25519 seed encoded as `0x` + 64 hex characters (66
        /// characters total). Mutually exclusive with `--mnemonic`;
        /// exactly one of the two must be provided. Clap rejects
        /// non-conforming input at parse time.
        #[arg(long, value_parser = parse_seed_hex)]
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
        /// BIP39 mnemonic phrase. Mutually exclusive with `--seed`; exactly
        /// one of the two must be provided.
        #[arg(long, conflicts_with = "seed")]
        mnemonic: Option<String>,
        /// 32-byte sr25519 seed encoded as `0x` + 64 hex characters (66
        /// characters total). Mutually exclusive with `--mnemonic`;
        /// exactly one of the two must be provided. Clap rejects
        /// non-conforming input at parse time.
        #[arg(long, value_parser = parse_seed_hex)]
        seed: Option<String>,
        /// Overwrite an existing hotkey file if one is present. Without
        /// this flag, the command refuses to run when the target key file
        /// already exists. The existing hotkey is destroyed before the
        /// restored one is written.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Send TAO from this wallet's coldkey to a destination address.
    ///
    /// Decrypts the coldkey, constructs a `Balances::transfer_keep_alive`
    /// extrinsic, signs, submits, and waits for finalization. The
    /// sender's account must retain at least the existential deposit
    /// after the transfer.
    Transfer {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        name: String,
        /// Destination SS58 address
        #[arg(long)]
        dest: String,
        /// Amount of TAO to transfer (decimal, e.g. 1.5)
        #[arg(long)]
        amount: f64,
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

    /// Replace a hotkey associated with this wallet's coldkey.
    ///
    /// Submits a `SubtensorModule::swap_hotkey` extrinsic. Coldkey-
    /// signing. The old hotkey's registrations, stakes, and weights
    /// transfer to the new hotkey.
    SwapHotkey {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        name: String,
        /// SS58 address of the old hotkey to replace
        #[arg(long)]
        old_hotkey: String,
        /// SS58 address of the new hotkey to install
        #[arg(long)]
        new_hotkey: String,
    },

    /// Announce intent to swap this wallet's coldkey. Coldkey-signing.
    /// Starts a 5-day (7200 block) waiting period before execution.
    SwapColdkeyAnnounce {
        /// Wallet name (current coldkey, used for signing)
        #[arg(long)]
        name: String,
        /// SS58 address of the new coldkey to swap to
        #[arg(long)]
        new_coldkey: String,
    },

    /// Execute a previously announced coldkey swap. Coldkey-signing.
    /// Only succeeds after the 5-day waiting period has elapsed.
    SwapColdkeyExecute {
        /// Wallet name (current coldkey, used for signing)
        #[arg(long)]
        name: String,
    },

    /// Cancel a pending coldkey swap announcement. Coldkey-signing.
    SwapColdkeyClear {
        /// Wallet name (current coldkey, used for signing)
        #[arg(long)]
        name: String,
    },

    /// Dispute another account's pending coldkey swap. Coldkey-signing.
    /// Requires governance authority (senate membership).
    SwapColdkeyDispute {
        /// Wallet name (disputer's coldkey, used for signing)
        #[arg(long)]
        name: String,
        /// SS58 address of the coldkey whose swap is being disputed
        #[arg(long)]
        target: String,
    },

    /// Query on-chain identity for an SS58 address.
    ///
    /// Reads `SubtensorModule::Identities` storage map. Returns name,
    /// URL, description, image, discord, github repo, and github
    /// username. Empty strings for unset fields. Read-only; no wallet,
    /// no signing, no extrinsic.
    GetIdentity {
        /// SS58 address to query
        #[arg(long)]
        ss58: String,
    },

    /// Set on-chain identity for this wallet's coldkey.
    ///
    /// Submits a `SubtensorModule::set_identity` extrinsic. Coldkey-
    /// signing. All fields are optional strings; unset fields are sent
    /// as empty strings.
    SetIdentity {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        name: String,
        /// Display name
        #[arg(long, default_value = "")]
        display_name: String,
        /// URL
        #[arg(long, default_value = "")]
        url: String,
        /// Description
        #[arg(long, default_value = "")]
        description: String,
        /// Image URL
        #[arg(long, default_value = "")]
        image: String,
        /// Discord handle
        #[arg(long, default_value = "")]
        discord: String,
        /// GitHub repository
        #[arg(long, default_value = "")]
        github_repo: String,
        /// GitHub username
        #[arg(long, default_value = "")]
        github_username: String,
    },

    /// Reap stale `.tmp.*`, `.bak.*`, and `.lock.*` entries under the
    /// wallets directory. These are reserved prefixes left behind by
    /// `wallet create` on crashed or interrupted runs (see issue #42).
    ///
    /// `.tmp.<name>.<pid>.<nanos>.<ctr>/` are atomic-create staging
    /// dirs, `.bak.<name>.<pid>.<nanos>.<ctr>/` are `--force` backup
    /// dirs, and `.lock.<name>` are per-wallet `flock(2)` sentinels.
    /// The cleanup command uses a strict grammar match and will never
    /// touch anything that does not fit the reserved-prefix pattern.
    /// `.lock.*` files are probed with a non-blocking `flock(LOCK_NB)`
    /// and skipped if currently held by another process.
    ///
    /// Emits a JSON array of `{path, kind, action}` records.
    Cleanup {
        /// List what would be removed without touching disk. Each
        /// candidate is reported with `action = "kept-dry-run"`.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Restrict the scan to entries whose `<name>` component
        /// matches this wallet name verbatim: `.tmp.<name>.*`,
        /// `.bak.<name>.*`, and `.lock.<name>`. The name is validated
        /// (1..=64 chars of `[A-Za-z0-9_-]`) before use; path-traversal
        /// characters (`/`, `..`, NUL) are rejected.
        #[arg(long, value_name = "NAME")]
        wallet: Option<String>,
        /// Only reap entries whose modification time is older than
        /// this duration. Grammar: `\d+[smhd]` — for example `60s`,
        /// `30m`, `24h`, `7d`. Default: no age filter (reap everything
        /// matching the prefix).
        #[arg(long, value_name = "DURATION")]
        older_than: Option<String>,
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

    /// Move stake from one hotkey/subnet to another without unstake+restake.
    ///
    /// Submits a `SubtensorModule::move_stake` extrinsic. Coldkey-signing.
    /// Avoids the slippage of separate unstake+restake on the dTAO AMM.
    /// The amount is specified in TAO and converted to alpha-rao
    /// internally.
    Move {
        /// Wallet name (coldkey will be decrypted for signing)
        #[arg(long)]
        wallet: String,
        /// SS58 address of the origin hotkey
        #[arg(long)]
        origin_hotkey: String,
        /// SS58 address of the destination hotkey
        #[arg(long)]
        destination_hotkey: String,
        /// Origin subnet ID
        #[arg(long)]
        origin_netuid: u16,
        /// Destination subnet ID
        #[arg(long)]
        destination_netuid: u16,
        /// Amount in TAO to move
        #[arg(long)]
        amount: f64,
    },

    /// Transfer staked alpha to a different coldkey without unstaking.
    ///
    /// Submits `SubtensorModule::transfer_stake`. Coldkey-signing.
    /// The recipient coldkey receives the alpha stake on the specified
    /// hotkey and subnet.
    Transfer {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// SS58 address of the destination coldkey
        #[arg(long)]
        dest_coldkey: String,
        /// Hotkey SS58 address
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Amount in TAO
        #[arg(long)]
        amount: f64,
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

    /// Swap alpha between two subnets via the dTAO AMM.
    ///
    /// Submits `SubtensorModule::swap_stake`. Coldkey-signing. Sells
    /// alpha on the origin subnet and buys alpha on the destination
    /// subnet through the pool. Slippage applies.
    Swap {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// Hotkey SS58 address
        #[arg(long)]
        hotkey: String,
        /// Origin subnet ID (selling alpha)
        #[arg(long)]
        origin_netuid: u16,
        /// Destination subnet ID (buying alpha)
        #[arg(long)]
        destination_netuid: u16,
        /// Amount in TAO
        #[arg(long)]
        amount: f64,
    },

    /// Set child hotkey delegation on a subnet. Hotkey-signing.
    ChildSet {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Parent hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// SS58 address of the child hotkey
        #[arg(long)]
        child: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Proportion of stake weight to delegate (0 to u64::MAX)
        #[arg(long)]
        proportion: u64,
    },

    /// Query child hotkeys for a parent. Read-only.
    ChildGet {
        /// SS58 address of the parent hotkey
        #[arg(long)]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
    },

    /// Revoke all child delegations on a subnet. Hotkey-signing.
    ChildRevoke {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Parent hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
    },

    /// Set the childkey take rate. Hotkey-signing.
    ChildTake {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Hotkey name
        #[arg(long, default_value = "default")]
        hotkey: String,
        /// Subnet ID
        #[arg(long)]
        netuid: u16,
        /// Take rate (0 to 65535, representing 0% to 100%)
        #[arg(long)]
        take: u16,
    },

    /// Claim accumulated alpha dividends from subnets. Coldkey-signing.
    ///
    /// Submits `SubtensorModule::claim_root` with up to 5 subnet IDs.
    /// Harvests any pending alpha emissions on the specified subnets.
    Claim {
        /// Wallet name (coldkey used for signing)
        #[arg(long)]
        wallet: String,
        /// Subnet IDs to claim from (up to 5, comma-separated)
        #[arg(long, value_delimiter = ',')]
        netuids: Vec<u16>,
    },
}

#[cfg(test)]
mod tests {
    use super::parse_seed_hex;

    // Issue #87: clap-level `parse_seed_hex` rejects non-conforming input
    // with clear messages. Accepts only `0x` + 64 hex chars.

    #[test]
    fn parse_seed_accepts_valid_64_hex_with_prefix() {
        let seed = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let parsed = parse_seed_hex(seed).expect("32-byte zero seed should parse");
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_seed_accepts_mixed_case_hex() {
        let seed = "0xDeadBeefCafeBabe0123456789aBcDeF0123456789ABCDEF0123456789abcdef";
        let parsed = parse_seed_hex(seed).expect("mixed-case hex should parse");
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_seed_rejects_missing_0x_prefix() {
        let err = parse_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("missing prefix must be rejected");
        assert!(err.contains("`0x`"), "error should name the 0x prefix: {err}");
    }

    #[test]
    fn parse_seed_rejects_too_short() {
        // 0x + 62 hex chars = 64 total, 2 short.
        let err = parse_seed_hex(
            "0x00000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("too short must be rejected");
        assert!(
            err.contains("exactly 64 hex characters"),
            "error should name the length: {err}"
        );
        assert!(err.contains("62"), "error should report the actual length: {err}");
    }

    #[test]
    fn parse_seed_rejects_too_long() {
        // 0x + 66 hex chars, 2 over.
        let err = parse_seed_hex(
            "0x000000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("too long must be rejected");
        assert!(err.contains("exactly 64 hex characters"), "got {err}");
        assert!(err.contains("66"), "error should report the actual length: {err}");
    }

    #[test]
    fn parse_seed_rejects_non_hex_characters() {
        // 63 zeros + 1 'z' — right length, wrong charset.
        let err = parse_seed_hex(
            "0x000000000000000000000000000000000000000000000000000000000000000z",
        )
        .expect_err("non-hex must be rejected");
        assert!(
            err.contains("only hex characters"),
            "error should name the charset: {err}"
        );
    }

    #[test]
    fn parse_seed_rejects_empty_string() {
        assert!(parse_seed_hex("").is_err());
    }

    #[test]
    fn parse_seed_rejects_just_prefix() {
        let err = parse_seed_hex("0x").expect_err("0x alone must be rejected");
        assert!(err.contains("exactly 64"), "got {err}");
    }
}
