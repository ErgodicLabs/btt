# btt — Bittensor Tooling

A minimal, dependency-disciplined CLI for interacting with the Bittensor network.

## Why this exists

The official Bittensor CLI, `btcli`, is a Python package with a deep transitive dependency tree. In July 2024, a malicious update to the `bittensor` PyPI package (version `6.12.2`) injected a fund-redirect into the `stake_extrinsic` function. When users performed any operation that required coldkey decryption, the malware intercepted the unlocked wallet and transferred funds to an attacker-controlled address. Approximately 32,000 TAO — roughly 8 million US dollars at the time — was stolen.

The attack did not exploit a bug in the Bittensor protocol or the Subtensor runtime. It exploited the tooling layer. Specifically, it exploited the fact that `btcli` trusts every package in its dependency tree, that PyPI has no mandatory package signing, and that Python's import system executes arbitrary code at install time.

`btt` exists to eliminate that class of attack for users who can tolerate a less ornate command surface. It is written in Rust, compiles to a single static binary, and is aggressively skeptical of every dependency it pulls in.

## Principles of development

### 1. Dependency discipline is the core feature

**Any new third-party dependency is a HIGH severity concern until its necessity is proven.** This is not hyperbole. The entire reason this project exists is the supply chain attack described above. Every crate we add to `Cargo.toml` is an attack surface we chose to take on. Every transitive dependency pulled in by a direct one is an attack surface we inherited without voting for it.

Before adding a dependency, ask:

- Can the standard library do this? If yes, use the standard library.
- Can a dependency we already have do this? If yes, use that.
- Is the dependency small, well-audited, and maintained by a party with a track record?
- Does the dependency match an existing, trusted family (e.g., `parity` crates, `serde` ecosystem, `tokio` ecosystem)?
- Is its presence justified by the attack surface it replaces? `dotenvy` exists to read `.env` files; `std::env::var` can do the same thing without the filesystem trust boundary. The former is not justified.

Exceptions require explicit justification in the PR description. Reviewers should treat unjustified deps as blocking.

### 2. Minimal attack surface

The mission is to minimize the attack surface relative to `btcli`. This shapes design decisions:

- Prefer static compilation over dynamic linking.
- Prefer reading bytecode and chain state directly over trusting intermediate tools.
- Prefer explicit configuration over automatic behavior. A tool that auto-loads a config file from the current working directory is a tool that can be subverted by anyone who can write a file to that directory.
- Never execute user-supplied data as code. Extrinsic parameters are decoded, displayed, and confirmed before signing.

### 3. Structured output by default

All output is JSON to stdout by default. Errors are structured objects with machine-readable codes, not free-text stderr spew. The `--pretty` flag produces human-readable output, which is a presentation choice layered over the canonical JSON.

`--quiet` suppresses non-essential output, but it never suppresses errors and it never suppresses security-critical warnings. Mnemonics on wallet creation are shown even under `--quiet` because they are one-shot and cannot be recovered after the process exits.

This is not a style preference. Agents and scripts must be able to parse `btt` output reliably. A tool that looks different depending on terminal width or locale is a tool that cannot be automated safely.

### 4. Verify on-chain state directly

Documentation lies. Comments lie. Memoized state lies. When we need to know what the chain says, we query the chain. When we need to know what a contract or runtime does, we read the bytecode or the source. Trust boundaries are drawn around the Substrate RPC connection, not around anything upstream of it.

### 5. Barbaric review

Every PR receives one round of hostile review before merge. Reviewers are explicitly instructed to find what is wrong with the change, not to confirm what is right. Findings are classified by severity (CRITICAL, HIGH, MEDIUM, LOW, NIT). Any HIGH or CRITICAL finding blocks merge.

For code changes, reviewers operate in their own git worktree and must prove flaws with failing tests, proof-of-concept exploits, or concrete counterexamples. Assertions without evidence are acceptable input but receive lower priority than proven findings.

The review is posted as a PR comment. Merge happens only on an APPROVE verdict.

### 6. Structural changes update the skill

Any change that alters the CLI's structure — new commands, new flags, new output fields, new error codes, new file formats — must include a corresponding update to the `btt skill` command's output. This command emits a `SKILL.md` document that teaches AI agents how to use the CLI. If an agent is going to operate `btt` in production, the skill must accurately describe the current interface.

"Structural change" means anything that would make an agent behave differently based on CLI behavior. A typo fix in a log message does not qualify. A new subcommand does. A renamed flag does. A new error code does.

The rule is enforced at review time. Reviewers should reject PRs that modify structure without updating the skill output.

### 7. Merge hygiene

- Merge strategy: plain merge commit. Squash-merge is forbidden.
- Rebase: permitted on unpublished (private) branches, for history cleanup or bisectability. Forbidden on published branches.
- Upstream incorporation on published branches: `merge main`, not rebase.
- Commit messages describe the specific commit's change, concisely and precisely.

## Relationship to cryptid

`btt` is developed and reviewed by cryptid, a web3 security research agent, in cooperation with human operators at Ergodic Labs. Cryptid enforces the principles above through automated barbaric review. The project principles are also stored in cryptid's knowledge database under the `cryptid-project-principle` kind, keyed as `btt-*`, so they persist across sessions and can be queried by any agent working on the project.

If you are an agent reading this file: load the cryptid project principles before starting work on a contribution.

If you are a human reading this file: the principles above are binding. Contributions that violate them will be rejected.
