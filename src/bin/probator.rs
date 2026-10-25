//! `probator` - the general review-contract runtime.
//!
//! One binary executes any review contract as data:
//! `docs/review-contract-design.md` records the design and
//! `docs/review-contract.schema.json` is the single contract source this
//! binary mirrors. A blocking gate binds a contract by registry tag in the
//! signed configuration; running a file path is the development and one-off
//! form, and its results are never authoritative receipts.

// This binary is its own crate root, so a plain `mod contract;` would resolve
// beside it in src/bin/ - where Cargo would auto-discover the module as yet
// another binary. The explicit path keeps the module tree in its own
// directory.
#[path = "../checker_binding.rs"]
mod checker_binding;
#[path = "probator/conceal.rs"]
mod conceal;
#[path = "probator/contract.rs"]
mod contract;
#[path = "probator/credential.rs"]
mod credential;
#[path = "probator/date.rs"]
mod date;
#[path = "probator/documents.rs"]
mod documents;
#[path = "probator/engine.rs"]
mod engine;
#[path = "probator/eval.rs"]
mod eval;
#[path = "probator/evidence.rs"]
mod evidence;
#[path = "probator/fullservice.rs"]
mod fullservice;
#[path = "probator/gate_audit.rs"]
mod gate_audit;
// The review binary shares the main crate's git helpers and exercises only
// the reachability probe - the rest of the module stays for that crate.
#[allow(dead_code)]
#[path = "../git.rs"]
mod git;
#[path = "probator/inspect.rs"]
mod inspect;
#[path = "probator/install.rs"]
mod install;
#[path = "probator/manifest.rs"]
mod manifest;
// Operator-ruled waivers: the signed objections ledger. This crate only reads
// and verifies rulings; filing and signing belong to the gate that holds the
// operator's key.
#[path = "probator/objection.rs"]
mod objection;
#[path = "probator/ranges.rs"]
mod ranges;
// The sealed run record: report fields plus the one optional signature
// marker whose empty default must not materialize on a re-serialization.
#[path = "probator/records.rs"]
mod records;
#[path = "probator/sanitize.rs"]
mod sanitize;
#[path = "../seal.rs"]
mod seal;
#[path = "probator/serve.rs"]
mod serve;
#[path = "probator/stage1.rs"]
mod stage1;
#[path = "probator/submit.rs"]
mod submit;
#[path = "probator/util.rs"]
mod util;

use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Execute a Probator review contract.
#[derive(Parser)]
#[command(name = "probator", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a contract file and validate it against the contract rules.
    Validate {
        /// The contract.json file.
        contract: PathBuf,
    },
    /// Sanitize a payload read from stdin, writing the result to stdout.
    Sanitize {
        /// The evidence variant: also strip endpoints, addresses and account
        /// identifiers.
        #[arg(long)]
        source: bool,
    },
    /// Host a run's tools as an MCP stdio server for the audit session.
    Serve {
        /// The contract.json file.
        #[arg(long)]
        contract: PathBuf,
        /// The run directory holding scope.json.
        #[arg(long)]
        run: PathBuf,
    },
    /// Print the tool manifest a contract generates.
    Manifest {
        /// The contract.json file.
        #[arg(long)]
        contract: PathBuf,
        /// The full-service surface instead of the gate's.
        #[arg(long)]
        full_service: bool,
        /// Project labels for full-service submit coverage.
        #[arg(long, value_delimiter = ',')]
        projects: Vec<String>,
    },
    /// Run a contract's deterministic stage over one explicit range.
    Stage1 {
        /// The contract.json file.
        #[arg(long)]
        contract: PathBuf,
        /// The repository under review.
        #[arg(long)]
        repo: PathBuf,
        /// The base commit; omit for a whole-snapshot scan.
        #[arg(long)]
        base: Option<String>,
        /// The outgoing commit.
        #[arg(long)]
        head: String,
        /// The machine-local withheld-names list (default: the documented
        /// environment override or config location).
        #[arg(long)]
        withheld: Option<PathBuf>,
    },
    /// Build a full-service snapshot into an output directory: snapshot.json,
    /// request.json and scope.json, ready for `serve`.
    Snapshot {
        /// The contract.json file.
        #[arg(long)]
        contract: PathBuf,
        /// The manifest: {"projects": {"label": "/absolute/source"}}.
        #[arg(long)]
        manifest: PathBuf,
        /// The original request document (conversation_url, messages, ...).
        #[arg(long)]
        request: PathBuf,
        /// The output directory, created fresh.
        #[arg(long)]
        output: PathBuf,
    },
    /// Run a checker's gate over the repository's unpublished snapshots.
    Run {
        /// The installed contract.json.
        #[arg(long)]
        contract: PathBuf,
        /// The repository under review.
        #[arg(long)]
        repo: PathBuf,
    },
    /// The deterministic publication sweep - withheld names and credential
    /// shapes over the repository's unpublished snapshots. Registered as an
    /// ordinary checker row in an earlier phase, it is the script-check half
    /// of a gate: a pattern-decidable refusal skips every later phase and
    /// never costs a semantic review a token.
    Baseline {
        /// The repository under review.
        #[arg(long)]
        repo: PathBuf,
    },
    /// Run or resume a full-service audit over selected projects.
    FullAudit {
        /// The installed contract.json.
        #[arg(long)]
        contract: PathBuf,
        /// The project selection manifest.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// The original request document.
        #[arg(long)]
        request: Option<PathBuf>,
        /// The output directory for a new audit.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Continue an existing audit directory.
        #[arg(long)]
        resume: Option<PathBuf>,
    },
    /// Score recorded audit runs into a checker x architecture matrix:
    /// productive sealed verdicts, decisive coverage and reason substance,
    /// with cost and handshake anomalies reported alongside.
    Eval {
        /// The profiles root; defaults to the installed data directory.
        #[arg(long)]
        profiles: Option<PathBuf>,
        /// Emit the matrix as JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Hide checker/architecture cells with fewer runs than this.
        #[arg(long, default_value = "1")]
        min_runs: usize,
        /// Also print one line per individual run after the matrix.
        #[arg(long)]
        verbose: bool,
    },
    /// The orchestrator-facing audit surface: one JSON action on stdin —
    /// {kind, target, detail} — runs every policy checker bound to the
    /// event and prints one JSON array of gate findings on stdout.
    /// Failures are high-severity findings, never bare errors.
    GateAudit,
    /// Show the policy Probator actually enforces: registered checkers, their
    /// contract domains, deterministic stage-1 rules and profile bindings,
    /// read from the installed configuration. --html writes a self-contained
    /// document; --json is the machine form.
    Inspect {
        /// The checkers.toml policy file; defaults to the config location.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The profiles root; defaults to the installed data directory.
        #[arg(long)]
        profiles: Option<PathBuf>,
        /// Emit the registry as JSON instead of a listing.
        #[arg(long)]
        json: bool,
        /// Write a self-contained HTML policy document to this path.
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Install a checker from its source directory (tools/<checker>/).
    Install {
        /// The checker's source directory.
        #[arg(long)]
        source: PathBuf,
    },
    /// Refresh an installed checker's payload and registry entry.
    Update {
        /// The checker's source directory.
        #[arg(long)]
        source: PathBuf,
    },
    /// Pull the registry's published profile documents for a checker.
    Pull {
        /// The checker's source directory (its contract names the profile).
        #[arg(long)]
        source: PathBuf,
        /// A specific published tag.
        #[arg(long)]
        tag: Option<String>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Validate { contract: path } => match contract::load(&path) {
            Ok(contract) => {
                let stage1 = contract.stage1.as_ref();
                println!("{}: valid review contract", contract.name);
                println!(
                    "  {} domains, {} finding keys, {} stage-1 rules{}, on: {}",
                    contract.domains.len(),
                    contract.finding_keys.len(),
                    stage1.map_or(0, |s| s.rules.len()),
                    if stage1.is_some_and(|s| s.surfaces) {
                        " (surfaces echoed)"
                    } else {
                        ""
                    },
                    contract.on.join(", ")
                );
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{}: {message}", path.display());
                ExitCode::FAILURE
            }
        },
        Command::Sanitize { source } => {
            let mut input = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut input) {
                eprintln!("stdin: {error}");
                return ExitCode::FAILURE;
            }
            let output = if source {
                sanitize::sanitize_source(&input)
            } else {
                sanitize::sanitize(&input)
            };
            print!("{output}");
            ExitCode::SUCCESS
        }
        Command::Serve { contract, run } => match serve::Server::load(&contract, &run) {
            Ok(server) => {
                let stdin = std::io::stdin();
                let stdout = std::io::stdout();
                server.serve_mcp(stdin.lock(), &mut stdout.lock());
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::Manifest {
            contract,
            full_service,
            projects,
        } => {
            match contract::load(&contract)
                .and_then(|c| serve::load_catalog(&contract, &c).map(|_| c))
            {
                Ok(contract) => {
                    let mode = if full_service {
                        manifest::Mode::FullService
                    } else {
                        manifest::Mode::Gate
                    };
                    let tools = manifest::manifest(&contract, mode, &projects);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&tools).unwrap_or_else(|_| "[]".to_string())
                    );
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Stage1 {
            contract,
            repo,
            base,
            head,
            withheld,
        } => match contract::load(&contract) {
            Ok(contract) => {
                let target = stage1::Target {
                    kind: "manual".to_string(),
                    label: format!("manual {}…{}", base.as_deref().unwrap_or(""), &head),
                    scope: if base.is_some() {
                        "range".into()
                    } else {
                        "snapshot".into()
                    },
                    base,
                    head,
                    ref_: None,
                };
                let rules: &[contract::Rule] =
                    contract.stage1.as_ref().map_or(&[], |stage1| &stage1.rules);
                let opts = stage1::Opts {
                    withheld_path: withheld,
                };
                match stage1::audit_all(
                    &repo.to_string_lossy(),
                    &[target],
                    rules,
                    &opts,
                    contract.stage1.as_ref().is_some_and(|s| s.surfaces),
                ) {
                    Ok((ok, summaries)) => {
                        let json: Vec<_> = summaries.iter().map(|s| s.to_json()).collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json).unwrap_or_else(|_| "[]".into())
                        );
                        if ok {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    Err(message) => {
                        eprintln!("{message}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(message) => {
                eprintln!("{}: {message}", contract.display());
                ExitCode::FAILURE
            }
        },
        Command::Snapshot {
            contract,
            manifest,
            request,
            output,
        } => match snapshot_run(&contract, &manifest, &request, &output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::Run { contract, repo } => match engine::run(&repo.to_string_lossy(), &contract) {
            Ok(code) => ExitCode::from(code as u8),
            Err(message) => {
                eprintln!("{}", sanitize::sanitize(&message));
                ExitCode::FAILURE
            }
        },
        Command::Baseline { repo } => {
            let repo = repo.to_string_lossy();
            // The baseline is not a checker: its rule set is fixed and
            // universal, so it needs no contract - only the machine-local
            // withheld-names list the builtin already knows how to find.
            let rules = [contract::Rule {
                id: "publication-baseline".to_string(),
                title: "Withheld names and credential shapes, scanned over the whole revision"
                    .to_string(),
                kind: "builtin".to_string(),
                pattern: None,
                target: None,
                prompt: None,
                builtin: Some("withheld-names-and-credentials".to_string()),
            }];
            let targets = match ranges::ranges(&repo) {
                Ok(targets) => targets,
                // An underivable scope is not a script-decidable refusal:
                // nothing mechanically checkable exists yet, and the
                // checkers that follow resolve the scope for themselves -
                // the semantic layer reports the problem, in its own words.
                Err(message) => {
                    eprintln!("baseline: {message}");
                    return ExitCode::SUCCESS;
                }
            };
            if targets.is_empty() {
                println!("baseline: nothing unpublished in this operation");
                return ExitCode::SUCCESS;
            }
            match stage1::audit_all(
                &repo,
                &targets,
                &rules,
                &stage1::Opts {
                    withheld_path: None,
                },
                false,
            ) {
                Err(message) => {
                    eprintln!("{}", sanitize::sanitize(&message));
                    ExitCode::FAILURE
                }
                Ok((ok, summaries)) => {
                    for summary in &summaries {
                        println!(
                            "baseline: {} — {} ({}, findings={})",
                            summary.status,
                            summary.label,
                            summary.scope,
                            summary.hits.len(),
                        );
                    }
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "baseline: the deterministic publication check refused this \
                             operation; nothing reaches a reviewer"
                        );
                        ExitCode::FAILURE
                    }
                }
            }
        }
        Command::FullAudit {
            contract,
            manifest,
            request,
            output,
            resume,
        } => {
            let outcome = match (resume, manifest, request, output) {
                (Some(dir), None, None, None) => engine::resume_full_audit(&contract, &dir),
                (None, Some(manifest), Some(request), Some(output)) => {
                    engine::start_full_audit(&contract, &manifest, &request, &output)
                }
                _ => Err(
                    "Use --resume alone, or provide --manifest, --request and --output".to_string(),
                ),
            };
            match outcome {
                Ok(code) => ExitCode::from(code as u8),
                Err(message) => {
                    eprintln!("{}", sanitize::sanitize(&message));
                    ExitCode::FAILURE
                }
            }
        }
        Command::Install { source } => match install::install(&source) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::Update { source } => match install::update(&source) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::Eval {
            profiles,
            json,
            min_runs,
            verbose,
        } => match eval::run(
            &profiles.unwrap_or_else(install::profile_root),
            json,
            min_runs,
            verbose,
        ) {
            Ok(code) => ExitCode::from(code as u8),
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::GateAudit => ExitCode::from(gate_audit::run() as u8),
        Command::Inspect {
            policy,
            profiles,
            json,
            html,
        } => match inspect::run(
            &policy.unwrap_or_else(install::policy_file),
            &profiles.unwrap_or_else(install::profile_root),
            json,
            html.as_deref(),
        ) {
            Ok(code) => ExitCode::from(code as u8),
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        Command::Pull { source, tag } => match install::pull(&source, tag.as_deref()) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Build a full-service run directory: the sanitized snapshot, the original
/// request, and the scope the evidence server reads. The review itself is
/// `full-audit`'s.
fn snapshot_run(
    contract_path: &std::path::Path,
    manifest_path: &std::path::Path,
    request_path: &std::path::Path,
    output: &std::path::Path,
) -> Result<(), String> {
    let contract = contract::load(contract_path)?;
    if !contract.tools.full_service {
        return Err("This contract offers no full-service mode".to_string());
    }
    engine::build_snapshot_dir(&contract, manifest_path, request_path, output)?;
    let snapshot: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(output.join("snapshot.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "snapshot: {} files over {} projects",
        snapshot["files"].as_object().map_or(0, |f| f.len()),
        snapshot["projects"].as_object().map_or(0, |p| p.len())
    );
    Ok(())
}
