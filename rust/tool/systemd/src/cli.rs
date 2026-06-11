use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{install, pcrlock};
use lanzaboote_tool::{
    architecture::Architecture,
    signature::{EmptyKeyPair, LocalKeyPair},
};

/// The default log level.
///
/// 2 corresponds to the level INFO.
const DEFAULT_LOG_LEVEL: usize = 2;

#[derive(Parser)]
pub struct Cli {
    /// Silence all output
    #[arg(short, long)]
    quiet: bool,
    /// Verbose mode (-v, -vv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install(InstallCommand),
    LockBootLoader(LockBootLoaderCommand),
    LockThinStub(LockThinStubCommand),
    GcPcrlock(GcPcrlockCommand),
    LockSysexts(LockSysextsCommand),
}

#[derive(Parser)]
struct InstallCommand {
    /// System for lanzaboote binaries, e.g. defines the EFI fallback path
    #[arg(long)]
    system: String,

    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// Systemd-boot loader config
    #[arg(long)]
    systemd_boot_loader_config: PathBuf,

    /// Allow installing unsigned artifacts
    #[arg(long, num_args = 1)]
    allow_unsigned: bool,

    /// sbsign Public Key
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// sbsign Private Key
    #[arg(long)]
    private_key: Option<PathBuf>,

    /// Configuration limit
    #[arg(long, default_value_t = 1)]
    configuration_limit: usize,

    /// Initial number of boot counting tries, set to zero to disable boot counting
    #[arg(long, default_value_t = 0)]
    bootcounting_initial_tries: u32,

    #[arg(long)]
    pcrlock_directory: Option<PathBuf>,

    /// Private key for signing PCR 11 predictions (via systemd-measure sign)
    #[arg(long)]
    pcr_private_key: Option<PathBuf>,

    /// Public key for PCR 11 signature verification
    #[arg(long)]
    pcr_public_key: Option<PathBuf>,

    /// EFI system partition mountpoint (e.g. efiSysMountPoint)
    esp: PathBuf,

    /// List of generation links (e.g. /nix/var/nix/profiles/system-*-link)
    generations: Vec<PathBuf>,
}

#[derive(Parser)]
struct LockThinStubCommand {
    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// EFI system partition mountpoint
    #[arg(long)]
    esp: PathBuf,

    /// Output .pcrlock file path
    #[arg(long)]
    pcrlock: PathBuf,

    /// Installed thin stub on the ESP
    stub: PathBuf,
}

#[derive(Parser)]
struct LockBootLoaderCommand {
    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// EFI system partition mountpoint
    #[arg(long)]
    esp: PathBuf,

    /// Output .pcrlock file path
    #[arg(long)]
    pcrlock: PathBuf,
}

#[derive(Parser)]
struct LockSysextsCommand {
    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// EFI system partition mountpoint
    #[arg(long)]
    esp: PathBuf,

    /// Output .pcrlock file path
    #[arg(long)]
    pcrlock: PathBuf,
}

#[derive(Parser)]
struct GcPcrlockCommand {
    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// Directory holding the .pcrlock variant files
    #[arg(long)]
    pcrlock: PathBuf,

    /// PE hash of a variant to keep; may be given multiple times
    #[arg(long)]
    keep: Vec<String>,
}

impl Cli {
    pub fn call(self, module: &str) {
        stderrlog::new()
            .module(module)
            .show_level(false)
            .quiet(self.quiet)
            .verbosity(DEFAULT_LOG_LEVEL + usize::from(self.verbose))
            .init()
            .expect("Failed to setup logger.");

        if let Err(e) = self.commands.call() {
            log::error!("{e:#}");
            std::process::exit(1);
        };
    }
}

impl Commands {
    pub fn call(self) -> Result<()> {
        match self {
            Commands::Install(args) => install(args),
            Commands::LockBootLoader(args) => {
                let result = pcrlock::lock_boot_loader(pcrlock::LockBootLoaderArgs {
                    systemd: args.systemd,
                    esp: args.esp,
                    pcrlock: args.pcrlock,
                })?;
                println!("{}", result.pe_hash);
                Ok(())
            }
            Commands::LockThinStub(args) => {
                let result = pcrlock::lock_thin_stub(pcrlock::LockThinStubArgs {
                    systemd: args.systemd,
                    esp: args.esp,
                    pcrlock: args.pcrlock,
                    stub: args.stub,
                })?;
                println!("{}", result.pe_hash);
                Ok(())
            }
            Commands::LockSysexts(args) => {
                let result = pcrlock::lock_sysexts(pcrlock::LockSysextsArgs {
                    systemd: args.systemd,
                    esp: args.esp,
                    pcrlock: args.pcrlock,
                })?;
                if let Some(result) = result {
                    println!("{}", result.pe_hash);
                }
                Ok(())
            }
            Commands::GcPcrlock(args) => pcrlock::gc(pcrlock::GcArgs {
                systemd: args.systemd,
                pcrlock: args.pcrlock,
                keep: args.keep,
            }),
        }
    }
}

fn install(args: InstallCommand) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;

    let public_key = &args.public_key.expect("Failed to obtain public key");
    let private_key = &args.private_key.expect("Failed to obtain private key");

    let installer_builder = install::InstallerBuilder::new(
        lanzaboote_stub,
        Architecture::from_nixos_system(&args.system)?,
        args.systemd,
        args.systemd_boot_loader_config,
        args.configuration_limit,
        args.bootcounting_initial_tries,
        args.pcrlock_directory,
        args.pcr_private_key,
        args.pcr_public_key,
        args.esp,
        args.generations,
    );

    if args.allow_unsigned
        && std::fs::exists(public_key).ok().is_none_or(|b| !b)
        && std::fs::exists(private_key).ok().is_none_or(|b| !b)
    {
        log::warn!("No keys provided. Installing unsigned artifacts.");
        let signer = EmptyKeyPair;
        installer_builder.build(signer).install()
    } else {
        let signer = LocalKeyPair::new(public_key, private_key);
        installer_builder.build(signer).install()
    }
}
