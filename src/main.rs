//! vsss-cli — CLI wrapper for `vsss-rs`.
//!
//! Only covers this configuration :
//!   - Shamir Secret Scheme (no Feldman - Pedersen),
//!   - only for "bytes array" (`Gf256::split_bytes` / `Gf256::combine_bytes`),
//!
//! Shares files are exactly byte arrays produced by `vsss-rs` (1 byte
//! for X coordinate followed by N bytes of Y coordinates).
//!
//! Users should note parameters used to ensure proper reconstruction.
//! Also, share format is non standardized binary output, with no
//! guarantee it will remain as such for ever. User should save the
//! code used for splitting to ensure proper combination in the
//! future.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use vsss_rs::Gf256;
use rand::rngs::SysRng;
use rand::rand_core::UnwrapErr;


/// share file name
const SHARE_FILE_NAME: &str = "SECRET_SHARE";

#[derive(Parser)]
#[command(
    name = "vsss-cli",
    version,
    about = "Split or combine byte string following Shamir scheme, using vsss-rs library for bytes/GF(256)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Split SECRET into N shares, with K shares required to combine back.
    Split {
        /// File path holding the secret content (use "-" for STDIN)
        #[arg(long, short = 's')]
        secret_path: PathBuf,

        /// Threshold K : number of shares required to combine back
        #[arg(long, short = 't', value_name = "K")]
        threshold: u8,

        /// Total number of shares to produce (< 256)
        #[arg(long, short = 'n', value_name = "N")]
        shares: u8,

        /// Shares output folder
        #[arg(long, short = 'd', value_name = "DIR")]
        shares_dir: PathBuf,
    },

    /// Combine shares back to reveal the secret.
    Combine {
        /// A directory with enough shares (more than the threshold) to rebuild the secret
        #[arg(long, short = 'd', value_name = "DIR", conflicts_with = "share")]
        shares_dir: Option<PathBuf>,

        /// Repeatable switch, use it to explicitely specify share files one after the other
        #[arg(long, short = 'p', value_name = "FILE", conflicts_with = "shares_dir")]
        share: Vec<PathBuf>,

        /// File to output to combined secret to (use "-" for STDOUT)
        #[arg(long, short = 'o', value_name = "FILE")]
        output: PathBuf,
    },
}


fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("erreur: {e}");
        std::process::exit(1);
    }
}


fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Split {
            secret_path,
            threshold,
            shares,
            shares_dir,
        } => split(&secret_path, threshold, shares, &shares_dir),
        Command::Combine {
            shares_dir,
            share,
            output,
        } => combine(shares_dir, share, &output),
    }
}

// ---------------------------------------------------------------------
// split
// ---------------------------------------------------------------------

fn split(secret_path: &Path, threshold: u8, shares_count: u8, shares_dir: &Path) -> Result<(), String> {
    if threshold < 2 {
        return Err("--threshold must be >= 2".into());
    }
    if shares_count < threshold {
        return Err("--shares must be >= --threshold".into());
    }

    let secret_bytes = read_secret(secret_path)?;

    if secret_bytes.is_empty() {
        return Err(format!("{} is empty", secret_path.display()));
    }

    fs::create_dir_all(shares_dir)
        .map_err(|e| format!("unable to mkdir {}: {e}", shares_dir.display()))?;

    // SysRng est la source d'entropie du noyau,
    // UnwrapErr le rend compatible avec l'API CryptoRng attendue.
    let mut sys_rng = UnwrapErr(SysRng);

    // Coeur de la lib : découpe le secret octet par octet sur GF(256).
    // Chaque élément renvoyé est une share
    // (1 octet de X + N octets de valeurs Y).
    let shares = Gf256::split_bytes(threshold as usize, shares_count as usize, &secret_bytes, &mut sys_rng)
        .map_err(|e| format!("unable to split: {e}"))?;

    for (i, share) in shares.iter().enumerate() {
        let share_number = i + 1;
        let file_name = format!("{SHARE_FILE_NAME}.{share_number}");
        let share_path = shares_dir.join(file_name);
        write_private_file(&share_path, share)
            .map_err(|e| format!("unable to write {}: {e}", share_path.display()))?;
    }

    eprintln!(
        "{shares_count} shares written to {}  /  Min combine threshold: {threshold}",
        shares_dir.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------
// combine
// ---------------------------------------------------------------------

fn combine(shares_dir: Option<PathBuf>, explicit_shares: Vec<PathBuf>, output_path: &Path) -> Result<(), String> {
    let share_paths = if !explicit_shares.is_empty() {
        explicit_shares
    } else if let Some(dir) = shares_dir {
        collect_share_files(&dir)?
    } else {
        return Err("provide a correct --shares-dir <DIR> or at least two --share <FILE>".into());
    };

    if share_paths.len() < 2 {
        return Err("at least two shares are required for combine".into());
    }

    let shares: Vec<Vec<u8>> = share_paths
        .iter()
        .map(|p| fs::read(p).map_err(|e| format!("unable to read {}: {e}", p.display())))
        .collect::<Result<_, _>>()?;

    // Si le nombre de parts fournies est inférieur au seuil utilisé
    // lors du split, vsss-rs ne le détectera pas : il produira un
    // résultat faux. Rien dans le format des parts ne contient cette
    // information ; c'est à l'appelant de fournir au moins K parts
    // valides.
    let secret = Gf256::combine_bytes(&shares).map_err(|e| format!("unable to combine: {e}"))?;

    write_secret_output(output_path, &secret)?;

    eprintln!(
"************************************************************
* secret successfully written to {} from {} shares
************************************************************",
        output_path.display(),
        share_paths.len()
    );
    Ok(())
}

/// Liste les fichiers du dossier
fn collect_share_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(fs::read_dir(dir)
       .map_err(|e| format!("unable to read {}: {e}", dir.display()))?
       .filter_map(Result::ok)
       .map(|entry| entry.path())
       .filter(|path| path.is_file())
       .collect())
}


/// Lit le secret depuis `path`, ou depuis stdin si `path` vaut `-`.
fn read_secret(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)
            .map_err(|e| format!("unable to read stdin: {e}"))?;
        Ok(buf)
    } else {
        fs::read(path).map_err(|e| format!("Unable to read {}: {e}", path.display()))
    }
}

/// Écrit `data` dans `path`, ou sur stdout si `path` vaut `-`.
///
/// Sur stdout, on n'impose pas les permissions 0600 : c'est à
/// l'utilisateur de rediriger proprement (`> file` avec umask
/// restrictif, ou pipe vers un consommateur de confiance).
fn write_secret_output(path: &Path, data: &[u8]) -> Result<(), String> {
    if path == Path::new("-") {
        write_stdout(data)
            .map_err(|e| format!("unable to write to stdout: {e}"))
    } else {
        write_private_file(path, data)
            .map_err(|e| format!("unable to write to {}: {e}", path.display()))
    }
}


/// Wrapper sortie STDOUT
fn write_stdout(data: &[u8]) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(data)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}



/// Écrit `data` dans `path`, en créant le fichier avec des permissions
/// restreintes au propriétaire (0600) puisqu'il contient un secret ou une
/// part de secret.
fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)
}
