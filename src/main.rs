use flate2::read::MultiGzDecoder;
use log::info;
use std::path::PathBuf;

use ark_bls12_381::{Bls12_381, Fr as FF};
use rand::rngs::OsRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

mod commitment;
use commitment::PublicParameters;

mod dna;
use dna::{RsIdPoly, RsIdHash};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Generate parameters
    Init {
        #[arg(short = 'D', default_value_t = 22)]
        degree: usize,
        #[arg(short, long, value_name = "FILE", default_value = "pp.bin")]
        dest: PathBuf,
    },
    /// Commit to a dna
    Hash {
        #[arg(short, long, default_value = "pp.bin")]
        pp: PathBuf,

        #[arg(short, long)]
        vcf: PathBuf,
    },
    /// Prove a point
    Prove {
        #[arg(short, long)]
        vcf: PathBuf,
        #[arg(short, long, default_value = "pp.bin")]
        pp: PathBuf,

        chr: usize,
        index: usize,
    },
    Verify {
        #[arg(short, long, default_value = "pp.bin")]
        pp: PathBuf,

        hash: PathBuf,
        #[arg(short, long)]
        proof: String,
    },
}

fn setup(dest: PathBuf, degree: usize) -> Result<(), &'static str> {
    let pp = PublicParameters::<ark_bls12_381::Bls12_381>::new(&mut OsRng, degree);
    let mut file = std::fs::File::create(dest).unwrap();
    CanonicalSerialize::serialize_compressed(&pp, &mut file).map_err(|_| "Serialization error")
}

fn hash(pp_path: PathBuf, vcf: PathBuf) -> Result<(), &'static str> {
    info!("start");

    let mut pp_file = std::fs::File::open(pp_path).map_err(|_| "Error opening pp file")?;
    let pp = PublicParameters::<Bls12_381>::deserialize_compressed_unchecked(&mut pp_file)
        .map_err(|_| "Deserialization error")?;
    info!("Loaded pp");

    let vcf_path = std::fs::File::open(vcf).map_err(|_| "Error opening vcf file")?;
    let vcf = RsIdPoly::<FF>::from_file(vcf_path);
    info!("Loaded vcf");

    let mut output = Vec::new();
    let hash = RsIdHash::new(&pp, &vcf);
    hash.serialize_compressed(&mut output)
        .map_err(|_| "Serialization error")?;
    println!("{}", hex::encode(output));

    Ok(())
}

fn prove(
    pp_path: PathBuf,
    vcf_path: PathBuf,
    chr: usize,
    index: usize,
) -> Result<(), &'static str> {
    let mut pp_file = std::fs::File::open(pp_path).map_err(|_| "Error opening pp file")?;
    let pp = PublicParameters::<Bls12_381>::deserialize_compressed(&mut pp_file)
        .map_err(|_| "Deserialization error")?;

    let vcf_file = std::fs::File::open(&vcf_path).map_err(|_| "Error opening vcf file")?;

    let vcf = if vcf_path.ends_with("gz") {
        RsIdPoly::<FF>::from_file(MultiGzDecoder::new(vcf_file))
    } else {
        RsIdPoly::<FF>::from_file(vcf_file)
    };

    let proof = RsIdHash::<Bls12_381>::prove(&pp, &vcf, index).map(|_| ());
    Ok(())
}

fn verify(pp: PathBuf, hash: PathBuf, proof: String) -> Result<(), &'static str> {
    Ok(())
}

fn main() -> Result<(), &'static str> {
    env_logger::init();

    let cli = Cli::parse();
    match cli {
        Cli::Init { dest, degree } => setup(dest, degree),
        Cli::Hash { vcf, pp } => hash(pp, vcf),
        Cli::Prove {
            vcf,
            pp,
            chr,
            index,
        } => prove(pp, vcf, chr, index),
        Cli::Verify { hash, proof, pp } => verify(pp, hash, proof),
    }
}
