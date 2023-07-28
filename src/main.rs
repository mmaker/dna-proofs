use ark_ec::pairing::Pairing;
use ark_ff::Field;
use flate2::read::MultiGzDecoder;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;

mod commitment;
use commitment::{PointProof, PublicParameters};

mod dna;
use dna::{RsIdHash, RsIdPoly, base_to_int};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Generate parameters
    Init {
        #[arg(short = 'D', default_value_t = 10)]
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
        #[arg(long, default_value = "rsidlist")]
        rsid: PathBuf,
    },
    /// Prove a point
    Prove {
        #[arg(short, long)]
        vcf: PathBuf,
        #[arg(short, long, default_value = "pp.bin")]
        pp: PathBuf,
        #[arg(long, default_value = "rsidlist")]
        rsid: PathBuf,
        // chr: usize,
        index: usize,
    },
    Verify {
        #[arg(short, long, default_value = "pp.bin")]
        pp: PathBuf,
        #[arg(long, default_value = "rsidlist")]
        rsid: PathBuf,

        index: usize,
        hash: String,
        proof: String,
        value: String,
    },
}

fn open_pp<E: Pairing>(pp_path: PathBuf) -> Result<PublicParameters<E>, &'static str> {
    let mut pp_file = std::fs::File::open(pp_path).map_err(|_| "Error opening pp file")?;
    PublicParameters::<E>::deserialize_compressed_unchecked(&mut pp_file)
        .map_err(|_| "Error deserializing")
}

fn open_vcf<F: Field>(vcf_path: &PathBuf, rsid_path: &PathBuf) -> Result<RsIdPoly<F>, &'static str> {
    let vcf_file = std::fs::File::open(&vcf_path).map_err(|_| "Error opening vcf file")?;
    let filter = open_rsid(&rsid_path)?;

    if vcf_path.ends_with("gz") {
        Ok(RsIdPoly::<F>::from_file(
            MultiGzDecoder::new(vcf_file),
            filter,
        ))
    } else {
        Ok(RsIdPoly::<F>::from_file(vcf_file, filter))
    }
}

fn open_rsid(rsid_path: &PathBuf) -> Result<HashMap<usize, usize>, &'static str> {
    let rsid_file = File::open(rsid_path).map_err(|_| "Error opening rsid list")?;
    Ok(BufReader::new(rsid_file)
        .lines()
        .enumerate()
        .map(|(x, y)| (y.unwrap()[2..].parse().unwrap(), x))
        .collect())
}

fn setup(dest: PathBuf, degree: usize) -> Result<(), &'static str> {
    let pp = PublicParameters::<ark_bls12_381::Bls12_381>::new(&mut OsRng, degree);
    let mut file = std::fs::File::create(dest).unwrap();
    CanonicalSerialize::serialize_compressed(&pp, &mut file).map_err(|_| "Serialization error")
}

fn hash(pp_path: PathBuf, vcf_path: PathBuf, rsid_path: PathBuf) -> Result<(), &'static str> {
    let pp = open_pp::<Bls12_381>(pp_path).map_err(|_| "Deserialization error")?;
    let vcf = open_vcf(&vcf_path, &rsid_path)?;

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
    index: usize,
    rsid_path: PathBuf,
) -> Result<(), &'static str> {
    let pp = open_pp(pp_path)?;
    let vcf = open_vcf(&vcf_path, &rsid_path)?;

    let filter = open_rsid(&rsid_path)?;
    let index = *filter.get(&index).ok_or("index not found")?;


    let proof = RsIdHash::<Bls12_381>::prove(&pp, &vcf, index).unwrap();

    let mut output = Vec::new();
    proof
        .serialize_compressed(&mut output)
        .map_err(|_| "Serialization error")?;
    println!("{}", hex::encode(&output));

    Ok(())
}

fn verify(
    pp_path: PathBuf,
    hash: String,
    proof: String,
    index: usize,
    value: usize,
    rsid_path: PathBuf,
) -> Result<(), &'static str> {
    let pp = open_pp(pp_path)?;

    let filter = open_rsid(&rsid_path)?;
    let index = *filter.get(&index).ok_or("index not found")?;

    let hash = hex::decode(hash).map_err(|_| "Error decoding hash")?;
    let hash = RsIdHash::<Bls12_381>::deserialize_compressed(&mut hash.as_slice())
        .map_err(|_| "Error deserializing hash")?;

    let proof = hex::decode(proof).map_err(|_| "Error decoding proof")?;
    let proof = PointProof::<Bls12_381>::deserialize_compressed(&mut proof.as_slice())
        .map_err(|_| "Error deserializing proof")?;

    proof
        .verify(&pp, &hash.into(), index, ark_bls12_381::Fr::from(value as i8))
        .map_err(|_| "Verification error")?;
    Ok(())
}

fn main() -> Result<(), &'static str> {
    env_logger::init();

    let cli = Cli::parse();
    match cli {
        Cli::Init { dest, degree } => setup(dest, degree),
        Cli::Hash { vcf, pp, rsid } => hash(pp, vcf, rsid),
        Cli::Prove {
            vcf,
            pp,
            index,
            rsid,
        } => prove(pp, vcf, index, rsid),
        Cli::Verify {
            hash,
            proof,
            pp,
            index,
            rsid,
            value,
        } => verify(pp, hash, proof, index, base_to_int(value.as_bytes()).into(), rsid),
    }
}
