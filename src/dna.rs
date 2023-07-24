use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read};
use crate::commitment::{Commitment, PointProof, PublicParameters};
use std::io::{BufReader, BufRead};
use std::borrow::Borrow;


fn base_to_int(base: &[u8]) -> u8 {
    match base {
        b"A" => 1,
        b"C" => 2,
        b"G" => 2,
        b"T" => 1,
        _ => 0,
    }
}

fn chromosome_to_int(chr: &[u8]) -> usize {
    str::parse(std::str::from_utf8(chr).unwrap()).unwrap()
}


#[derive(PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DnaHash<E: Pairing>([Commitment<E>; 23]);

#[derive(PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RsIdHash<E: Pairing>(Commitment<E>);

pub struct DnaPoly<F: From<u8>>([(Vec<usize>, Vec<F>); 23]);
pub struct RsIdPoly<F: From<u8>>((Vec<usize>, Vec<F>));

impl<F: From<u8>> DnaPoly<F> {
    pub fn from_file(vcf: impl Read) -> Self {
        let reader = BufReader::new(vcf);

        // read one record
        let mut records: [(Vec<usize>, Vec<F>); 23] = Default::default();

        for line in reader.lines() {
            let line = line.unwrap();
            if line.starts_with("##") {
                continue;
            }

            let cells = line.split_whitespace().collect::<Vec<_>>();

            let chromosome = chromosome_to_int(cells[0].as_bytes());
            let position = cells[1].parse::<usize>().unwrap();
            let alternative = base_to_int(cells[4].as_bytes());

            records[chromosome].0.push(position / 1 << 20);
            records[chromosome].1.push(alternative.into())
        }

        Self(records)
    }
}


impl<E: Pairing> DnaHash<E> {
    pub fn new(pp: &PublicParameters<E>, vcf: &DnaPoly<E::ScalarField>) -> Self {
        let mut commitments = [Commitment::default(); 23];
        for i in 0..23 {
            commitments[i] = pp.commit_sparse(&vcf.0[i]);
        }
        Self(commitments)
    }

    pub fn prove(
        pp: &PublicParameters<E>,
        vcf: &DnaPoly<E::ScalarField>,
        index: (usize, usize),
    ) -> Result<PointProof<E>, ()> {
        PointProof::new_sparse(pp, &vcf.0[index.0], index.1)
    }
}

impl<E: Pairing> RsIdHash<E> {
    pub fn new(pp: &PublicParameters<E>, rsid_poly: &RsIdPoly<E::ScalarField>) -> Self {
        Self(pp.commit_sparse(&rsid_poly.0))
    }

    pub fn prove(
        pp: &PublicParameters<E>,
        rsid_poly: &RsIdPoly<E::ScalarField>,
        rsid: usize,
    ) -> Result<PointProof<E>, ()> {
        PointProof::new_sparse(pp, &rsid_poly.0, rsid)
    }
}


impl<F: From<u8>> RsIdPoly<F> {
    pub fn from_file(vcf: impl Read) -> Self {
        let reader = BufReader::new(vcf);
        let mut records: (Vec<usize>, Vec<F>) = Default::default();


        for line in reader.lines() {
            let line = line.unwrap();
            if line.starts_with("##") {
                continue;
            }

            let cells = line.split_whitespace().collect::<Vec<_>>();

            if !cells[2].starts_with("rs") {
                continue;
            }
            let rsid = cells[2][2..].parse::<usize>().unwrap();
            let alternative = base_to_int(cells[4].as_bytes());

            records.0.push(rsid / 64);
            records.1.push(alternative.into());
        }

        Self(records)
    }
}

impl<E: Pairing, B: Borrow<RsIdHash<E>>> From<B> for Commitment<E> {
    fn from(value: B) -> Self {
        value.borrow().0
    }
}