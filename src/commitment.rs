use std::ops::Deref;

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::{CryptoRng, RngCore};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use rayon::slice::ParallelSliceMut;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameters<E: Pairing> {
    powers_of_g: Vec<E::G1Affine>,
    powers_of_g2: Vec<E::G2Affine>,
}

impl<E: Pairing> PublicParameters<E> {
    pub fn new(csrng: &mut (impl RngCore + CryptoRng), log_degree: usize) -> Self {
        let chunk_log_size = 12usize;
        let chunk_size = 1 << chunk_log_size;
        let mut powers_of_g = vec![Default::default(); 1 << log_degree];
        let mut powers_of_g2 = Vec::with_capacity(64);
        let tau = E::ScalarField::rand(csrng);

        powers_of_g[0] = E::G1Affine::generator();
        for i in 1..1 << usize::min(log_degree, chunk_log_size) {
            let current_power = (powers_of_g[i - 1] * &tau).into_affine();
            powers_of_g[i] = current_power;
        }

        if log_degree > chunk_log_size {
            let bases = powers_of_g[..chunk_size].to_vec();
            let shifts = (chunk_size..1 << log_degree)
                .step_by(chunk_size)
                .map(|i| tau.pow([i as u64]))
                .collect::<Vec<_>>();
            powers_of_g[chunk_size..]
                .par_chunks_mut(chunk_size)
                .zip(shifts.par_iter())
                .for_each(|(chunk, shift)| {
                    for j in 0..chunk.len() {
                        let current_power = (bases[j] * shift).into_affine();
                        chunk[j] = current_power;
                    }
                })
        }

        powers_of_g2.push(E::G2Affine::generator());
        for _ in 1..=64 {
            let current_power = (*powers_of_g2.last().unwrap() * tau).into_affine();
            powers_of_g2.push(current_power);
        }

        powers_of_g
            .iter()
            .enumerate()
            .for_each(|(i, p)| assert!(!p.is_zero(), "{}", i));

        Self {
            powers_of_g,
            powers_of_g2,
        }
    }

    pub fn commit(&self, polynomial: &[E::ScalarField]) -> Commitment<E> {
        Commitment::new(self, polynomial)
    }

    pub fn commit_sparse(&self, polynomial: &(impl Deref<Target = [usize]>, impl Deref<Target = [E::ScalarField]>)) -> Commitment<E> {
        Commitment::new_sparse(self, polynomial)
    }

    pub fn prove_point(
        &self,
        polynomial: &[E::ScalarField],
        index: usize,
    ) -> Result<PointProof<E>, ()> {
        PointProof::new(self, polynomial, index)
    }

    pub fn prove_point_sparse(
        &self,
        polynomial: (impl Deref<Target = [usize]>, impl Deref<Target = [E::ScalarField]>),
        index: usize,
    ) -> Result<PointProof<E>, ()> {
        PointProof::new_sparse(self, &polynomial, index)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: Pairing>(E::G1Affine);

pub struct PointProof<E: Pairing>(E::G1Affine, E::G1Affine);

impl<E: Pairing> Commitment<E> {
    pub fn new(pp: &PublicParameters<E>, polynomial: &[E::ScalarField]) -> Self {
        let commitment = E::G1::msm_unchecked(&pp.powers_of_g, polynomial);
        Self(commitment.into())
    }

    pub fn new_sparse(pp: &PublicParameters<E>, polynomial: &(impl Deref<Target = [usize]>, impl Deref<Target = [E::ScalarField]>)) -> Self {
        let basis = polynomial.0
            .iter()
            .map(|i| pp.powers_of_g[*i])
            .collect::<Vec<_>>();
        let commitment = E::G1::msm_unchecked(&basis, &polynomial.1);
        Self(commitment.into())
    }
}

impl<E: Pairing> Default for Commitment<E> {
    fn default() -> Self {
        Self(E::G1Affine::zero())
    }
}

impl<E: Pairing> serde::Serialize for Commitment<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::<u8>::new();
        self.0.serialize_compressed(&mut bytes[..]).unwrap();
        serializer.serialize_bytes(&bytes[..])
    }
}

impl<E: Pairing> PointProof<E> {
    pub fn new(
        pp: &PublicParameters<E>,
        polynomial: &[E::ScalarField],
        index: usize,
    ) -> Result<Self, ()> {
        if index >= polynomial.len() {
            Err(())
        } else {
            let lhs = E::G1::msm_unchecked(&pp.powers_of_g[..index], &polynomial[..index]);
            let rhs = E::G1::msm_unchecked(&pp.powers_of_g[index + 1..], &polynomial[index + 1..]);
            Ok(Self(lhs.into(), rhs.into()))
        }
    }

    pub fn new_sparse(
        pp: &PublicParameters<E>,
        polynomial: &(impl Deref<Target=[usize]>, impl Deref<Target =[E::ScalarField]>),
        index: usize,
    ) -> Result<Self, ()> {
        if index >= polynomial.0.len() || polynomial.0.len() != polynomial.1.len() {
            Err(())
        } else {
            let mut index = 0;
            (0 .. polynomial.0.len()).for_each(|i| if polynomial.0[i] < index { index = polynomial.0[i] });

            let lhs_bases = &polynomial.0[.. index].iter().map(|i| pp.powers_of_g[*i]).collect::<Vec<_>>();
            let lhs_scalars = &polynomial.1[.. index];

            let rhs_bases = &polynomial.0[index .. ].iter().map(|i| pp.powers_of_g[*i]).collect::<Vec<_>>();
            let rhs_scalars = &polynomial.1[index ..];

            let lhs = E::G1::msm_unchecked(lhs_bases, lhs_scalars);
            let rhs = E::G1::msm_unchecked(rhs_bases, rhs_scalars);
            Ok(Self(lhs.into(), rhs.into()))
        }
    }

    pub fn verify(
        pp: &PublicParameters<E>,
        commitment: &Commitment<E>,
        index: usize,
        value: E::ScalarField,
        proof: &PointProof<E>,
    ) -> Result<(), ()> {
        let expected = *pp.powers_of_g.get(index).ok_or(())? * value + proof.0 + proof.1;
        if commitment.0 == expected.into() {
            Ok(())
        } else {
            Err(())
        }
    }
}


#[test]
fn test_crs() {
    type E = ark_bls12_381::Bls12_381;

    let pp = PublicParameters::<E>::new(&mut rand::thread_rng(), 13);
    for i in 1..pp.powers_of_g.len()-1 {
        assert_eq!(E::pairing(pp.powers_of_g[i],  pp.powers_of_g2[1]), E::pairing(pp.powers_of_g[i+1], pp.powers_of_g2[0]));
    }
}