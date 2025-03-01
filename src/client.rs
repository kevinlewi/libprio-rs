// Copyright (c) 2020 Apple Inc.
// SPDX-License-Identifier: MPL-2.0

//! The Prio v2 client. Only 0 / 1 vectors are supported for now.

use crate::{
    field::FieldElement,
    polynomial::{poly_fft, PolyAuxMemory},
    prng::{Prng, PrngError},
    util::{proof_length, unpack_proof_mut},
    vdaf::suite::{Key, KeyStream, Suite, SuiteError},
};

use std::convert::TryFrom;

/// The main object that can be used to create Prio shares
///
/// Client is used to create Prio shares.
pub struct Client<F: FieldElement> {
    prng: Prng<F>,
    dimension: usize,
    points_f: Vec<F>,
    points_g: Vec<F>,
    evals_f: Vec<F>,
    evals_g: Vec<F>,
    poly_mem: PolyAuxMemory<F>,
}

/// Errors that might be emitted by the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// This error is output by `Client<F>::new()` if the length of the proof would exceed the
    /// number of roots of unity that can be generated in the field.
    #[error("input size exceeds field capacity")]
    InputSizeExceedsFieldCapacity,
    /// This error is output by `Client<F>::new()` if the length of the proof would exceed the
    /// system's addressible memory.
    #[error("input size exceeds field capacity")]
    InputSizeExceedsMemoryCapacity,
    /// PRNG error
    #[error("prng error: {0}")]
    Prng(#[from] PrngError),
    /// Suite error
    #[error("suite error: {0}")]
    Suite(#[from] SuiteError),
}

impl<F: FieldElement> Client<F> {
    /// Construct a new Prio client
    pub fn new(dimension: usize) -> Result<Self, ClientError> {
        let n = (dimension + 1).next_power_of_two();

        if let Ok(size) = F::Integer::try_from(2 * n) {
            if size > F::generator_order() {
                return Err(ClientError::InputSizeExceedsFieldCapacity);
            }
        } else {
            return Err(ClientError::InputSizeExceedsMemoryCapacity);
        }

        Ok(Client {
            prng: Prng::generate(Suite::Aes128CtrHmacSha256)?,
            dimension,
            points_f: vec![F::zero(); n],
            points_g: vec![F::zero(); n],
            evals_f: vec![F::zero(); 2 * n],
            evals_g: vec![F::zero(); 2 * n],
            poly_mem: PolyAuxMemory::new(n),
        })
    }

    /// Construct a pair of encrypted shares based on the input data.
    pub fn encode_simple(&mut self, data: &[F]) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        let copy_data = |share_data: &mut [F]| {
            share_data[..].clone_from_slice(data);
        };
        Ok(self.encode_with(copy_data)?)
    }

    /// Construct a pair of encrypted shares using a initilization function.
    ///
    /// This might be slightly more efficient on large vectors, because one can
    /// avoid copying the input data.
    pub fn encode_with<G>(&mut self, init_function: G) -> Result<(Vec<u8>, Vec<u8>), ClientError>
    where
        G: FnOnce(&mut [F]),
    {
        let mut proof = self.prove_with(init_function);

        // use prng to share the proof: share2 is the PRNG seed, and proof is mutated
        // in-place
        let share2 = Key::generate(Suite::Aes128CtrHmacSha256)?;
        let share2_prng = Prng::from_key_stream(KeyStream::from_key(&share2));
        for (s1, d) in proof.iter_mut().zip(share2_prng.into_iter()) {
            *s1 -= d;
        }
        let share1 = F::slice_into_byte_vec(&proof);

        Ok((share1, share2.as_slice().to_vec()))
    }

    pub(crate) fn prove_with<G>(&mut self, init_function: G) -> Vec<F>
    where
        G: FnOnce(&mut [F]),
    {
        let mut proof = vec![F::zero(); proof_length(self.dimension)];
        // unpack one long vector to different subparts
        let mut unpacked = unpack_proof_mut(&mut proof, self.dimension).unwrap();
        // initialize the data part
        init_function(&mut unpacked.data);
        // fill in the rest
        construct_proof(
            unpacked.data,
            self.dimension,
            &mut unpacked.f0,
            &mut unpacked.g0,
            &mut unpacked.h0,
            &mut unpacked.points_h_packed,
            self,
        );

        proof
    }
}

/// Convenience function if one does not want to reuse
/// [`Client`](struct.Client.html).
pub fn encode_simple<F: FieldElement>(data: &[F]) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    let dimension = data.len();
    let mut client_memory = Client::new(dimension)?;
    client_memory.encode_simple(data)
}

fn interpolate_and_evaluate_at_2n<F: FieldElement>(
    n: usize,
    points_in: &[F],
    evals_out: &mut [F],
    mem: &mut PolyAuxMemory<F>,
) {
    // interpolate through roots of unity
    poly_fft(
        &mut mem.coeffs,
        points_in,
        &mem.roots_n_inverted,
        n,
        true,
        &mut mem.fft_memory,
    );
    // evaluate at 2N roots of unity
    poly_fft(
        evals_out,
        &mem.coeffs,
        &mem.roots_2n,
        2 * n,
        false,
        &mut mem.fft_memory,
    );
}

/// Proof construction
///
/// Based on Theorem 2.3.3 from Henry Corrigan-Gibbs' dissertation
/// This constructs the output \pi by doing the necessesary calculations
fn construct_proof<F: FieldElement>(
    data: &[F],
    dimension: usize,
    f0: &mut F,
    g0: &mut F,
    h0: &mut F,
    points_h_packed: &mut [F],
    mem: &mut Client<F>,
) {
    let n = (dimension + 1).next_power_of_two();

    // set zero terms to random
    *f0 = mem.prng.get();
    *g0 = mem.prng.get();
    mem.points_f[0] = *f0;
    mem.points_g[0] = *g0;

    // set zero term for the proof polynomial
    *h0 = *f0 * *g0;

    // set f_i = data_(i - 1)
    // set g_i = f_i - 1
    #[allow(clippy::needless_range_loop)]
    for i in 0..dimension {
        mem.points_f[i + 1] = data[i];
        mem.points_g[i + 1] = data[i] - F::one();
    }

    // interpolate and evaluate at roots of unity
    interpolate_and_evaluate_at_2n(n, &mem.points_f, &mut mem.evals_f, &mut mem.poly_mem);
    interpolate_and_evaluate_at_2n(n, &mem.points_g, &mut mem.evals_g, &mut mem.poly_mem);

    // calculate the proof polynomial as evals_f(r) * evals_g(r)
    // only add non-zero points
    let mut j: usize = 0;
    let mut i: usize = 1;
    while i < 2 * n {
        points_h_packed[j] = mem.evals_f[i] * mem.evals_g[i];
        j += 1;
        i += 2;
    }
}

#[test]
fn test_encode() {
    use crate::field::Field32;

    let data_u32 = [0u32, 1, 0, 1, 1, 0, 0, 0, 1];
    let data = data_u32
        .iter()
        .map(|x| Field32::from(*x))
        .collect::<Vec<Field32>>();
    let encoded_shares = encode_simple(&data);
    assert!(encoded_shares.is_ok());
}
