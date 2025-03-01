// SPDX-License-Identifier: MPL-2.0

//! A collection of gadgets.

use crate::fft::{discrete_fourier_transform, discrete_fourier_transform_inv_finish};
use crate::field::FieldElement;
use crate::pcp::{Gadget, PcpError};
use crate::polynomial::{poly_deg, poly_eval, poly_mul};

#[cfg(feature = "multithreaded")]
use rayon::prelude::*;

use std::any::Any;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::marker::PhantomData;

/// For input polynomials larger than or equal to this threshold, gadgets will use FFT for
/// polynomial multiplication. Otherwise, the gadget uses direct multiplication.
const FFT_THRESHOLD: usize = 60;

/// An arity-2 gadget that multiples its inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mul<F: FieldElement> {
    /// Size of buffer for FFT operations.
    n: usize,
    /// Inverse of `n` in `F`.
    n_inv: F,
    /// The number of times this gadget will be called.
    num_calls: usize,
}

impl<F: FieldElement> Mul<F> {
    /// Return a new multiplier gadget. `num_calls` is the number of times this gadget will be
    /// called by the validity circuit.
    pub fn new(num_calls: usize) -> Self {
        // Compute the amount of memory that will be needed for the output of `call_poly`. The
        // degree of this gadget is `2`, so this is `2 * (1 + num_calls).next_power_of_two()`.
        // (We round up to the next power of two in order to make room for FFT.)
        let n = (2 * (1 + num_calls).next_power_of_two()).next_power_of_two();
        let n_inv = F::from(F::Integer::try_from(n).unwrap()).inv();
        Self {
            n,
            n_inv,
            num_calls,
        }
    }

    // Multiply input polynomials directly.
    pub(crate) fn call_poly_direct(
        &mut self,
        outp: &mut [F],
        inp: &[Vec<F>],
    ) -> Result<(), PcpError> {
        let v = poly_mul(&inp[0], &inp[1]);
        outp[..v.len()].clone_from_slice(&v);
        Ok(())
    }

    // Multiply input polynomials using FFT.
    pub(crate) fn call_poly_fft(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        let n = self.n;
        let mut buf = vec![F::zero(); n];

        discrete_fourier_transform(&mut buf, &inp[0], n)?;
        discrete_fourier_transform(outp, &inp[1], n)?;

        for i in 0..n {
            buf[i] *= outp[i];
        }

        discrete_fourier_transform(outp, &buf, n)?;
        discrete_fourier_transform_inv_finish(outp, n, self.n_inv);
        Ok(())
    }
}

impl<F: FieldElement> Gadget<F> for Mul<F> {
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
        gadget_call_check(self, inp.len())?;
        Ok(inp[0] * inp[1])
    }

    fn call_poly(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        gadget_call_poly_check(self, outp, inp)?;
        if inp[0].len() >= FFT_THRESHOLD {
            self.call_poly_fft(outp, inp)
        } else {
            self.call_poly_direct(outp, inp)
        }
    }

    fn arity(&self) -> usize {
        2
    }

    fn degree(&self) -> usize {
        2
    }

    fn calls(&self) -> usize {
        self.num_calls
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// An arity-1 gadget that evaluates its input on some polynomial.
//
// TODO Make `poly` an array of length determined by a const generic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyEval<F: FieldElement> {
    poly: Vec<F>,
    /// Size of buffer for FFT operations.
    n: usize,
    /// Inverse of `n` in `F`.
    n_inv: F,
    /// The number of times this gadget will be called.
    num_calls: usize,
}

impl<F: FieldElement> PolyEval<F> {
    /// Returns a gadget that evaluates its input on `poly`. `num_calls` is the number of times
    /// this gadget is called by the validity circuit.
    pub fn new(poly: Vec<F>, num_calls: usize) -> Self {
        let n = (poly_deg(&poly) * (1 + num_calls).next_power_of_two()).next_power_of_two();
        let n_inv = F::from(F::Integer::try_from(n).unwrap()).inv();
        Self {
            poly,
            n,
            n_inv,
            num_calls,
        }
    }
}

impl<F: FieldElement> PolyEval<F> {
    // Multiply input polynomials directly.
    fn call_poly_direct(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        outp[0] = self.poly[0];
        let mut x = inp[0].to_vec();
        for i in 1..self.poly.len() {
            for j in 0..x.len() {
                outp[j] += self.poly[i] * x[j];
            }

            if i < self.poly.len() - 1 {
                x = poly_mul(&x, &inp[0]);
            }
        }
        Ok(())
    }

    // Multiply input polynomials using FFT.
    fn call_poly_fft(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        let n = self.n;
        let inp = &inp[0];

        let mut inp_vals = vec![F::zero(); n];
        discrete_fourier_transform(&mut inp_vals, inp, n)?;

        let mut x_vals = inp_vals.clone();
        let mut x = vec![F::zero(); n];
        x[..inp.len()].clone_from_slice(inp);

        outp[0] = self.poly[0];
        for i in 1..self.poly.len() {
            for j in 0..outp.len() {
                outp[j] += self.poly[i] * x[j];
            }

            if i < self.poly.len() - 1 {
                for j in 0..n {
                    x_vals[j] *= inp_vals[j];
                }

                discrete_fourier_transform(&mut x, &x_vals, n)?;
                discrete_fourier_transform_inv_finish(&mut x, n, self.n_inv);
            }
        }
        Ok(())
    }
}

impl<F: FieldElement> Gadget<F> for PolyEval<F> {
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
        gadget_call_check(self, inp.len())?;
        Ok(poly_eval(&self.poly, inp[0]))
    }

    fn call_poly(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        gadget_call_poly_check(self, outp, inp)?;

        for item in outp.iter_mut() {
            *item = F::zero();
        }

        if inp[0].len() >= FFT_THRESHOLD {
            self.call_poly_fft(outp, inp)
        } else {
            self.call_poly_direct(outp, inp)
        }
    }

    fn arity(&self) -> usize {
        1
    }

    fn degree(&self) -> usize {
        poly_deg(&self.poly)
    }

    fn calls(&self) -> usize {
        self.num_calls
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// An arity-2 gadget that returns `poly(in[0]) * in[1]` for some polynomial `poly`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindPolyEval<F: FieldElement> {
    poly: Vec<F>,
    /// Size of buffer for the outer FFT multiplication.
    n: usize,
    /// Inverse of `n` in `F`.
    n_inv: F,
    /// The number of times this gadget will be called.
    num_calls: usize,
}

impl<F: FieldElement> BlindPolyEval<F> {
    /// Returns a `BlindPolyEval` gadget for polynomial `poly`.
    pub fn new(poly: Vec<F>, num_calls: usize) -> Self {
        let n = ((poly_deg(&poly) + 1) * (1 + num_calls).next_power_of_two()).next_power_of_two();
        let n_inv = F::from(F::Integer::try_from(n).unwrap()).inv();
        Self {
            poly,
            n,
            n_inv,
            num_calls,
        }
    }

    fn call_poly_direct(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        let x = &inp[0];
        let y = &inp[1];

        let mut z = y.to_vec();
        for i in 0..self.poly.len() {
            for j in 0..z.len() {
                outp[j] += self.poly[i] * z[j];
            }

            if i < self.poly.len() - 1 {
                z = poly_mul(&z, x);
            }
        }
        Ok(())
    }

    fn call_poly_fft(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        let n = self.n;
        let x = &inp[0];
        let y = &inp[1];

        let mut x_vals = vec![F::zero(); n];
        discrete_fourier_transform(&mut x_vals, x, n)?;

        let mut z_vals = vec![F::zero(); n];
        discrete_fourier_transform(&mut z_vals, y, n)?;

        let mut z = vec![F::zero(); n];
        let mut z_len = y.len();
        z[..y.len()].clone_from_slice(y);

        for i in 0..self.poly.len() {
            for j in 0..z_len {
                outp[j] += self.poly[i] * z[j];
            }

            if i < self.poly.len() - 1 {
                for j in 0..n {
                    z_vals[j] *= x_vals[j];
                }

                discrete_fourier_transform(&mut z, &z_vals, n)?;
                discrete_fourier_transform_inv_finish(&mut z, n, self.n_inv);
                z_len += x.len();
            }
        }
        Ok(())
    }
}

impl<F: FieldElement> Gadget<F> for BlindPolyEval<F> {
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
        gadget_call_check(self, inp.len())?;
        Ok(inp[1] * poly_eval(&self.poly, inp[0]))
    }

    fn call_poly(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        gadget_call_poly_check(self, outp, inp)?;

        for x in outp.iter_mut() {
            *x = F::zero();
        }

        if inp[0].len() >= FFT_THRESHOLD {
            self.call_poly_fft(outp, inp)
        } else {
            self.call_poly_direct(outp, inp)
        }
    }

    fn arity(&self) -> usize {
        2
    }

    fn degree(&self) -> usize {
        poly_deg(&self.poly) + 1
    }

    fn calls(&self) -> usize {
        self.num_calls
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// Marker trait for abstracting over [`ParallelSum`] and [`ParallelSumMultithreaded`]
pub trait ParallelSumGadget<F: FieldElement, G>: Gadget<F> + Debug {
    /// Wraps `inner` into a sum gadget with `chunks` chunks
    fn new(inner: G, chunks: usize) -> Self;
}

/// A wrapper gadget that applies the inner gadget to chunks of input and returns the sum of the
/// outputs. The arity is equal to the arity of the inner gadget times the number of chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelSum<F: FieldElement, G: Gadget<F>> {
    inner: G,
    chunks: usize,
    phantom: PhantomData<F>,
}

impl<F: FieldElement, G: 'static + Gadget<F>> ParallelSumGadget<F, G> for ParallelSum<F, G> {
    fn new(inner: G, chunks: usize) -> Self {
        Self {
            inner,
            chunks,
            phantom: PhantomData,
        }
    }
}

impl<F: FieldElement, G: 'static + Gadget<F>> Gadget<F> for ParallelSum<F, G> {
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
        gadget_call_check(self, inp.len())?;
        let mut outp = F::zero();
        for chunk in inp.chunks(self.inner.arity()) {
            outp += self.inner.call(chunk)?;
        }
        Ok(outp)
    }

    fn call_poly(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        gadget_call_poly_check(self, outp, inp)?;

        for x in outp.iter_mut() {
            *x = F::zero();
        }

        let mut partial_outp = vec![F::zero(); outp.len()];

        for chunk in inp.chunks(self.inner.arity()) {
            self.inner.call_poly(&mut partial_outp, chunk)?;
            for i in 0..outp.len() {
                outp[i] += partial_outp[i]
            }
        }

        Ok(())
    }

    fn arity(&self) -> usize {
        self.chunks * self.inner.arity()
    }

    fn degree(&self) -> usize {
        self.inner.degree()
    }

    fn calls(&self) -> usize {
        self.inner.calls()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// A wrapper gadget that applies the inner gadget to chunks of input and returns the sum of the
/// outputs. The arity is equal to the arity of the inner gadget times the number of chunks. The sum
/// evaluation is multithreaded.
#[cfg(feature = "multithreaded")]
#[cfg_attr(docsrs, doc(cfg(feature = "multithreaded")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelSumMultithreaded<F: FieldElement, G: Gadget<F>> {
    serial_sum: ParallelSum<F, G>,
}

#[cfg(feature = "multithreaded")]
impl<F, G> ParallelSumGadget<F, G> for ParallelSumMultithreaded<F, G>
where
    F: FieldElement + Sync + Send,
    G: 'static + Gadget<F> + Clone + Sync,
{
    fn new(inner: G, chunks: usize) -> Self {
        Self {
            serial_sum: ParallelSum::new(inner, chunks),
        }
    }
}

#[cfg(feature = "multithreaded")]
impl<F, G> Gadget<F> for ParallelSumMultithreaded<F, G>
where
    F: FieldElement + Sync + Send,
    G: 'static + Gadget<F> + Clone + Sync,
{
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
        self.serial_sum.call(inp)
    }

    fn call_poly(&mut self, outp: &mut [F], inp: &[Vec<F>]) -> Result<(), PcpError> {
        gadget_call_poly_check(self, outp, inp)?;

        let res = inp
            .par_chunks(self.serial_sum.inner.arity())
            .map(|chunk| {
                let mut inner = self.serial_sum.inner.clone();
                let mut partial_outp = vec![F::zero(); outp.len()];
                inner.call_poly(&mut partial_outp, chunk).unwrap();
                partial_outp
            })
            .reduce(
                || vec![F::zero(); outp.len()],
                |mut x, y| {
                    for i in 0..x.len() {
                        x[i] += y[i];
                    }
                    x
                },
            );

        outp.clone_from_slice(&res[..outp.len()]);
        Ok(())
    }

    fn arity(&self) -> usize {
        self.serial_sum.arity()
    }

    fn degree(&self) -> usize {
        self.serial_sum.degree()
    }

    fn calls(&self) -> usize {
        self.serial_sum.calls()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Check that the input parameters of g.call() are well-formed.
fn gadget_call_check<F: FieldElement, G: Gadget<F>>(
    gadget: &G,
    in_len: usize,
) -> Result<(), PcpError> {
    if in_len != gadget.arity() {
        return Err(PcpError::Gadget(format!(
            "unexpected number of inputs: got {}; want {}",
            in_len,
            gadget.arity()
        )));
    }

    if in_len == 0 {
        return Err(PcpError::Gadget("can't call an arity-0 gadget".to_string()));
    }

    Ok(())
}

// Check that the input parameters of g.call_poly() are well-formed.
fn gadget_call_poly_check<F: FieldElement, G: Gadget<F>>(
    gadget: &G,
    outp: &[F],
    inp: &[Vec<F>],
) -> Result<(), PcpError>
where
    G: Gadget<F>,
{
    gadget_call_check(gadget, inp.len())?;

    for i in 1..inp.len() {
        if inp[i].len() != inp[0].len() {
            return Err(PcpError::Gadget(
                "gadget called on polynomials with different lengths".to_string(),
            ));
        }
    }

    if outp.len() < gadget.degree() * inp[0].len() {
        return Err(PcpError::Gadget(
            "slice allocated for gadget output polynomial is too small".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::field::Field96 as TestField;
    use crate::prng::Prng;
    use crate::vdaf::suite::Suite;

    #[test]
    fn test_mul() {
        // Test the gadget with input polynomials shorter than `FFT_THRESHOLD`. This exercises the
        // naive multiplication code path.
        let num_calls = FFT_THRESHOLD / 2;
        let mut g: Mul<TestField> = Mul::new(num_calls);
        gadget_test(&mut g, num_calls);

        // Test the gadget with input polynomials longer than `FFT_THRESHOLD`. This exercises
        // FFT-based polynomial multiplication.
        let num_calls = FFT_THRESHOLD;
        let mut g: Mul<TestField> = Mul::new(num_calls);
        gadget_test(&mut g, num_calls);
    }

    #[test]
    fn test_poly_eval() {
        let poly: Vec<TestField> = Prng::generate(Suite::Blake3).unwrap().take(10).collect();

        let num_calls = FFT_THRESHOLD / 2;
        let mut g: PolyEval<TestField> = PolyEval::new(poly.clone(), num_calls);
        gadget_test(&mut g, num_calls);

        let num_calls = FFT_THRESHOLD;
        let mut g: PolyEval<TestField> = PolyEval::new(poly, num_calls);
        gadget_test(&mut g, num_calls);
    }

    #[test]
    fn test_blind_poly_eval() {
        let poly: Vec<TestField> = Prng::generate(Suite::Blake3).unwrap().take(10).collect();

        let num_calls = FFT_THRESHOLD / 2;
        let mut g: BlindPolyEval<TestField> = BlindPolyEval::new(poly.clone(), num_calls);
        gadget_test(&mut g, num_calls);

        let num_calls = FFT_THRESHOLD;
        let mut g: BlindPolyEval<TestField> = BlindPolyEval::new(poly, num_calls);
        gadget_test(&mut g, num_calls);
    }

    #[test]
    fn test_parallel_sum() {
        let poly: Vec<TestField> = Prng::generate(Suite::Blake3).unwrap().take(10).collect();
        let num_calls = 10;
        let chunks = 23;

        let mut g = ParallelSum::new(BlindPolyEval::new(poly, num_calls), chunks);
        gadget_test(&mut g, num_calls);
    }

    #[test]
    #[cfg(feature = "multithreaded")]
    fn test_parallel_sum_multithreaded() {
        let poly: Vec<TestField> = Prng::generate(Suite::Blake3).unwrap().take(10).collect();
        let num_calls = 10;
        let chunks = 23;

        let mut g =
            ParallelSumMultithreaded::new(BlindPolyEval::new(poly.clone(), num_calls), chunks);
        gadget_test(&mut g, num_calls);

        // Test that the multithreaded version has the same output as the normal version.
        let mut g_serial = ParallelSum::new(BlindPolyEval::new(poly, num_calls), chunks);
        assert_eq!(g.arity(), g_serial.arity());
        assert_eq!(g.degree(), g_serial.degree());
        assert_eq!(g.calls(), g_serial.calls());

        let arity = g.arity();
        let degree = g.degree();

        // Test that both gadgets evaluate to the same value when run on scalar inputs.
        let inp: Vec<TestField> = Prng::generate(Suite::Blake3).unwrap().take(arity).collect();
        let result = g.call(&inp).unwrap();
        let result_serial = g_serial.call(&inp).unwrap();
        assert_eq!(result, result_serial);

        // Test that both gadgets evaluate to the same value when run on polynomial inputs.
        let mut poly_outp = vec![TestField::zero(); (degree * (1 + num_calls)).next_power_of_two()];
        let mut poly_outp_serial =
            vec![TestField::zero(); (degree * (1 + num_calls)).next_power_of_two()];
        let mut poly_inp = vec![vec![TestField::zero(); 1 + num_calls]; arity];
        let mut prng: Prng<TestField> = Prng::generate(Suite::Blake3).unwrap();
        for i in 0..arity {
            for j in 0..num_calls {
                poly_inp[i][j] = prng.get();
            }
        }
        g.call_poly(&mut poly_outp, &poly_inp).unwrap();
        g_serial
            .call_poly(&mut poly_outp_serial, &poly_inp)
            .unwrap();
        assert_eq!(poly_outp, poly_outp_serial);
    }

    // Test that calling g.call_poly() and evaluating the output at a given point is equivalent
    // to evaluating each of the inputs at the same point and applying g.call() on the results.
    fn gadget_test<F: FieldElement, G: Gadget<F>>(g: &mut G, num_calls: usize) {
        let mut prng: Prng<F> = Prng::generate(Suite::Blake3).unwrap();
        let mut inp = vec![F::zero(); g.arity()];
        let mut poly_outp = vec![F::zero(); (g.degree() * (1 + num_calls)).next_power_of_two()];
        let mut poly_inp = vec![vec![F::zero(); 1 + num_calls]; g.arity()];

        let r = prng.get();
        for i in 0..g.arity() {
            for j in 0..num_calls {
                poly_inp[i][j] = prng.get();
            }
            inp[i] = poly_eval(&poly_inp[i], r);
        }

        g.call_poly(&mut poly_outp, &poly_inp).unwrap();
        let got = poly_eval(&poly_outp, r);
        let want = g.call(&inp).unwrap();
        assert_eq!(got, want);

        // Repeat the call to make sure that the gadget's memory is reset properly between calls.
        g.call_poly(&mut poly_outp, &poly_inp).unwrap();
        let got = poly_eval(&poly_outp, r);
        assert_eq!(got, want);
    }
}
