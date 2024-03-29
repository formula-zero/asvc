
use std::io::Error; use std::ops::{AddAssign, SubAssign};
use std::u32;
// temp. r1cs::SynthesisError
use std::{ops::{Div, MulAssign, Add}, usize};

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve, msm::FixedBaseMSM};
use ark_ff::{Field, One, Zero, PrimeField, UniformRand};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};

use ark_std::rand::Rng;   // in ver3.0 of ark_ec, use ark_std instead of rand::Rng
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial, UVPolynomial};

use std::ops::{Sub, Mul, Neg};

#[derive(Debug)]
pub enum CustomError {
  UnexpectedError,
  IoError(Error),
}

impl From<Error> for CustomError {
  fn from(e: Error) -> CustomError {
    CustomError::IoError(e)
  }
}

// Module explanation
// - ark_poly::GeneralEvaluationDomain
//    : Defines a domain over which finite field (I)FFTs can be performed. 
//    Generally tries to build a radix-2 domain and falls back to a mixed-radix domain 
//    if the radix-2 multiplicative subgroup is too small.
// - ark_poly::EvaluationDomain
//    : Defines a domain over which finite field (I)FFTs can be performed. 
//    The size of the supported FFT depends on the size of the multiplicative subgroup. 
//    For efficiency, we recommend that the field has at least one large subgroup generated by a root of unity.
// - ark_ec::msm::FixedBaseMSM
//    : MSM - Multi Scalar Multiplication
#[derive(Clone, Eq, PartialEq)]
pub struct UpdateKey<E: PairingEngine>{
  pub a_i: E::G1Affine,
  pub u_i: E::G1Affine,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProvingKey<E: PairingEngine> {
  pub list_g1_tau_i: Vec<E::G1Affine>,  // g^(tau^i), vector-length:n
  pub list_l_i: Vec<E::G1Affine>,        // l_i
  pub list_update_keys: Vec<UpdateKey<E>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifyingKey<E: PairingEngine> {
  pub list_g1_tau_i: Vec<E::G1Affine>,  // g^(tau^i), vector-length: |I|
  pub list_g2_tau_i: Vec<E::G2Affine>,
  pub a: E::G1Affine,              // a
}

#[derive(Clone)]
pub struct Parameters<E: PairingEngine> {
  pub proving_key: ProvingKey<E>,
  pub verifying_key: VerifyingKey<E>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Commitment<E: PairingEngine> {
  pub commit: E::G1Affine,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Proof<E: PairingEngine> {
  pub w: E::G1Affine,
}

fn group_gen<E: PairingEngine> (domain: &GeneralEvaluationDomain<E::Fr>) -> E::Fr {
  match domain {
    GeneralEvaluationDomain::Radix2(radix) => radix.group_gen,
    GeneralEvaluationDomain::MixedRadix(mixed ) => mixed.group_gen,
  }
}

pub fn key_gen<E: PairingEngine, R: Rng> (n: usize, rng: &mut R) -> Result<Parameters<E>, CustomError> {
  // rand from ark_ff::{UniformRand}
    // type Fr: PrimeField + SquareRootField - This is the scalar field of the G1/G2 groups.
  let tau = E::Fr::rand(rng);
  let g1 = E::G1Projective::rand(rng);
  let g2 = E::G2Projective::rand(rng);

  // Evaluation Domain - Subgroup!! <Not Fully Understood..>
  let domain: GeneralEvaluationDomain<E::Fr> = 
    EvaluationDomain::<E::Fr>::new(n).unwrap();//.ok_or(Error(0))?;
  let max_degree = domain.size();

  let scalar_bit = E::Fr::size_in_bits(); // size_in_bits from ark_ff::PrimeField
  let g1_window = FixedBaseMSM::get_mul_window_size(max_degree+1);
  let g1_table = FixedBaseMSM::get_window_table::<E::G1Projective>(scalar_bit, g1_window, g1);

  let g2_window = FixedBaseMSM::get_mul_window_size(max_degree+1);
  let g2_table = FixedBaseMSM::get_window_table::<E::G2Projective>(scalar_bit, g2_window, g2);

  let mut curs = vec![E::Fr::one()];  // one from ark_ff::One
  let mut cur = tau;

  for _ in 0..max_degree {
    curs.push(cur);
    cur.mul_assign(&tau); // num * G
  }

  // n-SDH public parameters : g, g^τ , g^(τ^2), ... g^(τ^n)

  let mut list_g1_tau_i = 
    FixedBaseMSM::multi_scalar_mul(scalar_bit, g1_window, &g1_table, &curs);
  // batch_normalization_into_affine from ark_ec::ProjectiveCurve trait
    // Normalizes a slice of projective elements and outputs a vector containing the affine equivalents.
  let list_g1_tau_i = E::G1Projective::batch_normalization_into_affine(&mut list_g1_tau_i);

  let mut list_g2_tau_i =
    FixedBaseMSM::multi_scalar_mul(scalar_bit, g2_window, &g2_table, &curs);
  let list_g2_tau_i = E::G2Projective::batch_normalization_into_affine(&mut list_g2_tau_i);
  
  // a = g^A(τ) when A(τ) = τ^n - 1 .. (why sub g1, not 1 ??)
  let a = list_g1_tau_i[max_degree].into_projective().sub(&g1); // sub from core::ops::{Sub} trait

  let mut update_keys : Vec<UpdateKey<E>> = Vec::new();
  let mut l_of_g1 : Vec<E::G1Projective> = Vec::new();

  for i in 0..max_degree {
    // 1/(τ-ω^i)
    let tau_omega_i_divisor =
        E::Fr::one().div(&tau.sub(&group_gen::<E>(&domain).pow(&[i as u64])));
    /*
    let omega = group_gen::<E>(&domain);
    let omega_i = omega.pow(&[i as u64]);
    let tau_omega_i = tau.sub(&omega_i);
    let tau_omega_i_divisor = E::Fr::one().div(&tau_omega_i);
    */

    // ai = g_1^(A(τ)/(τ-ω^i))  // <E as PairingEngine>::G1Projective
    let a_i = a.mul(tau_omega_i_divisor.into_repr());   
    // <- tau_omega_i_divisor.into occurs an compile error.

    // 1/nω^(n-i) = ω^i/n
    let a_aside_omega_i_divisor = group_gen::<E>(&domain)
      .pow(&[i as u64]) // limbs - list of integers
      .div(&E::Fr::from_repr((max_degree as u64).into()).unwrap());
    // from_repr : Returns a prime field element from its underlying representation.

    // li = g_1^L_i(x) = g_1^(A(τ)/((x-ω^i)*A'(ω^i))) = ai^(1/A'(ω^i))
    let l_i = a_i.mul(a_aside_omega_i_divisor.into_repr());  // scalar multiplication
    // <- a_aside_omega_i_divisor.into occurs an compile error

    // ui = (li-1)/(x-ω^i)
    let mut u_i = l_i.sub(&g1);
    u_i = u_i.mul(tau_omega_i_divisor.into_repr());  // compile error with into

    // batch_normalization_into_affine?
    let upk = UpdateKey {
      a_i: a_i.into_affine(),
      u_i: u_i.into_affine(),
    };

    update_keys.push(upk);
    l_of_g1.push(l_i);
  }
  let l_of_g1 = E::G1Projective::batch_normalization_into_affine(&mut l_of_g1);

  let params = Parameters::<E> {
    proving_key: ProvingKey::<E> {
      list_g1_tau_i: list_g1_tau_i.clone(),
      list_l_i: l_of_g1,
      list_update_keys: update_keys,
    },
    verifying_key: VerifyingKey::<E> {
      list_g1_tau_i: list_g1_tau_i,
      list_g2_tau_i: list_g2_tau_i,
      a: a.into_affine(),
    },
  };
  Ok(params)
  
}

// TT l_i^(v_i)
pub fn commit<E: PairingEngine>(
  prk_params: &ProvingKey<E>,
  values: Vec<E::Fr>,
) -> Result<Commitment<E>, Error> {

  let num_coefficient = values.len();
  let num_powers = prk_params.list_l_i.len();

  assert!(num_coefficient >= 1);
  assert!(num_coefficient <= num_powers);

  let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
    values.iter().map(|v| v.into_repr()).collect();

  let commit = VariableBaseMSM::multi_scalar_mul(&prk_params.list_l_i, &scalars);

  let c = Commitment::<E> {
    commit: commit.into_affine(),
  };
  
  Ok(c)
}

pub fn prove_pos<E: PairingEngine>(
  prk_params: &ProvingKey<E>,
  values: Vec<E::Fr>,
  points: Vec<u32>,
) -> Result<Proof<E>, CustomError> {
  let mut values = values.clone();
  let domain: GeneralEvaluationDomain<E::Fr> =
    EvaluationDomain::<E::Fr>::new(prk_params.list_g1_tau_i.len()-1)
      .ok_or(CustomError::UnexpectedError)?;
  domain.ifft_in_place(&mut values);

  // compile error without use 'UVPolynomial' - Univariate
  // from_coefficients_vec : Constructs a new polynomial from a list of coefficients.
  // phi(x)
  let polynomial = DensePolynomial::from_coefficients_vec(values);

  // ∏(x-ω^i)
  let mut divisor_polynomial = 
    DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
  for point in points.iter() {
    let tpoly = DensePolynomial::from_coefficients_vec(vec![
      group_gen::<E>(&domain).pow(&[*point as u64]).neg(),  // compile error without core::ops::Neg
      E::Fr::one(),
    ]); 
    divisor_polynomial = divisor_polynomial.mul(&tpoly);  // compile eror without core::ops::Mul
  };

  // Φ(x) / A_I(x) = q(x) ... r(x)  (quotient / remainder)
  let dense_or_sparse_poly: DenseOrSparsePolynomial<'_, E::Fr> = polynomial.into();
  let dense_or_sparse_divisor : DenseOrSparsePolynomial<'_, E::Fr> = divisor_polynomial.into();
  // Divide self by another (sparse or dense) polynomial, and returns the quotient and remainder.
  let (witness_polynomial, _) = dense_or_sparse_poly
    .divide_with_q_and_r(&dense_or_sparse_divisor)  
    .unwrap();
  
  // π = g_1^q(τ)
  // ??? where tau came from and how to apply ??? <-- Already calucated with list_g1_tau_i
  let scalars: Vec<<E::Fr as PrimeField>::BigInt> = 
    witness_polynomial.iter().map(|v| v.into_repr()).collect();
  let witness = VariableBaseMSM::multi_scalar_mul(&prk_params.list_g1_tau_i, &scalars);
  
  let proof = Proof::<E> {
    w: witness.into_affine(),
  };

  Ok(proof)
}

// VC.VerifyPos(vrk, c, vI , I, πI )
pub fn verify_pos<E: PairingEngine> (
  vrk_params: &VerifyingKey<E>,
  commit: &Commitment<E>,
  point_values: Vec<E::Fr>,
  points: Vec<u32>,
  proof: &Proof<E>,
  omega: E::Fr,         // ?? domain??
) -> Result<bool, CustomError> {

  // A_I(x) = ∏(x - ω^i)
  let mut a_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
  for point in points.iter() {
    let tpoly = DensePolynomial::from_coefficients_vec(vec![
      omega.pow(&[*point as u64]).neg(),
      E::Fr::one(), // x - first 
    ]);
    a_polynomial = a_polynomial.mul(&tpoly);
  };

  // r(x) = ∑（l_i * v_i） = ∑（A_I(x) * v_i）/(A_I'(ω^i)(x - ω_i))
  let mut r_polynomial = DensePolynomial::from_coefficients_vec(vec![E::Fr::zero()]);
  for (point, value) in points.iter().zip(point_values.iter()) {
    // x - ω_i
    let tpoly = DensePolynomial::from_coefficients_vec(vec![
      omega.pow(&[*point as u64]).neg(),
      E::Fr::one(),
    ]);
    // A_I(x)/(x - ω_i)
    let mut l_polynomial = a_polynomial.div(&tpoly);
    // A_I'(ω^i)
    let b_aside = l_polynomial.evaluate(&omega.pow(&[*point as u64]));

    // v_i/A_I'(ω^i)
    let bpoly = DensePolynomial::from_coefficients_vec(vec![value.div(&b_aside)]);

    // (A_I(x) /(x - ω_i)) * (v_i/(A_I'(ω^i))
    l_polynomial = l_polynomial.mul(&bpoly);
    
    r_polynomial = r_polynomial.add(l_polynomial);  // compile error without core::ops::Add
  };

  // Returns the underlying representation of the prime field element.
  // fn into_repr(&self) -> Self::BigInt
  let scalars: Vec<<E::Fr as PrimeField>::BigInt> = 
    r_polynomial.iter().map(|v| v.into_repr()).collect(); 
  
  //g^RI (τ)
  let r_value = VariableBaseMSM::multi_scalar_mul(&vrk_params.list_g1_tau_i, &scalars);

  // e(c/g^R_I(τ), g) = e(π_I , g^A_I(τ)).
  let mut inner = commit.commit.into_projective();
  inner.sub_assign(&r_value); // x -= 1 // G1Projective - why sub , not div?? 
  let lhs = E::pairing(inner, vrk_params.list_g2_tau_i[0]);

  // A_I(τ) = ∏(τ - ω^i)  --> // A_I(x) = ∏(x - ω^i)
  let a_scalars: Vec<<E::Fr as PrimeField>::BigInt> =
    a_polynomial.iter().map(|v| v.into_repr()).collect();
  let a_value = VariableBaseMSM::multi_scalar_mul(&vrk_params.list_g2_tau_i, &a_scalars);

  let rhs = E::pairing(proof.w, a_value);

  Ok(lhs == rhs)

}

//(vrk, i, upk_i)
pub fn verify_upk<E: PairingEngine> (
  vrk_params: &VerifyingKey<E>,
  point: u32,
  upk: &UpdateKey<E>,
  omega: E::Fr,
) -> Result<bool, CustomError> {
  // e(a_i, g^i/g^(w^i)) = e(a,g)
    // to prove that w^i is a root of X^n -1
  let omega_i = omega.pow(&[point as u64]);

  // g^i/g^(w^i)
  let inner = vrk_params.list_g2_tau_i[1].into_projective().sub(
    &vrk_params.list_g2_tau_i[0].into_projective().mul(omega_i.into_repr()), // compile error with into
  );
  let lhs = E::pairing(upk.a_i, inner);

  let rhs = E::pairing(vrk_params.a,
                                  vrk_params.list_g2_tau_i[0]);
  let rs1 = lhs == rhs;

  //e(l_i/g1, g) = e(u_i  , g^τ /g(ω_i))
  //a_i^(1/A'(ω^i))
  let n = vrk_params.list_g1_tau_i.len() - 1;
  let a_aside_omega_i_divisor = omega.pow(&[point as u64])
                          .div(&E::Fr::from_repr((n as u64).into()).unwrap());  // ??????
  let l_value = upk.a_i.mul(a_aside_omega_i_divisor);

  let inner2 = l_value.sub(&vrk_params.list_g1_tau_i[0].into_projective());
  let lhs = E::pairing(inner2, vrk_params.list_g2_tau_i[0]);

  let rhs = E::pairing(upk.u_i, inner);
  let rs2 = lhs == rhs;

  Ok(rs1 && rs2)
}

//(c, δ, j, upk_j)
// c' = c·(l_j )^δ, where l_j = a_j^(1/A'(ω^j))
pub fn update_commit<E: PairingEngine> (
  commit: &Commitment<E>,
  delta: E::Fr,
  point: u32,
  upk: &UpdateKey<E>,
  omega: E::Fr,
  n: usize, // ??
) -> Result<Commitment<E>, CustomError> {

  let a_aside_omega_i_divisor = omega.pow(&[point as u64])
      .div(&E::Fr::from_repr((n as u64).into()).unwrap());  //??
  let l_value = upk.a_i.mul(a_aside_omega_i_divisor);

  let new_commit = commit.commit.into_projective().add(&(l_value.mul(delta.into_repr()))); // compile error witn into

  let c = Commitment::<E>{
    commit: new_commit.into_affine(),
  };

  Ok(c)

}


pub fn update_proof<E: PairingEngine> (
  proof: &Proof<E>,
  delta: E::Fr,
  point_i: u32,
  point_j: u32,
  upk_i: &UpdateKey<E>,
  upk_j: &UpdateKey<E>,
  omega: E::Fr,
  n: usize,
) -> Result<Proof<E>, Error> {
  let mut new_witness = proof.w.into_projective();

  if point_i == point_j {
    new_witness.add_assign(&upk_i.u_i.mul(delta));
  } else { // i =/= j
    //c_1 = 1/(ω_j - ω_i), c_2 = 1/(ω_i - ω_j)
    let omega_i = omega.pow(&[point_i as u64]);
    let omega_j = omega.pow(&[point_j as u64]);

    let c_1 = E::Fr::one().div(&(omega_j.sub(&omega_i)));
    let c_2 = E::Fr::one().div(&(omega_i.sub(&omega_j)));

    // w_ij = a_j^c_1 * a_i^c2
    let w_ij = upk_j.a_i.mul(c_1).add(&upk_i.a_i.mul(c_2));

    // u_ij = w_ij ^ (1/A'(w^j))
    let a_aside_omega_i_divisor = omega
      .pow(&[point_j as u64])
      .div(&E::Fr::from_repr((n as u64).into()).unwrap());  // why n ???
    let u_ij = w_ij.mul(a_aside_omega_i_divisor.into_repr());  // compile error with into
    new_witness.add_assign(&u_ij.mul(delta.into_repr()));  // compile error with into
    
  };

  let proof = Proof::<E> {
    w: new_witness.into_affine(),
  };

  Ok(proof)

}

//VC.AggregateProofs(I,(π_i)i∈I )
pub fn aggregate_proofs<E: PairingEngine> (
  points: Vec<u32>,
  proofs: Vec<Proof<E>>,
  omega: E::Fr,
) -> Result<Proof<E>, CustomError> {

  // A(x) = ∏(x-ω^i)
  let mut a_polynomal = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
  for point in points.iter() {
    let tpoly = DensePolynomial::from_coefficients_vec(vec![
      omega.pow(&[*point as u64]).neg(),
      E::Fr::one(),
    ]);
    a_polynomal = a_polynomal.mul(&tpoly);
  };

  let mut aggregate_witness = E::G1Projective::zero();
  for (point, proof) in points.iter().zip(proofs.iter()) {
    let divisor_polynomial = DensePolynomial::from_coefficients_vec(vec![
      omega.pow(&[*point as u64]).neg(),
      E::Fr::one(),
    ]);
    let a_aside_polynomial = a_polynomal.div(&divisor_polynomial);

    let c = E::Fr::one().div(&a_aside_polynomial.evaluate(&omega.pow(&[*point as u64])));
    aggregate_witness.add_assign(&proof.w.mul(c));
  };

  let proof = Proof::<E> {
    w: aggregate_witness.into_affine(),
  };

  Ok(proof)

}