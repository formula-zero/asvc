use ark_ec::group;
// GeneralEvaluationDomain
  // Defines a domain over which finite field (I)FFTs can be performed. 
  // Generally tries to build a radix-2 domain and falls back to a mixed-radix domain 
  // if the radix-2 multiplicative subgroup is too small.
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_std::test_rng;
use ark_ff::UniformRand;
use asvc::{aggregate_proofs, verify_pos};
use std::time::Instant;

use core::ops::Add;

extern crate asvc;

fn group_gen(domain: &GeneralEvaluationDomain<Fr>) -> Fr {
  match domain {
    GeneralEvaluationDomain::Radix2(radix) => radix.group_gen,
    GeneralEvaluationDomain::MixedRadix(mixed) => mixed.group_gen,
  }
}
#[test]
fn test_aggregatable_svc(){
  let rng = &mut test_rng();
  let size: usize = 8;
  let params = asvc::key_gen::<E,_>(size, rng).unwrap();

  let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::<Fr>::new(size).unwrap();

  let mut values = Vec::<Fr>::new();
  values.push(Fr::rand(rng)); // ark_ff::UniformRand
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng));
  values.push(Fr::rand(rng)); // 8

  let c = asvc::commit(&params.proving_key, values.clone()).unwrap();

  let start = Instant::now();
  let mut points = Vec::<u32>::new();
  let mut point_values = Vec::<Fr>::new();

  // 0, 1, 5
  points.push(0);
  point_values.push(values[0]);
  points.push(1);
  point_values.push(values[1]);
  points.push(5);
  point_values.push(values[5]);

  let proof = asvc::prove_pos(&params.proving_key, 
                    values.clone(), points.clone())
                    .unwrap();  // error if 
  let rs = asvc::verify_pos(&params.verifying_key, 
          &c, point_values, points, &proof, group_gen(&domain))
          .unwrap();

  // Returns the amount of time elapsed since this instant was created.
  let total_setup = start.elapsed();
  println!("ASVC Verify Position Time: {:?}", total_setup);
  assert!(rs);

  let start = Instant::now();
  let index: u32 = 2;
  let rs = asvc::verify_upk(&params.verifying_key, 
                  index, &params.proving_key.list_update_keys[index as usize], 
                  group_gen(&domain))
                  .unwrap();
  let total_setup = start.elapsed();
  println!("ASVC Verify Update Key Time: {:?}", total_setup);
  assert!(rs);

  let start = Instant::now();
  let index: u32 = 3;
  let delta = Fr::rand(rng);

  let points_i = vec![index];
  let point_values_i = vec![values[index as usize].add(&delta)];  // core::ops::Add;
  let uc = asvc::update_commit(&c, 
                delta, index, &params.proving_key.list_update_keys[index as usize], 
                group_gen(&domain), size)
                .unwrap();
  let proof = asvc::prove_pos(&params.proving_key, 
                values.clone(), points_i.clone())
                .unwrap();
  
  let proof = asvc::update_proof(
                &proof, delta, index, index, 
                &params.proving_key.list_update_keys[index as usize], 
                &params.proving_key.list_update_keys[index as usize], 
                group_gen(&domain), size)
                .unwrap();
  let rs = asvc::verify_pos(
    &params.verifying_key, &uc, point_values_i, points_i, 
    &proof, group_gen(&domain))
    .unwrap();
  
  let total_setup = start.elapsed();
  println!("ASVC Verify Update commit and proof Time : {:?}", total_setup);
  assert!(rs);

  // not fully understood yet!!!
  let start = Instant::now();
  let index_i: u32 = 4;
  let points_i = vec![index_i];
  let point_values_i = vec![values[index_i as usize]];
  let proof = asvc::prove_pos(&params.proving_key, 
                    values.clone(), points_i.clone())
                    .unwrap();
  let proof = asvc::update_proof(
    &proof, delta, 
    index_i, index, 
    &params.proving_key.list_update_keys[index_i as usize], 
    &params.proving_key.list_update_keys[index as usize],
    group_gen(&domain), size)
    .unwrap();
  let rs = asvc::verify_pos(
    &params.verifying_key, &uc, point_values_i, points_i, 
    &proof, group_gen(&domain))
    .unwrap();

  let total_setup = start.elapsed();
  println!("ASVC Verify Update Proof, Different Index Time: {:?}", total_setup);
  assert!(rs);
  

  //..
  let start = Instant::now();
  let mut points = Vec::<u32>::new();
  let mut point_values = Vec::new();
  let mut point_proofs = Vec::new();

  let point = vec![1];
  points.push(1);
  point_values.push(values[1]);
  let proof = asvc::prove_pos(&params.proving_key, 
                        values.clone(), point.clone())
                        .unwrap();
  point_proofs.push(proof);

  let point = vec![5];
  points.push(5);
  point_values.push(values[5]);
  let proof = asvc::prove_pos(&params.proving_key, 
                        values.clone(), point.clone())
                        .unwrap();
  point_proofs.push(proof);

  let proofs = aggregate_proofs(
                    points.clone(), 
                    point_proofs, group_gen(&domain))
                    .unwrap();

  let rs = verify_pos( &params.verifying_key,
                  &c, point_values.clone(), points.clone(), 
                  &proofs, group_gen(&domain))
                  .unwrap();

  let total_setup = start.elapsed();
  println!("Asvc verify aggregate proofs Time: {:?}", total_setup);
  assert!(rs);

}