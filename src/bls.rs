
mod aggregate;
mod converters;
mod key_gen;
mod nodes_info;
mod random_helper;
mod sig;

use crate::bls::aggregate::*;

pub use self::key_gen::*;
pub use self::sig::*;

pub use self::nodes_info::*;
pub use self::random_helper::*;

//use blst::min_sig::*;

use blst::BLST_ERROR;
use blst::min_pk::Signature;
use blst::min_pk::PublicKey;
use blst::min_pk::AggregateSignature;
use blst::min_pk::AggregatePublicKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::RngCore;
use blst::min_pk::SecretKey;
use std::collections::HashMap;
use std::ptr;
use blst::MultiPoint;
use blst::blst_keygen;
use blst::blst_scalar;

use std::time::Instant;
use tvm_types::{fail, Result};

pub const BLS_SECRET_KEY_LEN: usize = 32;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE: usize = 48;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_SIG_MODE: usize = 96;
pub const BLS_PUBLIC_KEY_LEN: usize = BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE;
pub const BLS_KEY_MATERIAL_LEN: usize = 32;
pub const BLS_SIG_LEN_FOR_MIN_PK_MODE: usize = 96;
pub const BLS_SIG_LEN_FOR_MIN_SIG_MODE: usize = 48;
pub const BLS_SIG_LEN: usize = BLS_SIG_LEN_FOR_MIN_PK_MODE;
pub const BLS_SEED_LEN: usize = 32;

/** Basic signature scheme functions */

pub fn gen_bls_key_pair_based_on_key_material(
    ikm: &[u8; BLS_KEY_MATERIAL_LEN],
) -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair_based_on_key_material(ikm)?;
    Ok(key_pair.serialize())
}

pub fn gen_bls_key_pair() -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair()?;
    Ok(key_pair.serialize())
}

pub fn gen_public_key_based_on_secret_key(
    sk: &[u8; BLS_SECRET_KEY_LEN],
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    let pk = BlsKeyPair::deserialize_based_on_secret_key(sk)?;
    Ok(pk.pk_bytes)
}

pub fn sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &[u8]) -> Result<[u8; BLS_SIG_LEN]> {
    BlsSignature::simple_sign(sk_bytes, msg)
}

pub fn verify(
    sig_bytes: &[u8; BLS_SIG_LEN],
    msg: &[u8],
    pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN],
) -> Result<bool> {
    BlsSignature::simple_verify(sig_bytes, msg, pk_bytes)
}

pub fn validate_signature(sig_bytes: &[u8; BLS_SIG_LEN]) -> bool {
    BlsSignature::validate_signature(sig_bytes)
}

pub fn validate_public_key(pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> bool {
    BlsSignature::validate_public_key(pk_bytes)
}

/*** Functions handling raw pubkeys and sigs bytes plus extra node info) */

pub fn add_node_info_to_sig(
    sig_bytes: [u8; BLS_SIG_LEN],
    node_index: u16,
    total_num_of_nodes: u16,
) -> Result<Vec<u8>> {
    BlsSignature::add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes)
}

pub fn sign_and_add_node_info(
    sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
    msg: &[u8],
    node_index: u16,
    total_num_of_nodes: u16,
) -> Result<Vec<u8>> {
    BlsSignature::sign(sk_bytes, msg, node_index, total_num_of_nodes)
}

pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<[u8; BLS_SIG_LEN]> {
    BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<Vec<u8>> {
    BlsSignature::get_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn truncate_nodes_info_and_verify(
    sig_bytes_with_nodes_info: &[u8],
    pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN],
    msg: &[u8],
) -> Result<bool> {
    BlsSignature::verify(sig_bytes_with_nodes_info, pk_bytes, msg)
}

pub fn aggregate_bls_signatures(bls_sigs_bytes: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    aggregate::aggregate_bls_signatures(bls_sigs_bytes)
}

pub fn aggregate_two_bls_signatures(
    bls_sig_1_bytes: &[u8],
    bls_sig_2_bytes: &[u8],
) -> Result<Vec<u8>> {
    aggregate::aggregate_two_bls_signatures(bls_sig_1_bytes, bls_sig_2_bytes)
}

pub fn aggregate_public_keys_based_on_nodes_info(
    bls_pks_bytes: &[&[u8; BLS_PUBLIC_KEY_LEN]],
    nodes_info_bytes: &[u8],
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys_based_on_nodes_info(bls_pks_bytes, nodes_info_bytes)
}

pub fn print_bls_public_key(bls_pk_bytes: &[u8]) {
    BlsKeyPair::print_bls_public_key(bls_pk_bytes)
}

pub fn print_signature_bytes(sig_bytes: &[u8]) {
    BlsSignature::print_signature_bytes(sig_bytes)
}

pub fn print_bls_signature(bls_sig_bytes: &[u8]) {
    BlsSignature::print_bls_signature(bls_sig_bytes)
}


/*** Functions handling only raw pubkeys and sigs bytes, without extra node info) */

pub fn aggregate_public_keys(
    bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>, pks_validate: bool
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys(bls_pks_bytes, pks_validate)
}

pub fn aggregate_public_keys_without_pks_validate(
    bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys_without_pks_validate(bls_pks_bytes)
}

pub fn aggregate_public_keys_with_pks_validate(
    bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys_with_pks_validate(bls_pks_bytes)
}

pub fn aggregate_two_bls_signatures_without_node_info(
    sig_bytes_1: &[u8; BLS_SIG_LEN],
    sig_bytes_2: &[u8; BLS_SIG_LEN],
    sigs_groupcheck: bool
) -> Result<[u8; BLS_SIG_LEN]> {
    aggregate::aggregate_two_bls_signatures_without_node_info(sig_bytes_1, sig_bytes_2, sigs_groupcheck)
}

pub fn aggregate_two_bls_signatures_without_node_info_without_sigs_check(
    sig_bytes_1: &[u8; BLS_SIG_LEN],
    sig_bytes_2: &[u8; BLS_SIG_LEN]
) -> Result<[u8; BLS_SIG_LEN]> {
    aggregate::aggregate_two_bls_signatures_without_node_info_without_sigs_check(sig_bytes_1, sig_bytes_2)
}

pub fn aggregate_bls_signatures_without_node_info_without_sigs_check(sigs_bytes: &Vec<&[u8; BLS_SIG_LEN]>) -> Result<[u8; BLS_SIG_LEN]> {
    aggregate::aggregate_bls_signatures_without_node_info_without_sigs_check(sigs_bytes)
}

pub fn aggregate_bls_signatures_without_node_info(sigs_bytes: &Vec<&[u8; BLS_SIG_LEN]>, sigs_groupcheck: bool)-> Result<[u8; BLS_SIG_LEN]> {
    aggregate::aggregate_bls_signatures_without_node_info(sigs_bytes, sigs_groupcheck)
}



#[test]
fn test_gen_bls_key_pair() {
    for _i in 0..100 {
        let now = Instant::now();
        let _key_pair = gen_bls_key_pair().unwrap();
        let duration = now.elapsed();
        println!("Time elapsed by gen_bls_key_pair is: {:?}", duration);
    }
}

#[test]
fn test_gen_bls_key_pair_based_on_key_material() {
    let ikm = [0u8; BLS_KEY_MATERIAL_LEN];
    for _i in 0..100 {
        let now = Instant::now();
        let key_pair = gen_bls_key_pair_based_on_key_material(&ikm).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        println!("Secret key : {:?}", key_pair.1);
        println!(
            "Time elapsed by gen_bls_key_pair_based_on_key_material is: {:?}",
            duration
        );
    }
}

#[test]
fn test_gen_public_key_based_on_secret_key() {
    for _i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let now = Instant::now();
        let pk = gen_public_key_based_on_secret_key(&key_pair.1).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!(
            "Time elapsed by gen_public_key_based_on_secret_key is: {:?}",
            duration
        );
        assert_eq!(pk, key_pair.0);
    }
}

#[test]
fn test_sign() {
    for _i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(10000000);
        let now = Instant::now();
        let _sig = sign(&key_pair.1, &msg).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by sign is: {:?}", duration);
        // assert_eq!(pk, key_pair.0);
    }
}

#[test]
fn test_verify() {
    for _i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(1000);
        let sig = sign(&key_pair.1, &msg).unwrap();
        let now = Instant::now();
        let res = verify(&sig, &msg, &key_pair.0).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by verify is: {:?}", duration);
        assert!(res);
    }
}

#[test]
fn test_add_node_info_to_sig() {
    let index = 100;
    let total_num_of_index = 10000;
    for _i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(500000);
        let sig = sign(&key_pair.1, &msg).unwrap();
        let now = Instant::now();
        let _res = add_node_info_to_sig(sig, index, total_num_of_index).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by add_node_info_to_sig is: {:?}", duration);
    }
}

#[test]
fn test_sign_and_add_node_info() {
    let index = 100;
    let total_num_of_index = 1000;
    for _i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(10000000);
        let now = Instant::now();
        let _res = sign_and_add_node_info(&key_pair.1, &msg, index, total_num_of_index).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by sign_and_add_node_info is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_public_keys_based_on_nodes_info() {
    let total_num_of_nodes = 10000;
    for _i in 0..10 {
        let indexes: Vec<u16> = gen_signer_indexes(total_num_of_nodes, total_num_of_nodes * 2);
        let mut node_info_vec = Vec::new();
        for ind in &indexes {
            //println!("Node index = {}", ind);
            let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
            node_info_vec.push(nodes_info)
        }
        let node_info_vec_refs: Vec<&NodesInfo> = node_info_vec.iter().collect();
        let info = NodesInfo::merge_multiple(&node_info_vec_refs).unwrap();
        println!("Node info size = {}", info.map.len());
        // info.print();

        let mut public_keys = Vec::new();
        for _j in 0..total_num_of_nodes {
            let key_pair = gen_bls_key_pair().unwrap();
            public_keys.push(key_pair.0);
        }
        let public_keys_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = public_keys.iter().collect();
        let now = Instant::now();
        let _res = aggregate_public_keys_based_on_nodes_info(&public_keys_refs, &info.serialize())
            .unwrap();
        let duration = now.elapsed();

        println!("Time elapsed by aggregate_public_keys is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_two_bls_signatures() {
    let number_of_keys = 100;
    for _i in 0..10 {
        let key_pair_1 = gen_bls_key_pair().unwrap();
        let key_pair_2 = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg();
        let ind_1 = gen_random_index(number_of_keys);
        let ind_2 = gen_random_index(number_of_keys);
        let sig_1 = sign_and_add_node_info(&key_pair_1.1, &msg, ind_1, number_of_keys).unwrap();
        let sig_2 = sign_and_add_node_info(&key_pair_2.1, &msg, ind_2, number_of_keys).unwrap();
        let now = Instant::now();
        let _res = aggregate_two_bls_signatures(&sig_1, &sig_2).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!(
            "Time elapsed by aggregate_two_bls_signatures is: {:?}",
            duration
        );
    }
}

#[test]
fn test_aggregate_two_bls_signatures_2() {
    let number_of_keys = 10000;
    for _i in 0..10 {
        let key_pair_1 = gen_bls_key_pair().unwrap();
        let key_pair_2 = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg();

        let sig_1 = sign(&key_pair_1.1, &msg).unwrap();
        let sig_2 = sign(&key_pair_2.1, &msg).unwrap();
        let info_1 = create_random_nodes_info(number_of_keys, number_of_keys * 2);
        let info_2 = create_random_nodes_info(number_of_keys, number_of_keys * 2);
        println!("info_1 size: {:?}", &info_1.map.len());

        let bls_sig_1 = BlsSignature {
            sig_bytes: sig_1,
            nodes_info: info_1,
        }
        .serialize();

        println!("info_2 size: {:?}", &info_2.map.len());

        let bls_sig_2 = BlsSignature {
            sig_bytes: sig_2,
            nodes_info: info_2,
        }
        .serialize();

        let now = Instant::now();
        let _res = aggregate_two_bls_signatures(&bls_sig_1, &bls_sig_2).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!(
            "Time elapsed by aggregate_two_bls_signatures is: {:?}",
            duration
        );
    }
}

#[test]
fn test_aggregate_bls_signatures() {
    let number_of_keys = 10000;
    let number_of_signatures = 10000;
    for _i in 0..10 {
        let mut sigs = Vec::new();
        let msg = generate_random_msg();
        for _j in 0..number_of_signatures {
            let key_pair = gen_bls_key_pair().unwrap();
            let sig = sign(&key_pair.1, &msg).unwrap();
            let info = create_random_nodes_info(number_of_keys, number_of_keys * 2);
            println!("info size: {:?}", &info.map.len());
            let bls_sig = BlsSignature {
                sig_bytes: sig,
                nodes_info: info,
            }
            .serialize();
            sigs.push(bls_sig);
        }
        let sigs_refs: Vec<&Vec<u8>> = sigs.iter().collect();

        let now = Instant::now();
        let _res = aggregate_bls_signatures(&sigs_refs).unwrap();
        let duration = now.elapsed();

        println!(
            "Time elapsed by aggregate_bls_signatures is: {:?}",
            duration
        );
    }
}

fn gen_random_key(rng: &mut rand_chacha::ChaCha20Rng) -> SecretKey {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    SecretKey::key_gen(&ikm.to_vec(), &[]).unwrap()
}

#[test]
fn test_multi_point() {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    //let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    let num_pks = 10000;

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Create public keys
    let sks: Vec<_> = (0..num_pks).map(|_| gen_random_key(&mut rng)).collect();

    let pks = sks.iter().map(|sk| sk.sk_to_pk()).collect::<Vec<_>>();
    let pks_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();

    // Create random message for pks to all sign
    let msg_len = (rng.next_u64() & 0x3F) + 1;
    let mut msg = vec![0u8; msg_len as usize];
    rng.fill_bytes(&mut msg);
    println!("msg: {:?}", msg);

    // Generate signature for each key pair
    let sigs = sks
        .iter()
        .map(|sk| sk.sign(&msg, dst, &[]))
        .collect::<Vec<Signature>>();
        println!("sigs: {:?}", sigs.len());
        let sigs_refs: Vec<&Signature> =
        sigs.iter().map(|s| s).collect();

    let sigs = sks
        .iter()
        .map(|sk| sk.sign(&msg, dst, &[]))
        .collect::<Vec<Signature>>();
        println!("sigs: {:?}", sigs.len());
        let sigs_refs: Vec<&Signature> =
        sigs.iter().map(|s| s).collect();
                
    // create random values
    let mut rands: Vec<u8> = Vec::with_capacity(8 * num_pks);
    for _ in 0..num_pks {
        let mut r = rng.next_u64();
        while r == 0 {
            // Reject zero as it is used for multiplication.
             r = rng.next_u64();
        }
        rands.extend_from_slice(&r.to_le_bytes());
    }

    // Sanity test each current single signature
    let errs = sigs
        .iter()
        .zip(pks.iter())
        .map(|(s, pk)| (s.verify(true, &msg, dst, &[], pk, true)))
        .collect::<Vec<BLST_ERROR>>();
    assert_eq!(errs, vec![BLST_ERROR::BLST_SUCCESS; num_pks]);

    // sanity test aggregated signature
    let agg_pk = AggregatePublicKey::aggregate(&pks_refs, false)
        .unwrap()
        .to_public_key();

    let now = Instant::now();
    let agg_sig = AggregateSignature::aggregate(&sigs_refs, true)
        .unwrap()
        .to_signature();

    //let agg_sig = AggregateSignature::aggregate(&sigs_refs, false)
    //    .unwrap()
    //    .to_signature();
    let duration = now.elapsed();
    println!("Time elapsed by AggregateSignature::aggregate is: {:?}",
        duration
    );
    println!(
        "agg_sig is: {:?}",
        agg_sig
    );
    let err = agg_sig.verify(true, &msg, dst, &[], &agg_pk, true);
    println!(
        "err is: {:?}",
        err
    );
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    // test multi-point aggregation using add
    let agg_pk = pks.add().to_public_key();
    let agg_sig = sigs.add().to_signature();
    let err = agg_sig.verify(true, &msg, dst, &[], &agg_pk, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    // test multi-point aggregation using mult
    let agg_pk = pks.mult(&rands, 64).to_public_key();
    let agg_sig = sigs.mult(&rands, 64).to_signature();
    let err = agg_sig.verify(true, &msg, dst, &[], &agg_pk, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);
}

#[test]
fn test_aggregate_public_keys() {
    let number_of_keys = 10000;
    for _i in 0..10 {
        let mut public_keys = Vec::new();
        for _j in 0..number_of_keys {
            let key_pair = gen_bls_key_pair().unwrap();
            public_keys.push(key_pair.0);
        }
        let public_keys_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = public_keys.iter().collect();
        let now = Instant::now();
        let _res = aggregate_public_keys(&public_keys_refs, false).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by aggregate_public_keys is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_two_bls_signatures_without_node_info() {
    for _i in 0..10 {
        let key_pair_1 = gen_bls_key_pair().unwrap();
        let key_pair_2 = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg();
        let sig_1 = sign(&key_pair_1.1, &msg).unwrap();
        let sig_2 = sign(&key_pair_2.1, &msg).unwrap();
        let now = Instant::now();
        let _res = aggregate_two_bls_signatures_without_node_info(&sig_1, &sig_2, false).unwrap();
        let duration = now.elapsed();
        println!(
            "Time elapsed by aggregate_two_bls_signatures_without_node_info is: {:?}",
            duration
        );
    }
}

#[test]
fn test_aggregate_bls_signatures_without_node_info_without_sigs_check() {
    let number_of_signatures = 10000;
    for _i in 0..10 {
        let mut sigs = Vec::new();
        let msg = generate_random_msg();
        for _j in 0..number_of_signatures {
            let key_pair = gen_bls_key_pair().unwrap();
            let sig = sign(&key_pair.1, &msg).unwrap();
            sigs.push(sig);
        }
        let sigs_refs = sigs.iter().collect();
        let now = Instant::now();
        let _res = aggregate_bls_signatures_without_node_info_without_sigs_check(&sigs_refs).unwrap();
        let duration = now.elapsed();

        println!(
            "Time elapsed by aggregate_bls_signatures_without_node_info is: {:?}",
            duration
        );
    }
}

#[test]
fn test_validate_bls_signatures_without_node_info() {
    let number_of_signatures = 10000;
    let msg = generate_random_msg();
    let mut total = 0;
    for _j in 0..number_of_signatures {
        let key_pair = gen_bls_key_pair().unwrap();
        let sig = sign(&key_pair.1, &msg).unwrap();
        let now = Instant::now();
        let res = validate_signature(&sig);
        let duration = now.elapsed().as_micros();
        total = total + duration;
        
        //println!(
        //    "res: {:?}",
        //    res
        //);
    }
    println!(
        "Time elapsed by validate_signature is: {:?}",
        total
    );
    let sig = [1u8; 96];
    let res = validate_signature(&sig);
    println!(
            "res: {:?}",
            res
    );
}

#[test]
fn test_validate_bls_public_key_without_node_info() {
    let number_of_signatures = 10000;
    let mut total = 0;
    for _j in 0..number_of_signatures {
        let key_pair = gen_bls_key_pair().unwrap();
        let now = Instant::now();
        let res = validate_public_key(&key_pair.0);
        let duration = now.elapsed().as_micros();
        total = total + duration;
        
        //println!(
        //    "res: {:?}",
        //    res
        //);
    }
    println!(
        "Time elapsed by validate_public_key is: {:?}",
        total
    );
    let pk = [1u8; 48];
    let res = validate_public_key(&pk);
    println!(
            "res: {:?}",
            res
    );
}




    
